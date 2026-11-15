from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from ..agent_security import (
    generate_envelope_id,
    generate_nonce,
    sign_job_envelope,
    verify_agent_request,
)
from ..audit import record_audit
from ..authorization_policy import (
    ALLOWED_SCAN_PROFILES,
    find_matching_authorization,
)
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import (
    AgentJobEnvelope,
    AgentNode,
    Approval,
    Project,
    Role,
    Scan,
    ScanStatus,
    SourceArtifact,
    Target,
    User,
    utcnow,
)
from ..scanners.evidence import (
    NormalizedAsset,
    NormalizedFinding,
    ScanModuleResult,
    persist_scan_outputs,
)
from ..schemas import (
    AgentJobCreate,
    AgentJobEnvelopeOut,
    AgentJobResultSubmission,
)
from ..scope_guard import ScopeError, validate_public_http_target

router = APIRouter(tags=["agents-jobs"])


async def authenticate_agent_node(
    request: Request,
    db: Session = Depends(get_db),
) -> AgentNode:
    """Authenticate desktop agent via cryptographic HMAC request headers."""
    agent_id = request.headers.get("X-PentaGen-Agent-ID")
    timestamp = request.headers.get("X-PentaGen-Timestamp")
    nonce = request.headers.get("X-PentaGen-Nonce")
    signature = request.headers.get("X-PentaGen-Signature")

    if not all([agent_id, timestamp, nonce, signature]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required agent HMAC authentication headers.",
        )

    node = (
        db.query(AgentNode)
        .filter(AgentNode.id == agent_id, AgentNode.status == "active")
        .first()
    )
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent node not registered, inactive, or revoked.",
        )

    body = await request.body()
    is_valid, error_reason = verify_agent_request(
        secret=node.shared_secret,
        agent_id=node.id,
        method=request.method,
        path=request.url.path,
        timestamp=str(timestamp),
        nonce=str(nonce),
        body=body,
        signature=str(signature),
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Agent request verification failed: {error_reason}",
        )

    node.last_seen_at = utcnow()
    return node


@router.post("/agents/jobs", response_model=AgentJobEnvelopeOut)
def create_agent_job(
    payload: AgentJobCreate,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Schedule an authorized assessment job for execution by a paired desktop agent."""
    if not payload.confirm_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Explicit authorization confirmation is required.",
        )

    target: Target | None = None
    target_hostname = ""
    target_base_url = ""
    now = utcnow()

    if payload.target_id is not None:
        target = (
            db.query(Target)
            .filter(
                Target.id == payload.target_id,
                Target.organization_id == current_user.organization_id,
            )
            .first()
        )
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

        authorization = find_matching_authorization(
            db,
            organization_id=current_user.organization_id,
            target=target,
            profile=payload.action,
            now=now,
        )
        if authorization is None:
            record_audit(
                db,
                organization_id=current_user.organization_id,
                actor_user_id=current_user.id,
                event_type="agent_job.blocked_unauthorized",
                resource_type="target",
                resource_id=str(target.id),
                details={"action": payload.action},
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No active, approved authorization covers this target and action.",
            )

        try:
            target_hostname, _ = validate_public_http_target(target.base_url)
            target_base_url = target.base_url
        except ScopeError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    assigned_node: AgentNode | None = None
    if payload.agent_node_id:
        assigned_node = (
            db.query(AgentNode)
            .filter(
                AgentNode.id == payload.agent_node_id,
                AgentNode.organization_id == current_user.organization_id,
                AgentNode.status == "active",
            )
            .first()
        )
        if assigned_node is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Specified desktop agent node is not active or not found.",
            )

    project = Project(
        organization_id=current_user.organization_id,
        name=payload.project_name.strip(),
        description="Created by desktop agent job request",
        created_by=current_user.id,
    )
    db.add(project)
    db.flush()

    # Determine if human approval is required for gated risk actions
    needs_approval = (
        payload.requires_approval
        or payload.risk_level in ["high", "critical"]
        or payload.action not in ["safe_baseline", "tls_check", "passive_recon"]
    )

    scan_status = ScanStatus.awaiting_approval if needs_approval else ScanStatus.running
    scan = Scan(
        organization_id=current_user.organization_id,
        project_id=project.id,
        target_id=target.id if target else None,
        source_artifact_id=payload.source_artifact_id,
        requested_by=current_user.id,
        status=scan_status,
        profile=payload.action,
        started_at=now if not needs_approval else None,
    )
    db.add(scan)
    db.flush()

    envelope_id = generate_envelope_id()
    nonce = generate_nonce()

    job_payload = {
        "action": payload.action,
        "target_hostname": target_hostname,
        "target_url": target_base_url,
        "allowed_scope": [target_hostname] if target_hostname else [],
        "params": payload.params,
        "created_at": now.isoformat(),
    }

    signature = ""
    if assigned_node:
        signature = sign_job_envelope(
            secret=assigned_node.shared_secret,
            envelope_id=envelope_id,
            agent_node_id=assigned_node.id,
            action=payload.action,
            payload=job_payload,
            nonce=nonce,
        )

    envelope_status = "pending_approval" if needs_approval else "pending"

    approval_id: int | None = None
    if needs_approval:
        approval = Approval(
            organization_id=current_user.organization_id,
            scan_id=scan.id,
            target_id=target.id if target else None,
            envelope_id=envelope_id,
            requested_action=payload.action,
            risk_level=payload.risk_level,
            status="pending",
            risk_assessment_json={
                "reason": "Action requires explicit human review and approval before desktop dispatch.",
                "target_hostname": target_hostname,
                "profile": payload.action,
            },
            created_at=now,
        )
        db.add(approval)
        db.flush()
        approval_id = approval.id

    envelope = AgentJobEnvelope(
        id=envelope_id,
        organization_id=current_user.organization_id,
        agent_node_id=assigned_node.id if assigned_node else None,
        scan_id=scan.id,
        approval_id=approval_id,
        action=payload.action,
        payload_json=job_payload,
        nonce=nonce,
        signature=signature,
        status=envelope_status,
        created_at=now,
    )
    db.add(envelope)

    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="agent_job.created",
        resource_type="agent_job_envelope",
        resource_id=envelope_id,
        details={
            "scan_id": scan.id,
            "action": payload.action,
            "status": envelope_status,
            "approval_id": approval_id,
        },
    )
    db.commit()
    db.refresh(envelope)

    return envelope


@router.get("/agents/jobs/poll")
def poll_pending_job(
    agent: AgentNode = Depends(authenticate_agent_node),
    db: Session = Depends(get_db),
):
    """Desktop agent polls for the next signed job envelope matching its organization."""
    query = (
        db.query(AgentJobEnvelope)
        .filter(
            AgentJobEnvelope.organization_id == agent.organization_id,
            AgentJobEnvelope.status == "pending",
        )
        .filter(
            (AgentJobEnvelope.agent_node_id == agent.id)
            | (AgentJobEnvelope.agent_node_id.is_(None))
        )
        .order_by(AgentJobEnvelope.created_at.asc())
    )
    envelope = query.first()
    if envelope is None:
        return {"job": None}

    now = utcnow()
    if envelope.agent_node_id is None:
        envelope.agent_node_id = agent.id

    # Compute freshly signed envelope with the polling agent's secret
    envelope.signature = sign_job_envelope(
        secret=agent.shared_secret,
        envelope_id=envelope.id,
        agent_node_id=agent.id,
        action=envelope.action,
        payload=envelope.payload_json,
        nonce=envelope.nonce,
    )
    envelope.status = "dispatched"
    envelope.dispatched_at = now

    record_audit(
        db,
        organization_id=agent.organization_id,
        actor_user_id=None,
        event_type="agent_job.dispatched",
        resource_type="agent_job_envelope",
        resource_id=envelope.id,
        details={"agent_id": agent.id, "scan_id": envelope.scan_id},
    )
    db.commit()
    db.refresh(envelope)

    return {"job": AgentJobEnvelopeOut.model_validate(envelope)}


@router.post("/agents/jobs/{envelope_id}/results")
def submit_job_results(
    envelope_id: str,
    payload: AgentJobResultSubmission,
    agent: AgentNode = Depends(authenticate_agent_node),
    db: Session = Depends(get_db),
):
    """Receive signed execution findings and evidence from the paired desktop agent."""
    envelope = (
        db.query(AgentJobEnvelope)
        .filter(
            AgentJobEnvelope.id == envelope_id,
            AgentJobEnvelope.organization_id == agent.organization_id,
        )
        .first()
    )
    if envelope is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Job envelope not found."
        )

    if envelope.status not in ["dispatched", "pending"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Envelope is in '{envelope.status}' state and not accepting results.",
        )

    scan = (
        db.query(Scan)
        .filter(
            Scan.id == envelope.scan_id,
            Scan.organization_id == agent.organization_id,
        )
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Associated scan not found.")

    # Convert submitted findings to NormalizedFinding instances
    normalized_findings: list[NormalizedFinding] = []
    for item in payload.findings:
        normalized_findings.append(
            NormalizedFinding(
                category=str(item.get("category", "web")),
                title=str(item.get("title", "Desktop Agent Finding")),
                description=str(item.get("description", "")),
                severity=str(item.get("severity", "info")),
                confidence=str(item.get("confidence", "medium")),
                remediation=str(item.get("remediation", "Review finding details.")),
                evidence_type=str(item.get("evidence_type", "agent_execution")),
                evidence_content=str(item.get("evidence_content", "")),
                location=item.get("location"),
                cwe=item.get("cwe"),
                cvss_score=item.get("cvss_score"),
                artifact_metadata=item.get("artifact_metadata", {}),
            )
        )

    normalized_assets: list[NormalizedAsset] = []
    for asset_dict in payload.assets:
        normalized_assets.append(
            NormalizedAsset(
                asset_type=str(asset_dict.get("asset_type", "endpoint")),
                name=str(asset_dict.get("name", "Asset")),
                identifier=str(asset_dict.get("identifier", "")),
                metadata_json=asset_dict.get("metadata_json", {}),
            )
        )

    module_result = ScanModuleResult(
        findings=normalized_findings,
        assets=normalized_assets,
        notes=payload.summary,
    )

    persist_scan_outputs(
        db,
        organization_id=agent.organization_id,
        scan=scan,
        target_id=scan.target_id,
        result=module_result,
    )

    now = utcnow()
    envelope.status = payload.status
    envelope.completed_at = now
    envelope.result_json = payload.summary

    scan.status = ScanStatus.completed if payload.status == "completed" else ScanStatus.failed
    scan.finished_at = now
    scan.scanner_summary = {
        "execution_mode": "desktop_agent",
        "agent_id": agent.id,
        "findings_count": len(normalized_findings),
        "assets_count": len(normalized_assets),
        "summary": payload.summary,
        "error_message": payload.error_message,
    }

    record_audit(
        db,
        organization_id=agent.organization_id,
        actor_user_id=None,
        event_type="agent_job.completed",
        resource_type="agent_job_envelope",
        resource_id=envelope.id,
        details={
            "agent_id": agent.id,
            "scan_id": scan.id,
            "status": payload.status,
            "findings_count": len(normalized_findings),
        },
    )
    db.commit()

    return {
        "status": "ok",
        "envelope_id": envelope.id,
        "scan_id": scan.id,
        "findings_count": len(normalized_findings),
    }
