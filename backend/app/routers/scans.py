from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..authorization_policy import (
    ALLOWED_SCAN_PROFILES,
    TARGET_REQUIRED_PROFILES,
    find_matching_authorization,
)
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import (
    Evidence,
    Finding,
    FindingAnalysis,
    Organization,
    Project,
    Role,
    Scan,
    ScanStatus,
    SourceArtifact,
    Target,
    User,
    utcnow,
)
from ..reporting.pdf_generator import generate_scan_pdf_report
from ..scanners.evidence import persist_scan_outputs
from ..scanners.orchestrator import execute_scan_profile
from ..schemas import EvidenceOut, FindingOut, ScanCreate, ScanOut
from ..scope_guard import ScopeError, validate_public_http_target

router = APIRouter(tags=["scans"])


@router.get("/scans", response_model=list[ScanOut])
def list_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List scan executions belonging to the caller's organization."""
    return (
        db.query(Scan)
        .filter(Scan.organization_id == current_user.organization_id)
        .order_by(Scan.id.desc())
        .limit(100)
        .all()
    )


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve a single scan execution summary scoped to the caller's organization."""
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.organization_id == current_user.organization_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


@router.post("/scans")
async def create_scan(
    payload: ScanCreate,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Execute an authorized non-destructive scan across Sprint 2 scanner modules."""
    if not payload.confirm_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Explicit authorization confirmation is required.",
        )
    if payload.profile not in ALLOWED_SCAN_PROFILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported scan profile '{payload.profile}'.",
        )
    if payload.target_id is None and payload.source_artifact_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide target_id, source_artifact_id, or both.",
        )
    if payload.profile in TARGET_REQUIRED_PROFILES and payload.target_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Profile '{payload.profile}' requires a registered target_id.",
        )
    if payload.profile == "code_sast" and payload.source_artifact_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Profile 'code_sast' requires source_artifact_id.",
        )

    target: Target | None = None
    authorization_id: int | None = None
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
            profile=payload.profile,
            now=now,
        )
        if authorization is None:
            record_audit(
                db,
                organization_id=current_user.organization_id,
                actor_user_id=current_user.id,
                event_type="scan.blocked_unauthorized",
                resource_type="target",
                resource_id=str(target.id),
                details={"profile": payload.profile},
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No active, approved authorization record covers this target and profile.",
            )
        authorization_id = authorization.id

        try:
            hostname, _ = validate_public_http_target(target.base_url)
            if hostname != target.hostname:
                raise ScopeError("Resolved target identity changed; re-register and review scope.")
        except ScopeError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    artifact: SourceArtifact | None = None
    if payload.source_artifact_id is not None:
        artifact = (
            db.query(SourceArtifact)
            .filter(
                SourceArtifact.id == payload.source_artifact_id,
                SourceArtifact.organization_id == current_user.organization_id,
            )
            .first()
        )
        if artifact is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Source artifact not found."
            )

    project = Project(
        organization_id=current_user.organization_id,
        name=payload.project_name.strip(),
        description="Created by assessment scan request",
        created_by=current_user.id,
    )
    db.add(project)
    db.flush()

    scan = Scan(
        organization_id=current_user.organization_id,
        project_id=project.id,
        target_id=target.id if target else None,
        source_artifact_id=artifact.id if artifact else None,
        requested_by=current_user.id,
        status=ScanStatus.running,
        profile=payload.profile,
        started_at=now,
    )
    db.add(scan)
    db.flush()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="scan.started",
        resource_type="scan",
        resource_id=str(scan.id),
        details={
            "target_id": target.id if target else None,
            "source_artifact_id": artifact.id if artifact else None,
            "authorization_id": authorization_id,
            "profile": payload.profile,
        },
    )
    db.commit()

    try:
        module_result = await execute_scan_profile(
            profile=payload.profile,
            target=target,
            artifact=artifact,
        )
        finding_count, asset_count = persist_scan_outputs(
            db,
            organization_id=current_user.organization_id,
            scan=scan,
            target_id=target.id if target else None,
            result=module_result,
        )
        scan.status = ScanStatus.completed
        scan.finished_at = utcnow()
        scan.scanner_summary = {
            **module_result.notes,
            "finding_count": finding_count,
            "asset_count": asset_count,
        }
        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="scan.completed",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"finding_count": finding_count, "asset_count": asset_count},
        )
        db.commit()
        return {
            "scan_id": scan.id,
            "status": scan.status.value,
            "profile": scan.profile,
            "finding_count": finding_count,
            "asset_count": asset_count,
            "executed_modules": module_result.notes.get("executed_modules", []),
            "note": "Findings are preliminary and require human review.",
        }
    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.finished_at = utcnow()
        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="scan.failed",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"error_type": type(exc).__name__},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Safe assessment failed: {type(exc).__name__}",
        ) from exc


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    scan_id: int | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List findings belonging to the caller's organization."""
    query = db.query(Finding).filter(Finding.organization_id == current_user.organization_id)
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    return query.order_by(Finding.id.desc()).limit(200).all()


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve a single finding scoped to the caller's organization."""
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.organization_id == current_user.organization_id)
        .first()
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return finding


@router.get("/findings/{finding_id}/evidence", response_model=list[EvidenceOut])
def list_finding_evidence(
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve immutable redacted evidence items linked to an organization finding."""
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.organization_id == current_user.organization_id)
        .first()
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return (
        db.query(Evidence)
        .filter(
            Evidence.finding_id == finding_id,
            Evidence.organization_id == current_user.organization_id,
        )
        .order_by(Evidence.id.asc())
        .all()
    )


@router.get("/scans/{scan_id}/report.pdf")
def export_scan_pdf_report(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate and download a professional PDF security assessment report."""
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.organization_id == current_user.organization_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    target = (
        db.query(Target)
        .filter(Target.id == scan.target_id, Target.organization_id == current_user.organization_id)
        .first()
        if scan.target_id
        else None
    )

    org = (
        db.query(Organization)
        .filter(Organization.id == current_user.organization_id)
        .first()
    )
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id, Finding.organization_id == current_user.organization_id)
        .order_by(Finding.id.asc())
        .all()
    )

    finding_ids = [f.id for f in findings]
    evidence_items = (
        db.query(Evidence)
        .filter(
            Evidence.finding_id.in_(finding_ids),
            Evidence.organization_id == current_user.organization_id,
        )
        .all()
        if finding_ids
        else []
    )

    analyses = (
        db.query(FindingAnalysis)
        .filter(
            FindingAnalysis.finding_id.in_(finding_ids),
            FindingAnalysis.organization_id == current_user.organization_id,
        )
        .all()
        if finding_ids
        else []
    )

    pdf_bytes = generate_scan_pdf_report(
        scan=scan,
        target=target,
        organization=org,
        findings=findings,
        evidence_items=evidence_items,
        analyses=analyses,
    )

    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="scan.report_exported_pdf",
        resource_type="scan",
        resource_id=str(scan.id),
        details={"findings_count": len(findings), "bytes": len(pdf_bytes)},
    )
    db.commit()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="pentagen-scan-{scan.id}-report.pdf"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
