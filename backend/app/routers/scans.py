import hashlib
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..authorization_policy import ALLOWED_SCAN_PROFILES, find_matching_authorization
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import Evidence, Finding, Project, Role, Scan, ScanStatus, Severity, Target, User, utcnow
from ..scanners.safe_http import inspect_headers
from ..schemas import FindingOut, ScanCreate, ScanOut
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


@router.post("/scans")
async def create_scan(
    payload: ScanCreate,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Run a non-destructive assessment only after verifying RBAC, scope, and active authorization."""
    if not payload.confirm_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Explicit authorization confirmation is required.",
        )
    if payload.profile not in ALLOWED_SCAN_PROFILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only safe_baseline profile is enabled in this MVP.",
        )

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

    now = utcnow()
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

    try:
        hostname, _ = validate_public_http_target(target.base_url)
        if hostname != target.hostname:
            raise ScopeError("Resolved target identity changed; re-register and review scope.")
    except ScopeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

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
        target_id=target.id,
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
        details={"target_id": target.id, "authorization_id": authorization.id, "profile": payload.profile},
    )
    db.commit()

    try:
        results = await inspect_headers(target.base_url)
        for item in results:
            finding = Finding(
                organization_id=current_user.organization_id,
                scan_id=scan.id,
                title=item["title"],
                description=item["description"],
                severity=Severity(item["severity"]),
                confidence=item["confidence"],
                remediation=item["remediation"],
                status="needs_review",
            )
            db.add(finding)
            db.flush()

            evidence_text = item.get("evidence", "")
            if evidence_text:
                db.add(
                    Evidence(
                        organization_id=current_user.organization_id,
                        finding_id=finding.id,
                        evidence_type="http_header_check",
                        content_redacted=evidence_text,
                        content_hash=hashlib.sha256(evidence_text.encode("utf-8")).hexdigest(),
                    )
                )

        scan.status = ScanStatus.completed
        scan.finished_at = utcnow()
        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="scan.completed",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"finding_count": len(results)},
        )
        db.commit()
        return {
            "scan_id": scan.id,
            "status": scan.status.value,
            "finding_count": len(results),
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List findings belonging to the caller's organization."""
    return (
        db.query(Finding)
        .filter(Finding.organization_id == current_user.organization_id)
        .order_by(Finding.id.desc())
        .limit(200)
        .all()
    )

