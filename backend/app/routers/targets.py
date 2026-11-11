from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..authorization_policy import (
    AuthorizationPolicyError,
    validate_authorization_window,
    validate_profiles,
)
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import Authorization, Role, Target, User, utcnow
from ..schemas import AuthorizationCreate, AuthorizationOut, TargetCreate, TargetOut
from ..scope_guard import ScopeError, validate_public_http_target

router = APIRouter(tags=["targets"])


def _get_org_target_or_404(db: Session, *, target_id: int, organization_id: int) -> Target:
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.organization_id == organization_id)
        .first()
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    return target


def _create_authorization_record(
    db: Session,
    *,
    target: Target,
    actor: User,
    evidence_reference: str,
    starts_at,
    expires_at,
    allowed_profiles: list[str],
) -> Authorization:
    try:
        profiles = validate_profiles(allowed_profiles)
        start_utc, expiry_utc = validate_authorization_window(starts_at, expires_at)
    except AuthorizationPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    now = utcnow()
    # Owners can self-approve authorizations they grant; pentesters require reviewer/owner approval.
    auto_approve = actor.role == Role.owner
    authorization = Authorization(
        organization_id=actor.organization_id,
        target_id=target.id,
        granted_by=actor.id,
        approved_by=actor.id if auto_approve else None,
        evidence_reference=evidence_reference.strip(),
        scope_json={
            "base_url": target.base_url,
            "hostname": target.hostname,
            "allowed_profiles": profiles,
        },
        starts_at=start_utc,
        expires_at=expiry_utc,
        approved=auto_approve,
        approved_at=now if auto_approve else None,
    )
    db.add(authorization)
    return authorization


@router.get("/targets", response_model=list[TargetOut])
def list_targets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List targets belonging to the caller's organization."""
    return (
        db.query(Target)
        .filter(Target.organization_id == current_user.organization_id)
        .order_by(Target.id.desc())
        .limit(100)
        .all()
    )


@router.get("/targets/{target_id}", response_model=TargetOut)
def get_target(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve a single target scoped to the caller's organization."""
    return _get_org_target_or_404(
        db, target_id=target_id, organization_id=current_user.organization_id
    )


@router.post("/targets", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Register an allowlisted public HTTP/HTTPS target with an authorization record."""
    try:
        hostname, _ = validate_public_http_target(str(payload.base_url))
    except ScopeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    target = Target(
        organization_id=current_user.organization_id,
        name=payload.name.strip(),
        base_url=str(payload.base_url),
        hostname=hostname,
        owner_user_id=current_user.id,
    )
    db.add(target)
    db.flush()

    authorization = _create_authorization_record(
        db,
        target=target,
        actor=current_user,
        evidence_reference=payload.authorization_reference,
        starts_at=payload.authorization_starts_at,
        expires_at=payload.authorization_expires_at,
        allowed_profiles=payload.allowed_profiles,
    )
    db.flush()

    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="target.registered",
        resource_type="target",
        resource_id=str(target.id),
        details={
            "hostname": hostname,
            "authorization_id": authorization.id,
            "approved": authorization.approved,
        },
    )
    db.commit()
    db.refresh(target)
    return target


@router.get("/targets/{target_id}/authorizations", response_model=list[AuthorizationOut])
def list_target_authorizations(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List authorization records for an organization target."""
    _get_org_target_or_404(db, target_id=target_id, organization_id=current_user.organization_id)
    return (
        db.query(Authorization)
        .filter(
            Authorization.target_id == target_id,
            Authorization.organization_id == current_user.organization_id,
        )
        .order_by(Authorization.id.desc())
        .all()
    )


@router.post(
    "/targets/{target_id}/authorizations",
    response_model=AuthorizationOut,
    status_code=status.HTTP_201_CREATED,
)
def add_target_authorization(
    target_id: int,
    payload: AuthorizationCreate,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Add a new authorization window and scope record to an existing target."""
    target = _get_org_target_or_404(
        db, target_id=target_id, organization_id=current_user.organization_id
    )
    authorization = _create_authorization_record(
        db,
        target=target,
        actor=current_user,
        evidence_reference=payload.evidence_reference,
        starts_at=payload.starts_at,
        expires_at=payload.expires_at,
        allowed_profiles=payload.allowed_profiles,
    )
    db.flush()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="authorization.created",
        resource_type="authorization",
        resource_id=str(authorization.id),
        details={"target_id": target.id, "approved": authorization.approved},
    )
    db.commit()
    db.refresh(authorization)
    return authorization


@router.post("/authorizations/{authorization_id}/approve", response_model=AuthorizationOut)
def approve_authorization(
    authorization_id: int,
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Approve a pending target authorization within the caller's organization."""
    authorization = (
        db.query(Authorization)
        .filter(
            Authorization.id == authorization_id,
            Authorization.organization_id == current_user.organization_id,
        )
        .first()
    )
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Authorization record not found."
        )
    if authorization.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Revoked authorizations cannot be approved.",
        )
    if authorization.expires_at <= utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expired authorizations cannot be approved.",
        )

    authorization.approved = True
    authorization.approved_by = current_user.id
    authorization.approved_at = utcnow()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="authorization.approved",
        resource_type="authorization",
        resource_id=str(authorization.id),
        details={"target_id": authorization.target_id},
    )
    db.commit()
    db.refresh(authorization)
    return authorization


@router.post("/authorizations/{authorization_id}/revoke", response_model=AuthorizationOut)
def revoke_authorization(
    authorization_id: int,
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Revoke an authorization immediately so subsequent scans are blocked."""
    authorization = (
        db.query(Authorization)
        .filter(
            Authorization.id == authorization_id,
            Authorization.organization_id == current_user.organization_id,
        )
        .first()
    )
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Authorization record not found."
        )

    if authorization.revoked_at is None:
        authorization.revoked_at = utcnow()
        authorization.approved = False
        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="authorization.revoked",
            resource_type="authorization",
            resource_id=str(authorization.id),
            details={"target_id": authorization.target_id},
        )
        db.commit()
        db.refresh(authorization)
    return authorization

