from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..db import get_db
from ..deps import require_roles
from ..models import Role, User, UserSession, utcnow
from ..schemas import UserCreate, UserOut, UserUpdate
from ..security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(
    current_user: User = Depends(require_roles(Role.owner)),
    db: Session = Depends(get_db),
):
    """List users within the caller's organization (owner only)."""
    return (
        db.query(User)
        .filter(User.organization_id == current_user.organization_id)
        .order_by(User.id.asc())
        .all()
    )


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    current_user: User = Depends(require_roles(Role.owner)),
    db: Session = Depends(get_db),
):
    """Provision a new user inside the owner's organization."""
    email = payload.email.strip().lower()
    if db.query(User.id).filter(User.email == email).first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists.",
        )

    user = User(
        organization_id=current_user.organization_id,
        email=email,
        full_name=payload.full_name.strip() if payload.full_name else None,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="user.created",
        resource_type="user",
        resource_id=str(user.id),
        details={"email": email, "role": user.role.value},
    )
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    current_user: User = Depends(require_roles(Role.owner)),
    db: Session = Depends(get_db),
):
    """Update role, display name, or active status for a user in the same organization."""
    user = (
        db.query(User)
        .filter(User.id == user_id, User.organization_id == current_user.organization_id)
        .first()
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    next_role = payload.role if payload.role is not None else user.role
    next_active = payload.is_active if payload.is_active is not None else user.is_active
    demoting_or_deactivating_owner = (
        user.role == Role.owner
        and user.is_active
        and (next_role != Role.owner or not next_active)
    )
    if demoting_or_deactivating_owner:
        active_owners = (
            db.query(User)
            .filter(
                User.organization_id == current_user.organization_id,
                User.role == Role.owner,
                User.is_active.is_(True),
            )
            .count()
        )
        if active_owners <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization must retain at least one active owner.",
            )

    role_changed = payload.role is not None and payload.role != user.role
    deactivated = payload.is_active is False and user.is_active

    if payload.full_name is not None:
        user.full_name = payload.full_name.strip() or None
    user.role = next_role
    user.is_active = next_active

    # Revoke live sessions when privileges drop or account is deactivated.
    if role_changed or deactivated:
        now = utcnow()
        active_sessions = (
            db.query(UserSession)
            .filter(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
            .all()
        )
        for session in active_sessions:
            session.revoked_at = now
            session.revoked_reason = "account_deactivated" if deactivated else "role_changed"

    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="user.updated",
        resource_type="user",
        resource_id=str(user.id),
        details={"role": user.role.value, "is_active": user.is_active},
    )
    db.commit()
    db.refresh(user)
    return user

