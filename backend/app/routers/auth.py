import re
import uuid
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..config import settings
from ..db import get_db
from ..deps import AuthContext, get_auth_context, get_client_metadata, get_current_user
from ..models import Organization, Role, User, UserSession, utcnow
from ..schemas import (
    BootstrapRegisterRequest,
    LoginRequest,
    RefreshRequest,
    SessionOut,
    TokenResponse,
    UserOut,
)
from ..security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    needs_password_rehash,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_DUMMY_PASSWORD_HASH: str | None = None


def _get_dummy_hash() -> str:
    """Lazily compute a fallback Argon2id hash to equalize missing-user login timing."""
    global _DUMMY_PASSWORD_HASH
    if _DUMMY_PASSWORD_HASH is None:
        _DUMMY_PASSWORD_HASH = hash_password("pentagen-constant-time-dummy-password")
    return _DUMMY_PASSWORD_HASH


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "organization"


def _issue_session_tokens(
    db: Session,
    *,
    user: User,
    user_agent: str | None,
    ip_address: str | None,
) -> tuple[TokenResponse, UserSession]:
    """Create a persistent session with a hashed refresh token and paired JWT access token."""
    now = utcnow()
    session_id = str(uuid.uuid4())
    refresh_token = generate_refresh_token()
    session = UserSession(
        id=session_id,
        user_id=user.id,
        organization_id=user.organization_id,
        refresh_token_hash=hash_token(refresh_token),
        user_agent=user_agent,
        ip_address=ip_address,
        created_at=now,
        last_used_at=now,
        expires_at=now + timedelta(days=settings.refresh_token_days),
    )
    db.add(session)
    access_token, expires_in = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role.value,
        session_id=session_id,
    )
    response = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        session_id=session_id,
        user=UserOut.model_validate(user),
    )
    return response, session


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def bootstrap_register(
    payload: BootstrapRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Bootstrap the initial organization and owner account when no users exist yet."""
    if db.query(User.id).first() is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Initial setup is complete. Ask an organization owner to provision your account.",
        )

    email = payload.email.strip().lower()
    org_name = payload.organization_name.strip()
    org = Organization(name=org_name, slug=_slugify(org_name))
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=email,
        full_name=payload.full_name.strip() if payload.full_name else None,
        password_hash=hash_password(payload.password),
        role=Role.owner,
        is_active=True,
    )
    db.add(user)
    db.flush()

    user_agent, ip_address = get_client_metadata(request)
    token_response, session = _issue_session_tokens(
        db, user=user, user_agent=user_agent, ip_address=ip_address
    )
    record_audit(
        db,
        organization_id=org.id,
        actor_user_id=user.id,
        event_type="auth.bootstrap_registered",
        resource_type="user",
        resource_id=str(user.id),
        details={"email": email, "role": user.role.value, "session_id": session.id},
    )
    db.commit()
    return token_response


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate a user with email and password and issue a tracked session."""
    email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()

    if user is None:
        verify_password(payload.password, _get_dummy_hash())
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not verify_password(payload.password, user.password_hash):
        record_audit(
            db,
            organization_id=user.organization_id,
            actor_user_id=user.id,
            event_type="auth.login.failed",
            resource_type="user",
            resource_id=str(user.id),
            details={"reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        record_audit(
            db,
            organization_id=user.organization_id,
            actor_user_id=user.id,
            event_type="auth.login.failed",
            resource_type="user",
            resource_id=str(user.id),
            details={"reason": "account_inactive"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if needs_password_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    user_agent, ip_address = get_client_metadata(request)
    token_response, session = _issue_session_tokens(
        db, user=user, user_agent=user_agent, ip_address=ip_address
    )
    record_audit(
        db,
        organization_id=user.organization_id,
        actor_user_id=user.id,
        event_type="auth.login.succeeded",
        resource_type="session",
        resource_id=session.id,
        details={"ip_address": ip_address},
    )
    db.commit()
    return token_response


@router.post("/refresh", response_model=TokenResponse)
def refresh_session(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    """Rotate refresh token and issue a fresh JWT access token for an active session."""
    now = utcnow()
    token_digest = hash_token(payload.refresh_token)
    session = (
        db.query(UserSession)
        .filter(UserSession.refresh_token_hash == token_digest)
        .first()
    )
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )
    if session.revoked_at is not None or session.expires_at <= now:
        record_audit(
            db,
            organization_id=session.organization_id,
            actor_user_id=session.user_id,
            event_type="auth.refresh.rejected",
            resource_type="session",
            resource_id=session.id,
            details={"revoked": session.revoked_at is not None},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is expired or revoked.",
        )

    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        session.revoked_at = now
        session.revoked_reason = "account_inactive"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or unavailable.",
        )

    new_refresh_token = generate_refresh_token()
    user_agent, ip_address = get_client_metadata(request)
    session.refresh_token_hash = hash_token(new_refresh_token)
    session.last_used_at = now
    session.expires_at = now + timedelta(days=settings.refresh_token_days)
    if user_agent:
        session.user_agent = user_agent
    if ip_address:
        session.ip_address = ip_address

    access_token, expires_in = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role.value,
        session_id=session.id,
    )
    record_audit(
        db,
        organization_id=user.organization_id,
        actor_user_id=user.id,
        event_type="auth.token.refreshed",
        resource_type="session",
        resource_id=session.id,
        details={},
    )
    db.commit()
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=expires_in,
        session_id=session.id,
        user=UserOut.model_validate(user),
    )


@router.post("/logout")
def logout(ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)):
    """Revoke the current authentication session immediately."""
    ctx.session.revoked_at = utcnow()
    ctx.session.revoked_reason = "user_logout"
    record_audit(
        db,
        organization_id=ctx.user.organization_id,
        actor_user_id=ctx.user.id,
        event_type="auth.logout",
        resource_type="session",
        resource_id=ctx.session.id,
        details={},
    )
    db.commit()
    return {"status": "logged_out", "session_id": ctx.session.id}


@router.post("/logout-all")
def logout_all(ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)):
    """Revoke every active session belonging to the current user."""
    now = utcnow()
    active_sessions = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == ctx.user.id,
            UserSession.organization_id == ctx.user.organization_id,
            UserSession.revoked_at.is_(None),
        )
        .all()
    )
    for session in active_sessions:
        session.revoked_at = now
        session.revoked_reason = "user_logout_all"
    record_audit(
        db,
        organization_id=ctx.user.organization_id,
        actor_user_id=ctx.user.id,
        event_type="auth.logout_all",
        resource_type="user",
        resource_id=str(ctx.user.id),
        details={"revoked_count": len(active_sessions)},
    )
    db.commit()
    return {"status": "all_sessions_revoked", "revoked_count": len(active_sessions)}


@router.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return current_user


@router.get("/sessions", response_model=list[SessionOut])
def list_my_sessions(ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)):
    """List sessions belonging to the authenticated user."""
    rows = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == ctx.user.id,
            UserSession.organization_id == ctx.user.organization_id,
        )
        .order_by(UserSession.created_at.desc())
        .limit(50)
        .all()
    )
    result = []
    for row in rows:
        item = SessionOut.model_validate(row)
        item.is_current = row.id == ctx.session.id
        result.append(item)
    return result


@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
):
    """Revoke a session owned by the caller (or any session in the org for an owner)."""
    session = (
        db.query(UserSession)
        .filter(
            UserSession.id == session_id,
            UserSession.organization_id == ctx.user.organization_id,
        )
        .first()
    )
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    if session.user_id != ctx.user.id and ctx.user.role != Role.owner:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to revoke another user's session.",
        )
    if session.revoked_at is None:
        session.revoked_at = utcnow()
        session.revoked_reason = (
            "revoked_by_user" if session.user_id == ctx.user.id else "revoked_by_owner"
        )
        record_audit(
            db,
            organization_id=ctx.user.organization_id,
            actor_user_id=ctx.user.id,
            event_type="auth.session.revoked",
            resource_type="session",
            resource_id=session.id,
            details={"target_user_id": session.user_id},
        )
        db.commit()
    return {"status": "revoked", "session_id": session.id}

