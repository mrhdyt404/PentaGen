from dataclasses import dataclass
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from .db import get_db
from .models import Role, User, UserSession, utcnow
from .security import TokenError, decode_access_token

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthContext:
    """Authenticated user paired with their active database session."""

    user: User
    session: UserSession


def get_auth_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Authenticate Bearer JWT and verify the backing session and user remain active."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = int(payload["sub"])
    org_id = int(payload["org"])
    session_id = payload["sid"]
    now = utcnow()

    session = db.get(UserSession, session_id)
    if (
        session is None
        or session.user_id != user_id
        or session.organization_id != org_id
        or session.revoked_at is not None
        or session.expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is invalid, expired, or revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, user_id)
    if user is None or not user.is_active or user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or unavailable.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return AuthContext(user=user, session=session)


def get_current_user(ctx: AuthContext = Depends(get_auth_context)) -> User:
    """Return the authenticated active user."""
    return ctx.user


def require_roles(*allowed_roles: Role):
    """Build a dependency that enforces RBAC role membership using live DB role."""

    allowed = set(allowed_roles)

    def _guard(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this action.",
            )
        return user

    return _guard


def get_client_metadata(request: Request) -> tuple[str | None, str | None]:
    """Extract bounded user-agent and client IP metadata for session tracking."""
    user_agent = request.headers.get("user-agent")
    if user_agent:
        user_agent = user_agent[:512]
    ip_address = request.client.host if request.client else None
    if ip_address:
        ip_address = ip_address[:64]
    return user_agent, ip_address

