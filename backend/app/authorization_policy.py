from datetime import datetime
from sqlalchemy.orm import Session
from .audit import to_naive_utc
from .models import Authorization, Target, utcnow

ALLOWED_SCAN_PROFILES = frozenset({"safe_baseline"})


class AuthorizationPolicyError(ValueError):
    """Raised when an authorization window or scope definition is invalid."""


def validate_profiles(profiles: list[str]) -> list[str]:
    """Validate and deduplicate requested assessment profiles."""
    cleaned: list[str] = []
    for profile in profiles:
        name = profile.strip()
        if name not in ALLOWED_SCAN_PROFILES:
            raise AuthorizationPolicyError(
                f"Profile '{name}' is not permitted in the current MVP release."
            )
        if name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        raise AuthorizationPolicyError("At least one valid assessment profile is required.")
    return cleaned


def validate_authorization_window(
    starts_at: datetime | None,
    expires_at: datetime,
) -> tuple[datetime, datetime]:
    """Normalize authorization timestamps to UTC and verify the window is valid and active."""
    now = utcnow()
    start_utc = to_naive_utc(starts_at) if starts_at is not None else now
    expiry_utc = to_naive_utc(expires_at)
    if expiry_utc <= start_utc:
        raise AuthorizationPolicyError("Authorization expiry must be after the start time.")
    if expiry_utc <= now:
        raise AuthorizationPolicyError("Authorization expiry must be in the future.")
    return start_utc, expiry_utc


def find_matching_authorization(
    db: Session,
    *,
    organization_id: int,
    target: Target,
    profile: str,
    now: datetime | None = None,
) -> Authorization | None:
    """Return the newest approved, active authorization matching target and scan profile."""
    check_time = now or utcnow()
    candidates = (
        db.query(Authorization)
        .filter(
            Authorization.organization_id == organization_id,
            Authorization.target_id == target.id,
            Authorization.approved.is_(True),
            Authorization.revoked_at.is_(None),
            Authorization.starts_at <= check_time,
            Authorization.expires_at > check_time,
        )
        .order_by(Authorization.expires_at.desc())
        .all()
    )
    for auth in candidates:
        scope = auth.scope_json or {}
        allowed_profiles = scope.get("allowed_profiles") or ["safe_baseline"]
        if profile not in allowed_profiles:
            continue
        scope_host = scope.get("hostname")
        if scope_host and scope_host != target.hostname:
            continue
        scope_url = scope.get("base_url")
        if scope_url and scope_url != target.base_url:
            continue
        return auth
    return None

