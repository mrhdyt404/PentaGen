from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .models import AuditLog


def to_naive_utc(value: datetime) -> datetime:
    """Normalize aware or naive datetime to naive UTC."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def record_audit(
    db: Session,
    *,
    organization_id: int | None,
    actor_user_id: int | None,
    event_type: str,
    resource_type: str,
    resource_id: str,
    details: dict | None = None,
) -> AuditLog:
    """Append an audit entry to the current database transaction."""
    entry = AuditLog(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
    )
    db.add(entry)
    return entry

