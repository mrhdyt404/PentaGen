from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import require_roles
from ..models import AuditLog, Role, User
from ..schemas import AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Return read-only audit log entries for the caller's organization."""
    return (
        db.query(AuditLog)
        .filter(AuditLog.organization_id == current_user.organization_id)
        .order_by(AuditLog.id.desc())
        .limit(200)
        .all()
    )

