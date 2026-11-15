import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..db import get_db
from ..deps import require_roles
from ..models import AuditLog, Role, User
from ..schemas import AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    event_type: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    actor_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Return filtered, read-only audit log entries for the caller's organization."""
    query = db.query(AuditLog).filter(AuditLog.organization_id == current_user.organization_id)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type.strip())
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type.strip())
    if actor_id:
        query = query.filter(AuditLog.actor_user_id == actor_id)

    return query.order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()


@router.get("/export")
def export_audit_logs(
    format: Literal["jsonl", "csv"] = Query(default="jsonl"),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Export immutable audit trail records with SHA-256 integrity digest validation."""
    query = db.query(AuditLog).filter(AuditLog.organization_id == current_user.organization_id)

    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)

    logs = query.order_by(AuditLog.id.asc()).all()

    now_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if format == "jsonl":
        lines: list[str] = []
        for log in logs:
            record = {
                "id": log.id,
                "organization_id": log.organization_id,
                "actor_user_id": log.actor_user_id,
                "event_type": log.event_type,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": log.details,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
        content = "\n".join(lines).encode("utf-8")
        media_type = "application/x-ndjson"
        filename = f"pentagen-audit-{now_ts}.jsonl"
    else:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["id", "created_at", "actor_user_id", "event_type", "resource_type", "resource_id", "details"])
        for log in logs:
            writer.writerow([
                log.id,
                log.created_at.isoformat() if log.created_at else "",
                log.actor_user_id or "",
                log.event_type,
                log.resource_type,
                log.resource_id,
                json.dumps(log.details, sort_keys=True),
            ])
        content = out.getvalue().encode("utf-8")
        media_type = "text/csv"
        filename = f"pentagen-audit-{now_ts}.csv"

    # Compute tamper-evident content digest over the full export stream
    digest = hashlib.sha256(content).hexdigest()

    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="audit.exported",
        resource_type="audit_log",
        resource_id=f"count_{len(logs)}",
        details={"format": format, "records_count": len(logs), "sha256_digest": digest},
    )
    db.commit()

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-PentaGen-Audit-Digest": digest,
            "X-PentaGen-Record-Count": str(len(logs)),
        },
    )
