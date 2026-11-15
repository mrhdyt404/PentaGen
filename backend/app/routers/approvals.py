from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import (
    AgentJobEnvelope,
    Approval,
    Role,
    Scan,
    ScanStatus,
    User,
    utcnow,
)
from ..schemas import ApprovalDecisionRequest, ApprovalOut

router = APIRouter(tags=["approvals"])


@router.get("/approvals", response_model=list[ApprovalOut])
def list_approvals(
    status_filter: str | None = Query(default=None, alias="status"),
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer, Role.pentester)),
    db: Session = Depends(get_db),
):
    """List gated security action approvals for the caller's organization."""
    query = db.query(Approval).filter(Approval.organization_id == current_user.organization_id)
    if status_filter:
        query = query.filter(Approval.status == status_filter.strip())
    return query.order_by(Approval.created_at.desc()).limit(100).all()


@router.get("/approvals/{approval_id}", response_model=ApprovalOut)
def get_approval(
    approval_id: int,
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Retrieve details of a single gated security approval."""
    approval = (
        db.query(Approval)
        .filter(
            Approval.id == approval_id,
            Approval.organization_id == current_user.organization_id,
        )
        .first()
    )
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found."
        )
    return approval


@router.post("/approvals/{approval_id}/decide", response_model=ApprovalOut)
def decide_approval(
    approval_id: int,
    payload: ApprovalDecisionRequest,
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Approve or reject a gated security assessment action (reviewer or owner only)."""
    approval = (
        db.query(Approval)
        .filter(
            Approval.id == approval_id,
            Approval.organization_id == current_user.organization_id,
        )
        .first()
    )
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found."
        )

    if approval.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Approval request is already in '{approval.status}' state.",
        )

    now = utcnow()
    approval.decided_by = current_user.id
    approval.decided_at = now
    approval.reason = payload.reason.strip()

    associated_scan = (
        db.query(Scan)
        .filter(
            Scan.id == approval.scan_id,
            Scan.organization_id == current_user.organization_id,
        )
        .first()
    )

    associated_envelope = None
    if approval.envelope_id:
        associated_envelope = (
            db.query(AgentJobEnvelope)
            .filter(
                AgentJobEnvelope.id == approval.envelope_id,
                AgentJobEnvelope.organization_id == current_user.organization_id,
            )
            .first()
        )

    if payload.decision == "approve":
        approval.status = "approved"
        if associated_envelope and associated_envelope.status == "pending_approval":
            associated_envelope.status = "pending"
        if associated_scan and associated_scan.status == ScanStatus.awaiting_approval:
            associated_scan.status = ScanStatus.running

        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="approval.approved",
            resource_type="approval",
            resource_id=str(approval.id),
            details={
                "scan_id": approval.scan_id,
                "requested_action": approval.requested_action,
                "reason": payload.reason,
            },
        )
    else:
        approval.status = "rejected"
        if associated_envelope:
            associated_envelope.status = "rejected"
        if associated_scan:
            associated_scan.status = ScanStatus.cancelled

        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="approval.rejected",
            resource_type="approval",
            resource_id=str(approval.id),
            details={
                "scan_id": approval.scan_id,
                "requested_action": approval.requested_action,
                "reason": payload.reason,
            },
        )

    db.commit()
    db.refresh(approval)
    return approval
