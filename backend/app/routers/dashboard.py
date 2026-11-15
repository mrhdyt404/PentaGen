from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import get_current_user
from ..models import (
    AgentNode,
    Approval,
    Finding,
    Scan,
    ScanStatus,
    Target,
    User,
)
from ..reporting.pdf_generator import compute_posture_score
from ..schemas import DashboardOverviewOut

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/overview", response_model=DashboardOverviewOut)
def get_dashboard_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Aggregate enterprise security posture metrics, findings distributions, and recent tasks."""
    org_id = current_user.organization_id

    total_targets = db.query(Target).filter(Target.organization_id == org_id).count()
    total_scans = db.query(Scan).filter(Scan.organization_id == org_id).count()
    active_scans = (
        db.query(Scan)
        .filter(
            Scan.organization_id == org_id,
            Scan.status.in_([ScanStatus.running, ScanStatus.queued, ScanStatus.awaiting_approval]),
        )
        .count()
    )
    pending_approvals = (
        db.query(Approval)
        .filter(Approval.organization_id == org_id, Approval.status == "pending")
        .count()
    )
    paired_agents = (
        db.query(AgentNode)
        .filter(AgentNode.organization_id == org_id, AgentNode.status == "active")
        .count()
    )

    all_findings = db.query(Finding).filter(Finding.organization_id == org_id).all()
    total_findings = len(all_findings)

    sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_dist = {"needs_review": 0, "verified": 0, "false_positive": 0, "resolved": 0}

    for f in all_findings:
        sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
        if sev_key in sev_dist:
            sev_dist[sev_key] += 1
        st_key = str(f.status).lower()
        status_dist[st_key] = status_dist.get(st_key, 0) + 1

    posture_score, security_grade = compute_posture_score(all_findings)

    recent_scans = (
        db.query(Scan)
        .filter(Scan.organization_id == org_id)
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )
    recent_scans_data = [
        {
            "id": s.id,
            "profile": s.profile,
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "target_id": s.target_id,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in recent_scans
    ]

    recent_findings = (
        db.query(Finding)
        .filter(Finding.organization_id == org_id)
        .order_by(Finding.id.desc())
        .limit(5)
        .all()
    )
    recent_findings_data = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "confidence": f.confidence,
            "status": f.status,
            "location": f.location,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in recent_findings
    ]

    recent_approvals = (
        db.query(Approval)
        .filter(Approval.organization_id == org_id)
        .order_by(Approval.created_at.desc())
        .limit(5)
        .all()
    )
    recent_approvals_data = [
        {
            "id": a.id,
            "requested_action": a.requested_action,
            "risk_level": a.risk_level,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in recent_approvals
    ]

    return DashboardOverviewOut(
        total_targets=total_targets,
        total_scans=total_scans,
        active_scans=active_scans,
        pending_approvals=pending_approvals,
        paired_agents=paired_agents,
        total_findings=total_findings,
        posture_score=posture_score,
        security_grade=security_grade,
        severity_distribution=sev_dist,
        status_distribution=status_dist,
        recent_scans=recent_scans_data,
        recent_findings=recent_findings_data,
        recent_approvals=recent_approvals_data,
    )
