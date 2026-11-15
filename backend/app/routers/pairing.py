from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..agent_security import (
    generate_node_id,
    generate_pairing_token,
    generate_shared_secret,
    hash_token,
)
from ..audit import record_audit
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import (
    AgentJobEnvelope,
    AgentNode,
    Organization,
    PairingToken,
    Role,
    User,
    utcnow,
)
from ..schemas import (
    AgentNodeOut,
    PairDeviceRequest,
    PairDeviceResponse,
    PairingTokenCreate,
    PairingTokenOut,
)

router = APIRouter(tags=["agents-pairing"])


@router.post("/agents/pairing/tokens", response_model=PairingTokenOut)
def create_pairing_token(
    payload: PairingTokenCreate,
    current_user: User = Depends(require_roles(Role.owner)),
    db: Session = Depends(get_db),
):
    """Generate a single-use desktop agent pairing token (owner only)."""
    raw_token, token_hash = generate_pairing_token()
    now = utcnow()
    expires_at = now + timedelta(minutes=payload.expires_in_minutes)

    token_record = PairingToken(
        organization_id=current_user.organization_id,
        created_by=current_user.id,
        token_hash=token_hash,
        name_hint=payload.name_hint.strip() if payload.name_hint else None,
        expires_at=expires_at,
        created_at=now,
    )
    db.add(token_record)
    db.flush()

    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="agent_pairing.token_created",
        resource_type="pairing_token",
        resource_id=str(token_record.id),
        details={"name_hint": payload.name_hint, "expires_at": expires_at.isoformat()},
    )
    db.commit()

    return PairingTokenOut(
        id=token_record.id,
        token=raw_token,
        name_hint=token_record.name_hint,
        expires_at=token_record.expires_at,
        created_at=token_record.created_at,
    )


@router.post("/agents/pairing/pair", response_model=PairDeviceResponse)
def pair_desktop_device(
    payload: PairDeviceRequest,
    db: Session = Depends(get_db),
):
    """Pair a desktop agent device using a valid single-use pairing token."""
    token_digest = hash_token(payload.token)
    now = utcnow()

    token_record = (
        db.query(PairingToken)
        .filter(
            PairingToken.token_hash == token_digest,
            PairingToken.used_at.is_(None),
            PairingToken.expires_at > now,
        )
        .first()
    )
    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or already-consumed pairing token.",
        )

    org = db.query(Organization).filter(Organization.id == token_record.organization_id).first()
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")

    node_id = generate_node_id()
    shared_secret = generate_shared_secret()

    agent_node = AgentNode(
        id=node_id,
        organization_id=token_record.organization_id,
        name=payload.device_name.strip(),
        device_fingerprint=payload.device_fingerprint.strip(),
        shared_secret=shared_secret,
        status="active",
        platform_info=payload.platform_info,
        last_seen_at=now,
        created_at=now,
    )
    db.add(agent_node)

    token_record.used_at = now

    record_audit(
        db,
        organization_id=token_record.organization_id,
        actor_user_id=token_record.created_by,
        event_type="agent.paired",
        resource_type="agent_node",
        resource_id=node_id,
        details={
            "device_name": payload.device_name,
            "device_fingerprint": payload.device_fingerprint,
        },
    )
    db.commit()

    return PairDeviceResponse(
        agent_id=node_id,
        shared_secret=shared_secret,
        organization_id=org.id,
        organization_name=org.name,
    )


@router.get("/agents/nodes", response_model=list[AgentNodeOut])
def list_agent_nodes(
    current_user: User = Depends(require_roles(Role.owner, Role.reviewer, Role.pentester)),
    db: Session = Depends(get_db),
):
    """List paired desktop agent devices belonging to the caller's organization."""
    return (
        db.query(AgentNode)
        .filter(AgentNode.organization_id == current_user.organization_id)
        .order_by(AgentNode.created_at.desc())
        .all()
    )


@router.post("/agents/nodes/{node_id}/revoke", response_model=AgentNodeOut)
def revoke_agent_node(
    node_id: str,
    current_user: User = Depends(require_roles(Role.owner)),
    db: Session = Depends(get_db),
):
    """Revoke a paired desktop agent node immediately (owner only)."""
    node = (
        db.query(AgentNode)
        .filter(
            AgentNode.id == node_id,
            AgentNode.organization_id == current_user.organization_id,
        )
        .first()
    )
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Agent node not found."
        )

    if node.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Agent node is already revoked."
        )

    now = utcnow()
    node.status = "revoked"
    node.revoked_at = now
    node.revoked_by = current_user.id

    # Cancel any pending envelopes assigned to this revoked node
    pending_envelopes = (
        db.query(AgentJobEnvelope)
        .filter(
            AgentJobEnvelope.agent_node_id == node_id,
            AgentJobEnvelope.status.in_(["pending", "dispatched"]),
        )
        .all()
    )
    for env in pending_envelopes:
        env.status = "cancelled"

    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="agent.revoked",
        resource_type="agent_node",
        resource_id=node.id,
        details={"name": node.name},
    )
    db.commit()
    db.refresh(node)

    return node
