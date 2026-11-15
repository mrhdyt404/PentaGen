import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
import pytest

DESKTOP_AGENT_DIR = str(Path(__file__).resolve().parents[2] / "desktop-agent")
if DESKTOP_AGENT_DIR not in sys.path:
    sys.path.insert(0, DESKTOP_AGENT_DIR)

from backend.app.agent_security import (
    generate_envelope_id,
    generate_nonce,
    generate_pairing_token,
    generate_shared_secret,
    sign_agent_request,
    sign_job_envelope,
    verify_agent_request,
    verify_job_envelope,
)
from backend.app.models import AgentJobEnvelope, AgentNode, Approval, PairingToken, ScanStatus
from agent_client import DesktopAgentClient, ALLOWED_DESKTOP_ACTIONS


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _bootstrap_owner(client, email: str = "owner@pentagen.example.com") -> dict:
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "PentaGen Hybrid Security",
            "email": email,
            "password": "StrongOwnerPassword!2026",
            "full_name": "Security Lead",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_and_login_user(client, owner_token: str, *, email: str, role: str) -> dict:
    password = f"Strong{role.capitalize()}Pass!2026"
    create_resp = client.post(
        "/api/v1/users",
        headers=_auth_headers(owner_token),
        json={
            "email": email,
            "password": password,
            "full_name": f"{role} user",
            "role": role,
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200, login_resp.text
    return login_resp.json()


def _mock_public_dns(monkeypatch):
    import ipaddress

    def fake_getaddrinfo(host, port, *args, **kwargs):
        try:
            ipaddress.ip_address(host)
            resolved = host
        except ValueError:
            resolved = "93.184.216.34"
        return [(2, 1, 0, "", (resolved, port or 443))]

    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)


def test_pairing_token_lifecycle_and_single_use(client):
    owner_auth = _bootstrap_owner(client)
    owner_token = owner_auth["access_token"]

    pentester_auth = _create_and_login_user(
        client, owner_token, email="pentester@pentagen.example.com", role="pentester"
    )
    pentester_token = pentester_auth["access_token"]

    # 1. Pentester cannot generate pairing tokens (strictly owner only)
    forbidden_resp = client.post(
        "/api/v1/agents/pairing/tokens",
        headers=_auth_headers(pentester_token),
        json={"name_hint": "Analyst Workstation", "expires_in_minutes": 15},
    )
    assert forbidden_resp.status_code == 403

    # 2. Owner generates pairing token
    token_resp = client.post(
        "/api/v1/agents/pairing/tokens",
        headers=_auth_headers(owner_token),
        json={"name_hint": "Workstation Alpha", "expires_in_minutes": 15},
    )
    assert token_resp.status_code == 200, token_resp.text
    token_data = token_resp.json()
    assert token_data["token"].startswith("pgp_")
    raw_token = token_data["token"]

    # 3. Pair desktop agent device
    desktop = DesktopAgentClient()
    pair_data = desktop.pair(
        server_url="http://testserver",
        pairing_token=raw_token,
        device_name="Workstation Alpha",
        client=client,
    )
    assert desktop.is_paired
    assert desktop.agent_id.startswith("node_")
    assert len(desktop.shared_secret) == 64
    assert pair_data["organization_name"] == "PentaGen Hybrid Security"

    # 4. Attempting to reuse the same token is rejected (single-use enforcement)
    second_desktop = DesktopAgentClient()
    with pytest.raises(RuntimeError) as exc_info:
        second_desktop.pair(
            server_url="http://testserver",
            pairing_token=raw_token,
            device_name="Workstation Beta",
            client=client,
        )
    assert "401" in str(exc_info.value)

    # 5. Invalid token is rejected
    with pytest.raises(RuntimeError) as exc_info:
        second_desktop.pair(
            server_url="http://testserver",
            pairing_token="pgp_invalid_token_value_here",
            device_name="Workstation Gamma",
            client=client,
        )
    assert "401" in str(exc_info.value)


def test_agent_node_management_and_revocation(client):
    owner_auth = _bootstrap_owner(client)
    owner_token = owner_auth["access_token"]

    reviewer_auth = _create_and_login_user(
        client, owner_token, email="reviewer@pentagen.example.com", role="reviewer"
    )
    reviewer_token = reviewer_auth["access_token"]

    # Generate token and pair agent
    token_resp = client.post(
        "/api/v1/agents/pairing/tokens",
        headers=_auth_headers(owner_token),
        json={"name_hint": "SecOps Node 1"},
    )
    raw_token = token_resp.json()["token"]

    desktop = DesktopAgentClient()
    desktop.pair("http://testserver", raw_token, "SecOps Node 1", client=client)

    # Reviewer can view nodes
    nodes_resp = client.get(
        "/api/v1/agents/nodes",
        headers=_auth_headers(reviewer_token),
    )
    assert nodes_resp.status_code == 200
    nodes = nodes_resp.json()
    assert len(nodes) == 1
    assert nodes[0]["id"] == desktop.agent_id
    assert nodes[0]["status"] == "active"
    assert "shared_secret" not in nodes[0]  # Ensure secret is never leaked

    # Owner revokes the agent node
    revoke_resp = client.post(
        f"/api/v1/agents/nodes/{desktop.agent_id}/revoke",
        headers=_auth_headers(owner_token),
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "revoked"

    # Revoked agent cannot poll for jobs
    with pytest.raises(RuntimeError) as exc_info:
        desktop.poll_job(client=client)
    assert "401" in str(exc_info.value)


def test_hmac_envelope_and_request_signature_verification():
    secret = generate_shared_secret()
    envelope_id = generate_envelope_id()
    agent_id = "node_test_01"
    action = "safe_baseline"
    payload = {"target_hostname": "target.example.com", "params": {"check": "headers"}}
    nonce = generate_nonce()

    # 1. Authentic envelope signature
    sig = sign_job_envelope(secret, envelope_id, agent_id, action, payload, nonce)
    assert verify_job_envelope(secret, envelope_id, agent_id, action, payload, nonce, sig)

    # 2. Tampered payload is rejected
    tampered_payload = dict(payload)
    tampered_payload["target_hostname"] = "malicious.example.com"
    assert not verify_job_envelope(
        secret, envelope_id, agent_id, action, tampered_payload, nonce, sig
    )

    # 3. Tampered nonce is rejected
    assert not verify_job_envelope(
        secret, envelope_id, agent_id, action, payload, "tampered_nonce", sig
    )

    # 4. Tampered action is rejected
    assert not verify_job_envelope(
        secret, envelope_id, agent_id, "active_exploit", payload, nonce, sig
    )

    # 5. Agent request signature and timestamp freshness
    now_ts = str(int(time.time()))
    req_sig = sign_agent_request(secret, agent_id, "GET", "/api/v1/agents/jobs/poll", now_ts, nonce)
    is_valid, err = verify_agent_request(
        secret, agent_id, "GET", "/api/v1/agents/jobs/poll", now_ts, nonce, b"", req_sig
    )
    assert is_valid
    assert err is None

    # Stale timestamp (> 300s) rejected
    stale_ts = str(int(time.time()) - 400)
    stale_sig = sign_agent_request(secret, agent_id, "GET", "/api/v1/agents/jobs/poll", stale_ts, nonce)
    is_valid, err = verify_agent_request(
        secret, agent_id, "GET", "/api/v1/agents/jobs/poll", stale_ts, nonce, b"", stale_sig
    )
    assert not is_valid
    assert "freshness window" in err


def test_approval_gated_desktop_execution_workflow(client, monkeypatch):
    _mock_public_dns(monkeypatch)
    owner_auth = _bootstrap_owner(client)
    owner_token = owner_auth["access_token"]

    reviewer_auth = _create_and_login_user(
        client, owner_token, email="reviewer@pentagen.example.com", role="reviewer"
    )
    reviewer_token = reviewer_auth["access_token"]

    pentester_auth = _create_and_login_user(
        client, owner_token, email="pentester@pentagen.example.com", role="pentester"
    )
    pentester_token = pentester_auth["access_token"]

    # Register target with safe_baseline authorization
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    target_resp = client.post(
        "/api/v1/targets",
        headers=_auth_headers(owner_token),
        json={
            "name": "Production API Target",
            "base_url": "https://api.example.com",
            "authorization_reference": "SECOPS-PROD-2026",
            "authorization_expires_at": future_expiry,
            "allowed_profiles": ["safe_baseline"],
        },
    )
    assert target_resp.status_code == 201, target_resp.text
    target_id = target_resp.json()["id"]

    # Pair desktop agent
    token_resp = client.post(
        "/api/v1/agents/pairing/tokens",
        headers=_auth_headers(owner_token),
        json={"name_hint": "Auditor Laptop"},
    )
    raw_token = token_resp.json()["token"]
    desktop = DesktopAgentClient()
    desktop.pair("http://testserver", raw_token, "Auditor Laptop", client=client)

    # Schedule a desktop job requiring human approval
    job_create_resp = client.post(
        "/api/v1/agents/jobs",
        headers=_auth_headers(pentester_token),
        json={
            "target_id": target_id,
            "project_name": "Gated Production Assessment",
            "action": "safe_baseline",
            "agent_node_id": desktop.agent_id,
            "requires_approval": True,
            "risk_level": "high",
            "confirm_authorized": True,
        },
    )
    assert job_create_resp.status_code == 200, job_create_resp.text
    job_data = job_create_resp.json()
    envelope_id = job_data["id"]
    approval_id = job_data["approval_id"]
    assert job_data["status"] == "pending_approval"
    assert approval_id is not None

    # Desktop agent polls: NO job is returned because it is awaiting approval!
    polled = desktop.poll_job(client=client)
    assert polled is None

    # Review approvals list
    approvals_resp = client.get(
        "/api/v1/approvals?status=pending",
        headers=_auth_headers(reviewer_token),
    )
    assert approvals_resp.status_code == 200
    pending_list = approvals_resp.json()
    assert len(pending_list) >= 1
    assert any(a["id"] == approval_id for a in pending_list)

    # Pentester attempts to decide approval -> 403 Forbidden (separation of duties)
    forbidden_decision = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers=_auth_headers(pentester_token),
        json={"decision": "approve", "reason": "Self-approval attempt"},
    )
    assert forbidden_decision.status_code == 403

    # Reviewer approves the gated action
    decision_resp = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers=_auth_headers(reviewer_token),
        json={"decision": "approve", "reason": "SecOps lead approved after scope validation."},
    )
    assert decision_resp.status_code == 200
    assert decision_resp.json()["status"] == "approved"

    # Now desktop agent polls: receives the signed job envelope!
    job_envelope = desktop.poll_job(client=client)
    assert job_envelope is not None
    assert job_envelope["id"] == envelope_id
    assert job_envelope["action"] == "safe_baseline"

    # Verify envelope HMAC and policy locally
    is_valid, err = desktop.verify_envelope(job_envelope)
    assert is_valid, err

    # Execute locally and submit results
    results = desktop.execute_job(job_envelope)
    assert results["status"] == "completed"
    assert len(results["findings"]) >= 1

    submit_resp = desktop.submit_results(envelope_id, results, client=client)
    assert submit_resp["status"] == "ok"
    assert submit_resp["findings_count"] >= 1

    # Verify scan is now marked completed and findings are persisted
    scan_id = job_envelope["scan_id"]
    scan_resp = client.get(
        f"/api/v1/scans/{scan_id}",
        headers=_auth_headers(reviewer_token),
    )
    assert scan_resp.status_code == 200
    assert scan_resp.json()["status"] == ScanStatus.completed


def test_approval_rejection_halts_task(client, monkeypatch):
    _mock_public_dns(monkeypatch)
    owner_auth = _bootstrap_owner(client)
    owner_token = owner_auth["access_token"]

    reviewer_auth = _create_and_login_user(
        client, owner_token, email="reviewer@pentagen.example.com", role="reviewer"
    )
    reviewer_token = reviewer_auth["access_token"]

    future_expiry = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    target_resp = client.post(
        "/api/v1/targets",
        headers=_auth_headers(owner_token),
        json={
            "name": "Sensitive Internal Service",
            "base_url": "https://service.example.com",
            "authorization_reference": "SECOPS-2026-REJECT",
            "authorization_expires_at": future_expiry,
            "allowed_profiles": ["safe_baseline"],
        },
    )
    target_id = target_resp.json()["id"]

    token_resp = client.post(
        "/api/v1/agents/pairing/tokens",
        headers=_auth_headers(owner_token),
        json={"name_hint": "Desktop Agent"},
    )
    desktop = DesktopAgentClient()
    desktop.pair("http://testserver", token_resp.json()["token"], "Desktop Agent", client=client)

    job_create_resp = client.post(
        "/api/v1/agents/jobs",
        headers=_auth_headers(owner_token),
        json={
            "target_id": target_id,
            "project_name": "Rejected Assessment",
            "action": "safe_baseline",
            "agent_node_id": desktop.agent_id,
            "requires_approval": True,
            "confirm_authorized": True,
        },
    )
    approval_id = job_create_resp.json()["approval_id"]
    scan_id = job_create_resp.json()["scan_id"]

    # Reviewer rejects the approval
    reject_resp = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers=_auth_headers(reviewer_token),
        json={"decision": "reject", "reason": "Target is undergoing emergency maintenance."},
    )
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "rejected"

    # Polling receives nothing
    polled = desktop.poll_job(client=client)
    assert polled is None

    # Scan status is cancelled
    scan_resp = client.get(
        f"/api/v1/scans/{scan_id}",
        headers=_auth_headers(reviewer_token),
    )
    assert scan_resp.json()["status"] == ScanStatus.cancelled


def test_cross_tenant_desktop_isolation(client, monkeypatch, db_session_factory):
    _mock_public_dns(monkeypatch)
    # Organization A
    owner_a = _bootstrap_owner(client, email="owner_a@pentagen.example.com")
    token_a = owner_a["access_token"]

    target_resp = client.post(
        "/api/v1/targets",
        headers=_auth_headers(token_a),
        json={
            "name": "Org A Target",
            "base_url": "https://orga.example.com",
            "authorization_reference": "AUTH-ORG-A",
            "authorization_expires_at": (datetime.now(timezone.utc) + timedelta(days=5)).isoformat(),
            "allowed_profiles": ["safe_baseline"],
        },
    )
    target_a_id = target_resp.json()["id"]

    token_a_pair = client.post(
        "/api/v1/agents/pairing/tokens",
        headers=_auth_headers(token_a),
        json={"name_hint": "Agent A"},
    )
    desktop_a = DesktopAgentClient()
    desktop_a.pair("http://testserver", token_a_pair.json()["token"], "Agent A", client=client)

    # Schedule job in Org A (safe, no approval needed)
    job_a_resp = client.post(
        "/api/v1/agents/jobs",
        headers=_auth_headers(token_a),
        json={
            "target_id": target_a_id,
            "project_name": "Org A Job",
            "action": "safe_baseline",
            "agent_node_id": desktop_a.agent_id,
            "requires_approval": False,
            "confirm_authorized": True,
        },
    )
    assert job_a_resp.status_code == 200
    job_a_id = job_a_resp.json()["id"]

    # Provision Organization B in DB directly to simulate multi-tenant separation
    from backend.app.models import Organization, Role, User
    from backend.app.security import hash_password

    with db_session_factory() as db:
        org_b = Organization(name="Org B Competitor", slug="org-b-competitor")
        db.add(org_b)
        db.flush()
        user_b = User(
            organization_id=org_b.id,
            email="owner_b@pentagen.example.com",
            password_hash=hash_password("StrongOwnerPassword!2026"),
            role=Role.owner,
            is_active=True,
        )
        db.add(user_b)
        db.flush()

        raw_b_token, token_b_hash = generate_pairing_token()
        pair_token_b = PairingToken(
            organization_id=org_b.id,
            created_by=user_b.id,
            token_hash=token_b_hash,
            name_hint="Agent B",
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=15),
        )
        db.add(pair_token_b)
        db.commit()

    desktop_b = DesktopAgentClient()
    desktop_b.pair("http://testserver", raw_b_token, "Agent B", client=client)

    # Agent B polling must NEVER receive Org A's job!
    polled_b = desktop_b.poll_job(client=client)
    assert polled_b is None

    # Agent B attempting to submit results for Org A's job is rejected (404)
    with pytest.raises(RuntimeError) as exc_info:
        desktop_b.submit_results(
            job_a_id,
            {"status": "completed", "findings": [], "assets": [], "evidence": [], "summary": {}},
            client=client,
        )
    assert "404" in str(exc_info.value)


def test_desktop_client_execution_policy_and_ssrf_rejection():
    desktop = DesktopAgentClient(
        server_url="http://testserver",
        agent_id="node_unit_test",
        shared_secret=generate_shared_secret(),
        organization_id=1,
    )

    # Disallowed action rejected
    fake_job_bad_action = {
        "id": "env_bad",
        "action": "destructive_exploit",
        "payload_json": {"target_hostname": "target.example.com"},
        "nonce": "1234567890abcdef",
    }
    fake_job_bad_action["signature"] = sign_job_envelope(
        desktop.shared_secret,
        fake_job_bad_action["id"],
        desktop.agent_id,
        fake_job_bad_action["action"],
        fake_job_bad_action["payload_json"],
        fake_job_bad_action["nonce"],
    )
    is_valid, err = desktop.verify_envelope(fake_job_bad_action)
    assert not is_valid
    assert "local agent execution policy" in err

    # SSRF target (127.0.0.1) rejected
    fake_job_ssrf = {
        "id": "env_ssrf",
        "action": "safe_baseline",
        "payload_json": {"target_hostname": "127.0.0.1"},
        "nonce": "1234567890abcdef",
    }
    fake_job_ssrf["signature"] = sign_job_envelope(
        desktop.shared_secret,
        fake_job_ssrf["id"],
        desktop.agent_id,
        fake_job_ssrf["action"],
        fake_job_ssrf["payload_json"],
        fake_job_ssrf["nonce"],
    )
    is_valid, err = desktop.verify_envelope(fake_job_ssrf)
    assert not is_valid
    assert "local SSRF protection" in err
