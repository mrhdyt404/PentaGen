from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
from alembic import command
from alembic.config import Config
import jwt
from backend.app.config import Settings
from backend.app.models import Authorization, Organization, Role, Target, User
from backend.app.security import hash_password, verify_password
import pytest


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _bootstrap_owner(client, email: str = "owner@pentagen.example.com") -> dict:
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "PentaGen Security",
            "email": email,
            "password": "StrongOwnerPassword!2026",
            "full_name": "Initial Owner",
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
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolved, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def test_alembic_roundtrip(tmp_path: Path):
    project_root = Path(__file__).resolve().parents[2]
    db_file = tmp_path / "alembic_roundtrip.db"
    cfg = Config(str(project_root / "backend" / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_file.as_posix()}")

    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


def test_argon2id_hashing_and_verification():
    hashed = hash_password("CorrectHorseBatteryStaple!99")
    assert hashed.startswith("$argon2id$")
    assert verify_password("CorrectHorseBatteryStaple!99", hashed) is True
    assert verify_password("wrong-password", hashed) is False
    assert verify_password("anything", "not-a-valid-hash") is False


def test_bootstrap_and_session_lifecycle(client, db_session_factory):
    owner_data = _bootstrap_owner(client)
    access_token = owner_data["access_token"]
    refresh_token = owner_data["refresh_token"]
    session_id = owner_data["session_id"]

    # Stored password uses Argon2id.
    with db_session_factory() as db:
        owner = db.query(User).filter(User.email == "owner@pentagen.example.com").one()
        assert owner.password_hash.startswith("$argon2id$")

    # Second public registration must be rejected.
    second = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Rogue Org",
            "email": "attacker@evil.example.com",
            "password": "AttackerPassword!2026",
        },
    )
    assert second.status_code == 403

    # /me succeeds with valid bearer token.
    me = client.get("/api/v1/auth/me", headers=_auth_headers(access_token))
    assert me.status_code == 200
    assert me.json()["role"] == "owner"

    # Refresh rotates refresh token; replaying old refresh token fails.
    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refreshed.status_code == 200
    new_access = refreshed.json()["access_token"]
    new_refresh = refreshed.json()["refresh_token"]
    assert new_refresh != refresh_token

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert replay.status_code == 401

    # Logout immediately revokes both refresh and access tokens for the session.
    sessions = client.get("/api/v1/auth/sessions", headers=_auth_headers(new_access))
    assert sessions.status_code == 200
    assert any(s["id"] == session_id and s["is_current"] for s in sessions.json())

    logout = client.post("/api/v1/auth/logout", headers=_auth_headers(new_access))
    assert logout.status_code == 200

    assert client.get("/api/v1/auth/me", headers=_auth_headers(new_access)).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh}).status_code == 401
    )


def test_tampered_and_unauthenticated_requests_rejected(client):
    assert client.get("/api/v1/targets").status_code == 401
    assert client.get("/api/v1/findings").status_code == 401
    assert client.get("/api/v1/users").status_code == 401
    assert client.get("/api/v1/audit-logs").status_code == 401

    forged = jwt.encode(
        {"sub": "1", "org": 1, "role": "owner", "sid": "fake"},
        "wrong-secret-key-12345678901234567890",
        algorithm="HS256",
    )
    assert client.get("/api/v1/auth/me", headers=_auth_headers(forged)).status_code == 401


def test_rbac_user_management_and_session_invalidation(client):
    owner = _bootstrap_owner(client)
    owner_token = owner["access_token"]

    pentester = _create_and_login_user(
        client, owner_token, email="pentester@pentagen.example.com", role="pentester"
    )
    viewer = _create_and_login_user(
        client, owner_token, email="viewer@pentagen.example.com", role="viewer"
    )
    reviewer = _create_and_login_user(
        client, owner_token, email="reviewer@pentagen.example.com", role="reviewer"
    )

    # Only owners manage users.
    for non_owner in (pentester, viewer, reviewer):
        assert (
            client.get("/api/v1/users", headers=_auth_headers(non_owner["access_token"])).status_code
            == 403
        )
        assert (
            client.post(
                "/api/v1/users",
                headers=_auth_headers(non_owner["access_token"]),
                json={
                    "email": "escalate@pentagen.example.com",
                    "password": "EscalatedPassword!2026",
                    "role": "owner",
                },
            ).status_code
            == 403
        )

    # Cannot demote or deactivate the last active owner.
    owner_id = owner["user"]["id"]
    assert (
        client.patch(
            f"/api/v1/users/{owner_id}",
            headers=_auth_headers(owner_token),
            json={"role": "viewer"},
        ).status_code
        == 400
    )

    # Audit log access is restricted to owner and reviewer.
    assert client.get("/api/v1/audit-logs", headers=_auth_headers(owner_token)).status_code == 200
    assert (
        client.get("/api/v1/audit-logs", headers=_auth_headers(reviewer["access_token"])).status_code
        == 200
    )
    assert (
        client.get("/api/v1/audit-logs", headers=_auth_headers(pentester["access_token"])).status_code
        == 403
    )
    assert (
        client.get("/api/v1/audit-logs", headers=_auth_headers(viewer["access_token"])).status_code
        == 403
    )

    # Deactivating viewer revokes their active access token immediately.
    viewer_id = viewer["user"]["id"]
    deactivate = client.patch(
        f"/api/v1/users/{viewer_id}",
        headers=_auth_headers(owner_token),
        json={"is_active": False},
    )
    assert deactivate.status_code == 200
    assert (
        client.get("/api/v1/auth/me", headers=_auth_headers(viewer["access_token"])).status_code
        == 401
    )


def test_target_authorization_scope_and_scan_enforcement(client, monkeypatch):
    _mock_public_dns(monkeypatch)

    async def fake_inspect_headers(url: str) -> list[dict]:
        return [
            {
                "title": "Missing security header: content-security-policy",
                "description": "The HTTP response did not include content-security-policy.",
                "severity": "medium",
                "confidence": "high",
                "remediation": "Define a restrictive Content Security Policy.",
                "evidence": "HTTP 200; header absent",
            }
        ]

    monkeypatch.setattr("backend.app.scanners.orchestrator.inspect_headers", fake_inspect_headers)

    async def fake_inspect_tls(*args, **kwargs):
        from backend.app.scanners.evidence import ScanModuleResult

        return ScanModuleResult()

    monkeypatch.setattr("backend.app.scanners.orchestrator.inspect_tls", fake_inspect_tls)

    owner = _bootstrap_owner(client)
    owner_token = owner["access_token"]
    pentester = _create_and_login_user(
        client, owner_token, email="pentester@pentagen.example.com", role="pentester"
    )
    reviewer = _create_and_login_user(
        client, owner_token, email="reviewer@pentagen.example.com", role="reviewer"
    )
    viewer = _create_and_login_user(
        client, owner_token, email="viewer@pentagen.example.com", role="viewer"
    )

    future_expiry = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    # SSRF / localhost targets are rejected.
    bad_target = client.post(
        "/api/v1/targets",
        headers=_auth_headers(owner_token),
        json={
            "name": "Localhost forbidden",
            "base_url": "http://127.0.0.1:8000",
            "authorization_reference": "TICKET-001",
            "authorization_expires_at": future_expiry,
        },
    )
    assert bad_target.status_code == 400

    # Viewers and reviewers cannot register targets or trigger scans.
    assert (
        client.post(
            "/api/v1/targets",
            headers=_auth_headers(viewer["access_token"]),
            json={
                "name": "Staging",
                "base_url": "https://example.com",
                "authorization_reference": "TICKET-002",
                "authorization_expires_at": future_expiry,
            },
        ).status_code
        == 403
    )

    # Target registered by pentester starts unapproved.
    target_resp = client.post(
        "/api/v1/targets",
        headers=_auth_headers(pentester["access_token"]),
        json={
            "name": "Example Staging",
            "base_url": "https://example.com",
            "authorization_reference": "SOW-2026-01",
            "authorization_expires_at": future_expiry,
        },
    )
    assert target_resp.status_code == 201, target_resp.text
    target_id = target_resp.json()["id"]

    auths = client.get(
        f"/api/v1/targets/{target_id}/authorizations",
        headers=_auth_headers(pentester["access_token"]),
    )
    assert auths.status_code == 200
    auth_id = auths.json()[0]["id"]
    assert auths.json()[0]["approved"] is False

    # Scan fails while authorization is pending approval.
    blocked_scan = client.post(
        "/api/v1/scans",
        headers=_auth_headers(pentester["access_token"]),
        json={
            "target_id": target_id,
            "project_name": "Q4 Baseline",
            "profile": "safe_baseline",
            "confirm_authorized": True,
        },
    )
    assert blocked_scan.status_code == 403

    # Pentester cannot self-approve; reviewer approves.
    assert (
        client.post(
            f"/api/v1/authorizations/{auth_id}/approve",
            headers=_auth_headers(pentester["access_token"]),
        ).status_code
        == 403
    )
    approve = client.post(
        f"/api/v1/authorizations/{auth_id}/approve",
        headers=_auth_headers(reviewer["access_token"]),
    )
    assert approve.status_code == 200
    assert approve.json()["approved"] is True

    # Missing explicit confirmation is blocked.
    unconfirmed = client.post(
        "/api/v1/scans",
        headers=_auth_headers(pentester["access_token"]),
        json={
            "target_id": target_id,
            "project_name": "Q4 Baseline",
            "profile": "safe_baseline",
            "confirm_authorized": False,
        },
    )
    assert unconfirmed.status_code == 403

    # Authorized scan succeeds and records findings.
    scan = client.post(
        "/api/v1/scans",
        headers=_auth_headers(pentester["access_token"]),
        json={
            "target_id": target_id,
            "project_name": "Q4 Baseline",
            "profile": "safe_baseline",
            "confirm_authorized": True,
        },
    )
    assert scan.status_code == 200, scan.text
    assert scan.json()["status"] == "completed"
    assert scan.json()["finding_count"] == 1

    findings = client.get("/api/v1/findings", headers=_auth_headers(viewer["access_token"]))
    assert findings.status_code == 200
    assert len(findings.json()) == 1

    # Revoking authorization blocks future scans immediately.
    revoke = client.post(
        f"/api/v1/authorizations/{auth_id}/revoke",
        headers=_auth_headers(owner_token),
    )
    assert revoke.status_code == 200
    assert revoke.json()["approved"] is False

    post_revoke_scan = client.post(
        "/api/v1/scans",
        headers=_auth_headers(pentester["access_token"]),
        json={
            "target_id": target_id,
            "project_name": "Q4 Followup",
            "profile": "safe_baseline",
            "confirm_authorized": True,
        },
    )
    assert post_revoke_scan.status_code == 403


def test_cross_organization_isolation(client, db_session_factory, monkeypatch):
    _mock_public_dns(monkeypatch)
    owner = _bootstrap_owner(client)
    owner_token = owner["access_token"]

    # Seed a second tenant directly in DB to verify strict query isolation.
    with db_session_factory() as db:
        other_org = Organization(name="Other Corp", slug="other-corp")
        db.add(other_org)
        db.flush()
        other_user = User(
            organization_id=other_org.id,
            email="other-owner@other.example.com",
            password_hash=hash_password("OtherStrongPass!2026"),
            role=Role.owner,
            is_active=True,
        )
        db.add(other_user)
        db.flush()
        other_target = Target(
            organization_id=other_org.id,
            name="Other Staging",
            base_url="https://other.example.com",
            hostname="other.example.com",
            owner_user_id=other_user.id,
        )
        db.add(other_target)
        db.flush()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        other_auth = Authorization(
            organization_id=other_org.id,
            target_id=other_target.id,
            granted_by=other_user.id,
            approved_by=other_user.id,
            evidence_reference="OTHER-1",
            scope_json={"base_url": other_target.base_url, "hostname": other_target.hostname},
            starts_at=now - timedelta(hours=1),
            expires_at=now + timedelta(days=3),
            approved=True,
            approved_at=now,
        )
        db.add(other_auth)
        db.commit()
        other_target_id = other_target.id
        other_auth_id = other_auth.id

    assert (
        client.get(
            f"/api/v1/targets/{other_target_id}", headers=_auth_headers(owner_token)
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/v1/authorizations/{other_auth_id}/revoke",
            headers=_auth_headers(owner_token),
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/v1/scans",
            headers=_auth_headers(owner_token),
            json={
                "target_id": other_target_id,
                "project_name": "Cross-tenant attempt",
                "profile": "safe_baseline",
                "confirm_authorized": True,
            },
        ).status_code
        == 404
    )
    assert client.get("/api/v1/targets", headers=_auth_headers(owner_token)).json() == []


def test_session_deletion_and_logout_all(client):
    owner = _bootstrap_owner(client)
    owner_token = owner["access_token"]
    pentester_login1 = _create_and_login_user(
        client, owner_token, email="pentester@pentagen.example.com", role="pentester"
    )
    pentester_login2 = client.post(
        "/api/v1/auth/login",
        json={"email": "pentester@pentagen.example.com", "password": "StrongPentesterPass!2026"},
    ).json()
    reviewer = _create_and_login_user(
        client, owner_token, email="reviewer@pentagen.example.com", role="reviewer"
    )

    # Non-owner cannot revoke another user's session.
    assert (
        client.delete(
            f"/api/v1/auth/sessions/{pentester_login1['session_id']}",
            headers=_auth_headers(reviewer["access_token"]),
        ).status_code
        == 403
    )

    # Owner can revoke another user's session in the same org.
    assert (
        client.delete(
            f"/api/v1/auth/sessions/{pentester_login1['session_id']}",
            headers=_auth_headers(owner_token),
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/api/v1/auth/me", headers=_auth_headers(pentester_login1["access_token"])
        ).status_code
        == 401
    )
    # Second session remains active until logout-all.
    assert (
        client.get(
            "/api/v1/auth/me", headers=_auth_headers(pentester_login2["access_token"])
        ).status_code
        == 200
    )
    logout_all = client.post(
        "/api/v1/auth/logout-all", headers=_auth_headers(pentester_login2["access_token"])
    )
    assert logout_all.status_code == 200
    assert logout_all.json()["revoked_count"] == 1
    assert (
        client.get(
            "/api/v1/auth/me", headers=_auth_headers(pentester_login2["access_token"])
        ).status_code
        == 401
    )


def test_expired_authorization_blocks_scan(client, db_session_factory, monkeypatch):
    _mock_public_dns(monkeypatch)
    owner = _bootstrap_owner(client)
    owner_token = owner["access_token"]
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()

    target_resp = client.post(
        "/api/v1/targets",
        headers=_auth_headers(owner_token),
        json={
            "name": "Expiring Target",
            "base_url": "https://example.com",
            "authorization_reference": "SOW-EXP",
            "authorization_expires_at": future_expiry,
        },
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # Fast-forward expiry into the past in DB.
    with db_session_factory() as db:
        auth = db.query(Authorization).filter(Authorization.target_id == target_id).one()
        auth.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        db.commit()

    scan = client.post(
        "/api/v1/scans",
        headers=_auth_headers(owner_token),
        json={
            "target_id": target_id,
            "project_name": "Expired Attempt",
            "profile": "safe_baseline",
            "confirm_authorized": True,
        },
    )
    assert scan.status_code == 403


def test_runtime_security_rejects_weak_prod_secret():
    prod_settings = Settings(
        app_env="production",
        jwt_secret="development-only-change-this-secret-32-bytes",
    )
    with pytest.raises(RuntimeError):
        prod_settings.validate_runtime_security()

    strong_settings = Settings(
        app_env="production",
        jwt_secret="9f4a8b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4",
    )
    strong_settings.validate_runtime_security()
