from datetime import datetime, timedelta, timezone
import hashlib
import json
import pytest
from backend.app.models import Evidence, Finding, FindingAnalysis, Scan, ScanStatus, Target


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _bootstrap_owner(client, email: str = "owner_s5@pentagen.example.com") -> dict:
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "PentaGen Enterprise Release",
            "email": email,
            "password": "StrongOwnerPassword!2026",
            "full_name": "Enterprise Lead",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


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


def test_pdf_report_generation(client, monkeypatch, db_session_factory):
    _mock_public_dns(monkeypatch)
    owner = _bootstrap_owner(client)
    token = owner["access_token"]
    org_id = owner["user"]["organization_id"]
    user_id = owner["user"]["id"]

    # Register target
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    target_resp = client.post(
        "/api/v1/targets",
        headers=_auth_headers(token),
        json={
            "name": "Audit Target",
            "base_url": "https://target.example.com",
            "authorization_reference": "SECOPS-REPORT-001",
            "authorization_expires_at": future_expiry,
            "allowed_profiles": ["safe_baseline"],
        },
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # Seed Scan, Findings, Evidence, and AI Analysis in DB
    with db_session_factory() as db:
        from backend.app.models import Project, Severity
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        proj = Project(organization_id=org_id, name="Audit Engagement", created_by=user_id)
        db.add(proj)
        db.flush()

        scan = Scan(
            organization_id=org_id,
            project_id=proj.id,
            target_id=target_id,
            requested_by=user_id,
            status=ScanStatus.completed,
            profile="safe_baseline",
            started_at=now - timedelta(minutes=5),
            finished_at=now,
        )
        db.add(scan)
        db.flush()

        f1 = Finding(
            organization_id=org_id,
            scan_id=scan.id,
            category="web",
            title="Missing Content-Security-Policy",
            description="The web server does not return a Content-Security-Policy header.",
            severity=Severity.medium,
            confidence="high",
            remediation="Implement strict CSP directives.",
            location="https://target.example.com",
            cwe="CWE-1021",
            cvss_score="5.3",
        )
        f2 = Finding(
            organization_id=org_id,
            scan_id=scan.id,
            category="network",
            title="TLS 1.0 Enabled",
            description="The server supports deprecated TLS 1.0 cipher suites.",
            severity=Severity.high,
            confidence="high",
            remediation="Disable TLS 1.0 and 1.1; enforce TLS 1.2 or 1.3.",
            location="target.example.com:443",
            cwe="CWE-326",
            cvss_score="7.5",
        )
        db.add_all([f1, f2])
        db.flush()

        ev1 = Evidence(
            organization_id=org_id,
            finding_id=f1.id,
            evidence_type="http_headers",
            content_redacted="HTTP/1.1 200 OK\nServer: nginx\nX-Frame-Options: SAMEORIGIN",
            content_hash=hashlib.sha256(b"ev1").hexdigest(),
        )
        db.add(ev1)
        db.commit()
        scan_id = scan.id

    # Request PDF report
    pdf_resp = client.get(
        f"/api/v1/scans/{scan_id}/report.pdf",
        headers=_auth_headers(token),
    )
    assert pdf_resp.status_code == 200, pdf_resp.text
    assert pdf_resp.headers["Content-Type"] == "application/pdf"
    assert f"pentagen-scan-{scan_id}-report.pdf" in pdf_resp.headers["Content-Disposition"]

    # Verify PDF magic bytes
    pdf_bytes = pdf_resp.content
    assert pdf_bytes.startswith(b"%PDF-"), "Generated report is not a valid PDF document"
    assert len(pdf_bytes) > 2000, "PDF byte length is unexpectedly small"


def test_dashboard_overview_metrics(client, monkeypatch):
    _mock_public_dns(monkeypatch)
    owner = _bootstrap_owner(client)
    token = owner["access_token"]

    overview_resp = client.get(
        "/api/v1/dashboard/overview",
        headers=_auth_headers(token),
    )
    assert overview_resp.status_code == 200, overview_resp.text
    data = overview_resp.json()

    assert "total_targets" in data
    assert "total_scans" in data
    assert "active_scans" in data
    assert "pending_approvals" in data
    assert "paired_agents" in data
    assert "total_findings" in data
    assert "posture_score" in data
    assert "security_grade" in data
    assert "severity_distribution" in data
    assert data["security_grade"] in ["A", "B", "C", "D", "F"]


def test_audit_logs_and_integrity_export(client):
    owner = _bootstrap_owner(client)
    token = owner["access_token"]

    # Retrieve audit logs list
    list_resp = client.get(
        "/api/v1/audit-logs",
        headers=_auth_headers(token),
    )
    assert list_resp.status_code == 200
    logs = list_resp.json()
    assert len(logs) >= 1  # Bootstrap audit log

    # Export JSONL format with SHA-256 digest validation
    jsonl_resp = client.get(
        "/api/v1/audit-logs/export?format=jsonl",
        headers=_auth_headers(token),
    )
    assert jsonl_resp.status_code == 200
    assert "X-PentaGen-Audit-Digest" in jsonl_resp.headers
    expected_digest = hashlib.sha256(jsonl_resp.content).hexdigest()
    assert jsonl_resp.headers["X-PentaGen-Audit-Digest"] == expected_digest

    # Verify JSONL lines validity
    raw_lines = jsonl_resp.content.decode("utf-8").strip().split("\n")
    for line in raw_lines:
        if line:
            parsed = json.loads(line)
            assert "event_type" in parsed
            assert "organization_id" in parsed

    # Export CSV format with digest validation
    csv_resp = client.get(
        "/api/v1/audit-logs/export?format=csv",
        headers=_auth_headers(token),
    )
    assert csv_resp.status_code == 200
    assert "X-PentaGen-Audit-Digest" in csv_resp.headers
    assert hashlib.sha256(csv_resp.content).hexdigest() == csv_resp.headers["X-PentaGen-Audit-Digest"]
    assert b"event_type" in csv_resp.content


def test_deployment_hardening_security_headers(client):
    resp = client.get("/health")
    assert resp.status_code == 200

    # Validate essential OWASP defense-in-depth headers
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers.get("Permissions-Policy", "")
    assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")


def test_rate_limiting_sensitive_endpoints(client):
    from backend.app.security_headers import RATE_LIMIT_RULES, _RATE_LIMIT_STORE
    _RATE_LIMIT_STORE.clear()

    max_reqs, _ = RATE_LIMIT_RULES["/api/v1/auth/login"]

    # Send requests up to the threshold
    for _ in range(max_reqs):
        client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@pentagen.example.com", "password": "DummyPassword123!"},
        )

    # Next request must be throttled with HTTP 429 Too Many Requests
    blocked_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@pentagen.example.com", "password": "DummyPassword123!"},
    )
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert "Too many requests" in blocked_resp.text
