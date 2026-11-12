from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import socket
import zipfile
import httpx
import pytest
from backend.app.scanners.evidence import ScanModuleResult, redact_sensitive_text
from backend.app.scanners.execution_policy import ExecutionPolicyError, run_allowlisted_tool
from backend.app.scanners.recon import run_passive_recon
from backend.app.scanners.web import run_web_baseline


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _bootstrap_owner(client) -> dict:
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "PentaGen Scanner Org",
            "email": "owner@pentagen-s2.example.com",
            "password": "StrongOwnerPassword!2026",
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
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolved, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def test_evidence_redaction_strips_secrets():
    sample = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secretpayload.sig\n"
        "Set-Cookie: sessionid=supersecretcookie123; Path=/\n"
        "aws_key=AKIAIOSFODNN7EXAMPLE\n"
        "db=postgresql+psycopg://pentagen:TopSecretPass@db:5432/pentagen\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    )
    redacted = redact_sensitive_text(sample)
    assert "secretpayload" not in redacted
    assert "supersecretcookie123" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "TopSecretPass" not in redacted
    assert "MIIEowIBAAKCAQEA" not in redacted
    assert "[REDACTED]" in redacted


def test_execution_policy_blocks_unlisted_tool_and_escape(tmp_path: Path):
    root = tmp_path / "artifacts"
    root.mkdir(exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)

    with pytest.raises(ExecutionPolicyError):
        run_allowlisted_tool("bash", ["-c", "id"], work_dir=root, allowed_root=root)

    with pytest.raises(ExecutionPolicyError):
        run_allowlisted_tool("semgrep", ["--version"], work_dir=outside, allowed_root=root)


@pytest.mark.anyio
async def test_passive_recon_and_web_baseline(monkeypatch):
    _mock_public_dns(monkeypatch)

    monkeypatch.setattr(
        "backend.app.scanners.recon._inspect_tls_sync",
        lambda host, port, timeout: {
            "protocol": "TLSv1.1",
            "cipher": ("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.1", 128),
            "cert": {
                "subject": ((("commonName", host),),),
                "notAfter": "Jan 01 00:00:00 2020 GMT",
            },
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin")
        if request.url.path == "/.env":
            return httpx.Response(200, text="APP_ENV=production\nJWT_SECRET=supersecret")
        if request.url.path == "/.git/HEAD":
            return httpx.Response(404, text="Not Found")
        return httpx.Response(
            200,
            headers={
                "Server": "nginx/1.24.0",
                "X-Powered-By": "Express/4.18",
                "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
                "Access-Control-Allow-Credentials": "true",
                "Set-Cookie": "sid=mysecretcookieval; Path=/",
            },
            text="<html><head><title>Staging App</title><meta name='generator' content='Next.js 14'></head></html>",
        )

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda *args, **kwargs: real_async_client(*args, transport=transport, **kwargs),
    )

    recon_res = await run_passive_recon("https://app.example.com")
    assert any(a.asset_type == "dns_record" for a in recon_res.assets)
    assert any(a.asset_type == "tls_endpoint" for a in recon_res.assets)
    assert any(a.asset_type == "web_technology" for a in recon_res.assets)
    assert any("Deprecated TLS protocol" in f.title for f in recon_res.findings)
    assert any("expired" in f.title.lower() for f in recon_res.findings)

    web_res = await run_web_baseline("https://app.example.com")
    titles = [f.title for f in web_res.findings]
    assert any("missing security attributes" in t.lower() for t in titles)
    assert any("cors origin reflection" in t.lower() for t in titles)
    assert any(".env" in t.lower() for t in titles)
    cookie_findings = [f for f in web_res.findings if f.evidence_type == "set_cookie_header"]
    assert cookie_findings and "mysecretcookieval" not in cookie_findings[0].evidence_content


def test_source_code_zip_slip_blocked_and_sast_scan(client):
    owner = _bootstrap_owner(client)
    token = owner["access_token"]

    # Reject ZIP containing path traversal.
    bad_buf = io.BytesIO()
    with zipfile.ZipFile(bad_buf, "w") as zf:
        zf.writestr("../../evil.py", "print('boom')")
    bad_resp = client.post(
        "/api/v1/artifacts/upload",
        headers=_auth_headers(token),
        data={"name": "Bad Zip"},
        files={"file": ("bad.zip", bad_buf.getvalue(), "application/zip")},
    )
    assert bad_resp.status_code == 400

    # Upload clean inline bundle with vulnerable patterns + secrets + dependencies.
    inline_resp = client.post(
        "/api/v1/artifacts/inline",
        headers=_auth_headers(token),
        json={
            "name": "Sample Service",
            "files": {
                "app/main.py": (
                    "import subprocess, hashlib\n"
                    "JWT_SECRET = 'hardcoded-super-secret-value-1234'\n"
                    "def run(cmd):\n"
                    "    return subprocess.run(cmd, shell=True)\n"
                    "def query(cur, uid):\n"
                    "    cur.execute(f'SELECT * FROM users WHERE id={uid}')\n"
                    "digest = hashlib.md5(b'abc').hexdigest()\n"
                ),
                "frontend/widget.tsx": "export const W = () => <div dangerouslySetInnerHTML={{__html: x}} />;",
                "requirements.txt": "pyyaml==5.3.1\nrequests\n",
                "package.json": '{"dependencies": {"lodash": "4.17.19"}}',
            },
        },
    )
    assert inline_resp.status_code == 201, inline_resp.text
    artifact_id = inline_resp.json()["id"]

    scan_resp = client.post(
        "/api/v1/scans",
        headers=_auth_headers(token),
        json={
            "source_artifact_id": artifact_id,
            "project_name": "SAST Audit",
            "profile": "code_sast",
            "confirm_authorized": True,
        },
    )
    assert scan_resp.status_code == 200, scan_resp.text
    body = scan_resp.json()
    assert body["status"] == "completed"
    assert body["finding_count"] >= 6
    assert body["asset_count"] == 3

    findings = client.get(f"/api/v1/findings?scan_id={body['scan_id']}", headers=_auth_headers(token)).json()
    titles = [f["title"] for f in findings]
    assert any("Shell command execution sink" in t for t in titles)
    assert any("SQL injection" in t for t in titles)
    assert any("Hardcoded secret" in t for t in titles)
    assert any("pyyaml" in t.lower() for t in titles)

    # Confirm secret evidence is redacted in DB response.
    secret_finding = next(f for f in findings if "Hardcoded secret" in f["title"])
    ev = client.get(f"/api/v1/findings/{secret_finding['id']}/evidence", headers=_auth_headers(token)).json()
    assert len(ev) == 1
    assert "hardcoded-super-secret-value-1234" not in ev[0]["content_redacted"]
    assert "[REDACTED]" in ev[0]["content_redacted"]

    deps = client.get(
        f"/api/v1/assets?scan_id={body['scan_id']}&asset_type=dependency",
        headers=_auth_headers(token),
    ).json()
    assert len(deps) == 3


def test_openapi_import_api_audit_and_profile_scope(client, monkeypatch):
    _mock_public_dns(monkeypatch)
    owner = _bootstrap_owner(client)
    token = owner["access_token"]

    spec_yaml = """
openapi: 3.0.3
info:
  title: Sample API
  version: "1.0"
servers:
  - url: http://api.example.com
components:
  securitySchemes:
    QueryApiKey:
      type: apiKey
      in: query
      name: api_key
paths:
  /health:
    get:
      responses:
        "200":
          description: ok
  /admin/users:
    delete:
      operationId: deleteUser
      responses:
        "204":
          description: deleted
"""
    import_resp = client.post(
        "/api/v1/artifacts/openapi",
        headers=_auth_headers(token),
        json={"name": "Sample OpenAPI", "spec_text": spec_yaml},
    )
    assert import_resp.status_code == 201, import_resp.text
    spec_id = import_resp.json()["id"]

    api_scan = client.post(
        "/api/v1/scans",
        headers=_auth_headers(token),
        json={
            "source_artifact_id": spec_id,
            "project_name": "API Spec Review",
            "profile": "api_audit",
            "confirm_authorized": True,
        },
    )
    assert api_scan.status_code == 200, api_scan.text
    assert api_scan.json()["finding_count"] >= 3
    assert api_scan.json()["asset_count"] == 2

    # Register target limited strictly to safe_baseline and verify web_baseline is blocked.
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    target = client.post(
        "/api/v1/targets",
        headers=_auth_headers(token),
        json={
            "name": "Scoped Target",
            "base_url": "https://example.com",
            "authorization_reference": "SCOPE-S2",
            "authorization_expires_at": future_expiry,
            "allowed_profiles": ["safe_baseline"],
        },
    )
    assert target.status_code == 201
    target_id = target.json()["id"]

    blocked = client.post(
        "/api/v1/scans",
        headers=_auth_headers(token),
        json={
            "target_id": target_id,
            "project_name": "Out-of-scope profile",
            "profile": "web_baseline",
            "confirm_authorized": True,
        },
    )
    assert blocked.status_code == 403
