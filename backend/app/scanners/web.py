from urllib.parse import urlparse
import httpx
from .evidence import NormalizedFinding, ScanModuleResult
from .recon import inspect_tls
from .safe_http import inspect_headers

_SAFE_SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/.env", "Potential .env file exposed over HTTP", "APP_ENV"),
    ("/.git/HEAD", "Exposed Git repository HEAD metadata", "ref: refs/"),
)


def _check_cookies(set_cookie_headers: list[str], *, base_url: str, is_https: bool) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for raw_cookie in set_cookie_headers:
        cookie_name = raw_cookie.split("=", 1)[0].strip() or "unknown"
        attrs = raw_cookie.lower()
        missing: list[str] = []
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "samesite=" not in attrs:
            missing.append("SameSite")
        if missing:
            findings.append(
                NormalizedFinding(
                    category="web",
                    title=f"Cookie '{cookie_name}' missing security attributes ({', '.join(missing)})",
                    description="Session or application cookie lacks recommended browser protection flags.",
                    severity="medium" if ("HttpOnly" in missing or "Secure" in missing) else "low",
                    confidence="high",
                    location=base_url,
                    cwe="CWE-614" if "Secure" in missing else "CWE-1004",
                    remediation="Set HttpOnly, Secure (over HTTPS), and SameSite=Lax or Strict on cookies.",
                    evidence_type="set_cookie_header",
                    evidence_content=f"Set-Cookie: {cookie_name}=[REDACTED]; attributes_checked={missing}",
                    artifact_metadata={"cookie_name": cookie_name, "missing_flags": missing},
                )
            )
    return findings


async def run_web_baseline(base_url: str, *, timeout_seconds: float = 8.0) -> ScanModuleResult:
    """Run non-destructive HTTP posture, TLS, cookie, CORS, and metadata exposure checks."""
    result = ScanModuleResult()

    header_items = await inspect_headers(base_url)
    for item in header_items:
        result.findings.append(
            NormalizedFinding(
                category="web",
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                confidence=item["confidence"],
                location=base_url,
                cwe="CWE-693",
                remediation=item["remediation"],
                evidence_type="http_header_check",
                evidence_content=item.get("evidence", ""),
            )
        )

    result.merge(await inspect_tls(base_url, timeout_seconds=min(timeout_seconds, 6.0)))

    parsed = urlparse(base_url)
    is_https = parsed.scheme == "https"
    timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 4.0))

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": "PentaGen-WebBaseline/0.2"},
    ) as client:
        probe_resp = await client.get(base_url, headers={"Origin": "https://untrusted.example"})
        set_cookies = probe_resp.headers.get_list("set-cookie")
        result.findings.extend(_check_cookies(set_cookies, base_url=base_url, is_https=is_https))

        acao = probe_resp.headers.get("access-control-allow-origin", "").strip()
        acac = probe_resp.headers.get("access-control-allow-credentials", "").strip().lower()
        result.notes["content_type"] = probe_resp.headers.get("content-type", "")

        if acao == "*" and acac == "true":
            result.findings.append(
                NormalizedFinding(
                    category="web",
                    title="Wildcard CORS combined with Access-Control-Allow-Credentials",
                    description="Server advertises wildcard origin alongside credentials support.",
                    severity="high",
                    confidence="high",
                    location=base_url,
                    cwe="CWE-942",
                    remediation="Restrict Access-Control-Allow-Origin to explicitly trusted origins.",
                    evidence_type="cors_headers",
                    evidence_content=f"ACAO={acao}; ACAC={acac}",
                )
            )
        elif acao == "https://untrusted.example":
            result.findings.append(
                NormalizedFinding(
                    category="web",
                    title="Permissive CORS origin reflection",
                    description="Endpoint reflected an untrusted Origin header in Access-Control-Allow-Origin.",
                    severity="high" if acac == "true" else "medium",
                    confidence="high",
                    location=base_url,
                    cwe="CWE-942",
                    remediation="Validate Origin against a strict allowlist instead of echoing arbitrary origins.",
                    evidence_type="cors_headers",
                    evidence_content=f"Sent Origin=https://untrusted.example; received ACAO={acao}; ACAC={acac}",
                )
            )

        for rel_path, title, marker in _SAFE_SENSITIVE_PATHS:
            check_url = f"{parsed.scheme}://{parsed.netloc}{rel_path}"
            try:
                path_resp = await client.get(check_url)
            except httpx.HTTPError:
                continue
            if path_resp.status_code == 200 and marker in path_resp.text[:512]:
                result.findings.append(
                    NormalizedFinding(
                        category="web",
                        title=title,
                        description=f"Sensitive configuration or VCS metadata appears readable at {rel_path}.",
                        severity="critical" if rel_path == "/.env" else "high",
                        confidence="high",
                        location=check_url,
                        cwe="CWE-200",
                        remediation=f"Block public web server access to {rel_path} and rotate any exposed secrets.",
                        evidence_type="http_exposure_check",
                        evidence_content=f"GET {rel_path} returned HTTP 200 matching expected signature",
                    )
                )

    return result

