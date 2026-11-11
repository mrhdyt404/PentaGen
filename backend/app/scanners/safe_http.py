import hashlib
import httpx

SECURITY_HEADERS = {
    "strict-transport-security": "Enforce HTTPS using HSTS.",
    "content-security-policy": "Define a restrictive Content Security Policy.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "referrer-policy": "Set an explicit Referrer-Policy.",
    "permissions-policy": "Restrict browser features with Permissions-Policy.",
}

async def inspect_headers(url: str) -> list[dict]:
    # One GET, no crawling, no payloads, no form submission, no authentication bypass.
    timeout = httpx.Timeout(8.0, connect=4.0)
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False,
        headers={"User-Agent": "PentaGen-SafeAssessment/0.1"}
    ) as client:
        response = await client.get(url)
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    for header, remediation in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "title": f"Missing security header: {header}",
                "description": f"The HTTP response did not include {header}.",
                "severity": "low" if header in ("referrer-policy", "permissions-policy") else "medium",
                "confidence": "high",
                "remediation": remediation,
                "evidence": f"HTTP {response.status_code}; header absent",
            })
    if response.url.scheme != "https":
        findings.append({
            "title": "Target responded over HTTP",
            "description": "The assessed endpoint did not use HTTPS.",
            "severity": "high", "confidence": "high",
            "remediation": "Serve the application over HTTPS and redirect HTTP to HTTPS.",
            "evidence": f"Final response scheme: {response.url.scheme}",
        })
    return findings
