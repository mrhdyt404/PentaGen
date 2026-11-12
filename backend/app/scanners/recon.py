import asyncio
from datetime import datetime, timezone
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlparse
import httpx
from .evidence import NormalizedAsset, NormalizedFinding, ScanModuleResult

_TECH_HEADER_KEYS = ("server", "x-powered-by", "x-aspnet-version", "via", "x-generator")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)


def _inspect_tls_sync(hostname: str, port: int, timeout_seconds: float) -> dict:
    """Perform a non-destructive TLS handshake to inspect certificate and protocol metadata."""
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout_seconds) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()
            cipher = tls_sock.cipher()
    return {"cert": cert or {}, "protocol": protocol, "cipher": cipher}


async def _collect_dns_assets(hostname: str) -> tuple[list[NormalizedAsset], list[str]]:
    def _resolve() -> list[str]:
        infos = socket.getaddrinfo(hostname, None)
        return sorted({item[4][0] for item in infos})

    addresses = await asyncio.to_thread(_resolve)
    assets: list[NormalizedAsset] = []
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        assets.append(
            NormalizedAsset(
                asset_type="dns_record",
                name=f"DNS {'AAAA' if ip.version == 6 else 'A'}",
                identifier=f"{hostname} -> {addr}",
                metadata_json={"hostname": hostname, "ip": addr, "ip_version": ip.version},
            )
        )
    return assets, addresses


async def inspect_tls(base_url: str, *, timeout_seconds: float = 6.0) -> ScanModuleResult:
    """Assess TLS protocol version and certificate expiry on HTTPS targets."""
    result = ScanModuleResult()
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        return result

    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        info = await asyncio.to_thread(_inspect_tls_sync, hostname, port, timeout_seconds)
    except ssl.SSLCertVerificationError as exc:
        result.findings.append(
            NormalizedFinding(
                category="tls",
                title="TLS certificate verification failed",
                description=f"The TLS certificate for {hostname}:{port} failed standard trust/hostname verification.",
                severity="high",
                confidence="high",
                location=f"{hostname}:{port}",
                cwe="CWE-295",
                remediation="Install a valid, CA-trusted certificate matching the target hostname.",
                evidence_type="tls_handshake",
                evidence_content=f"TLS verification error on {hostname}:{port}: {exc.verify_message or exc}",
            )
        )
        return result
    except (OSError, ssl.SSLError) as exc:
        result.notes["tls_error"] = type(exc).__name__
        return result

    protocol = info.get("protocol") or "unknown"
    cipher = info.get("cipher")
    cert = info.get("cert") or {}
    not_after_raw = cert.get("notAfter")
    days_remaining: int | None = None
    if not_after_raw:
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after_raw), tz=timezone.utc)
        days_remaining = (expires_at - datetime.now(timezone.utc)).days

    subject_cn = ""
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                subject_cn = value

    result.assets.append(
        NormalizedAsset(
            asset_type="tls_endpoint",
            name=f"TLS {hostname}:{port}",
            identifier=f"{hostname}:{port}",
            metadata_json={
                "protocol": protocol,
                "cipher": cipher[0] if cipher else None,
                "subject_cn": subject_cn,
                "not_after": not_after_raw,
                "days_remaining": days_remaining,
            },
        )
    )

    if protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
        result.findings.append(
            NormalizedFinding(
                category="tls",
                title=f"Deprecated TLS protocol negotiated: {protocol}",
                description=f"The target accepted deprecated protocol {protocol}.",
                severity="high",
                confidence="high",
                location=f"{hostname}:{port}",
                cwe="CWE-326",
                remediation="Disable TLSv1.0/TLSv1.1 and enforce TLS 1.2 or TLS 1.3.",
                evidence_type="tls_handshake",
                evidence_content=f"Negotiated protocol={protocol} on {hostname}:{port}",
            )
        )

    if days_remaining is not None and days_remaining < 0:
        result.findings.append(
            NormalizedFinding(
                category="tls",
                title="TLS certificate is expired",
                description=f"Certificate expired {abs(days_remaining)} day(s) ago.",
                severity="critical",
                confidence="high",
                location=f"{hostname}:{port}",
                cwe="CWE-298",
                remediation="Renew and deploy a valid TLS certificate immediately.",
                evidence_type="tls_certificate",
                evidence_content=f"notAfter={not_after_raw}",
            )
        )
    elif days_remaining is not None and days_remaining <= 14:
        result.findings.append(
            NormalizedFinding(
                category="tls",
                title="TLS certificate expiring soon",
                description=f"Certificate expires in {days_remaining} day(s).",
                severity="medium",
                confidence="high",
                location=f"{hostname}:{port}",
                cwe="CWE-298",
                remediation="Automate certificate renewal before expiration.",
                evidence_type="tls_certificate",
                evidence_content=f"notAfter={not_after_raw}; days_remaining={days_remaining}",
            )
        )

    return result


async def run_passive_recon(base_url: str, *, timeout_seconds: float = 8.0) -> ScanModuleResult:
    """Collect DNS inventory, TLS metadata, HTTP technology banners, and standard metadata files."""
    result = ScanModuleResult()
    parsed = urlparse(base_url)
    hostname = (parsed.hostname or "").lower()

    if hostname:
        try:
            dns_assets, addresses = await _collect_dns_assets(hostname)
            result.assets.extend(dns_assets)
            result.notes["resolved_ips"] = addresses
        except socket.gaierror:
            result.notes["dns_error"] = "gaierror"

    result.merge(await inspect_tls(base_url, timeout_seconds=min(timeout_seconds, 6.0)))

    timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 4.0))
    headers_map: dict[str, str] = {}
    body_sample = ""
    status_code: int | None = None
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": "PentaGen-PassiveRecon/0.2"},
    ) as client:
        resp = await client.get(base_url)
        status_code = resp.status_code
        headers_map = {k.lower(): v for k, v in resp.headers.items()}
        body_sample = resp.text[:4096]

        for meta_path in ("/robots.txt", "/.well-known/security.txt"):
            try:
                meta_url = f"{parsed.scheme}://{parsed.netloc}{meta_path}"
                meta_resp = await client.get(meta_url)
                if meta_resp.status_code == 200:
                    result.assets.append(
                        NormalizedAsset(
                            asset_type="well_known_file",
                            name=meta_path,
                            identifier=meta_url,
                            metadata_json={"status_code": meta_resp.status_code},
                        )
                    )
            except httpx.HTTPError:
                pass

    result.notes["http_status"] = status_code
    result.notes["content_type"] = headers_map.get("content-type", "")

    for key in _TECH_HEADER_KEYS:
        val = headers_map.get(key)
        if not val:
            continue
        result.assets.append(
            NormalizedAsset(
                asset_type="web_technology",
                name=f"HTTP header {key}",
                identifier=f"{key}: {val[:120]}",
                metadata_json={"header": key, "value": val[:120]},
            )
        )
        if key in {"server", "x-powered-by", "x-aspnet-version"} and any(ch.isdigit() for ch in val):
            result.findings.append(
                NormalizedFinding(
                    category="recon",
                    title=f"Technology version disclosed via {key} header",
                    description=f"The HTTP response reveals specific software/version details in '{key}'.",
                    severity="info",
                    confidence="high",
                    location=base_url,
                    cwe="CWE-200",
                    remediation=f"Remove or generalize the '{key}' response header.",
                    evidence_type="http_header",
                    evidence_content=f"{key}: {val}",
                )
            )

    title_match = _TITLE_RE.search(body_sample)
    if title_match:
        result.notes["page_title"] = " ".join(title_match.group(1).split())[:140]

    gen_match = _GENERATOR_RE.search(body_sample)
    if gen_match:
        generator = gen_match.group(1).strip()[:120]
        result.assets.append(
            NormalizedAsset(
                asset_type="web_technology",
                name="HTML meta generator",
                identifier=generator,
                metadata_json={"source": "meta_generator"},
            )
        )

    return result

