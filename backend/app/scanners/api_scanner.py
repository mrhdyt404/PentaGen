import json
from urllib.parse import urlparse
import httpx
import yaml
from .evidence import NormalizedAsset, NormalizedFinding, ScanModuleResult

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_STATE_CHANGING = frozenset({"post", "put", "patch", "delete"})
_SENSITIVE_PATH_HINTS = ("admin", "user", "token", "key", "secret", "scan", "audit", "role")


class OpenAPIParseError(ValueError):
    """Raised when an imported OpenAPI/Swagger specification is invalid."""


def parse_openapi_document(raw_text: str) -> dict:
    """Parse OpenAPI/Swagger JSON or YAML safely and validate basic structure."""
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        try:
            parsed = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            raise OpenAPIParseError("Specification is neither valid JSON nor valid YAML.") from exc

    if not isinstance(parsed, dict) or ("openapi" not in parsed and "swagger" not in parsed):
        raise OpenAPIParseError("Document must be an OpenAPI 3.x or Swagger 2.0 object.")
    if not isinstance(parsed.get("paths", {}), dict):
        raise OpenAPIParseError("OpenAPI 'paths' section must be an object.")
    return parsed


def scan_openapi_spec(spec: dict, *, spec_name: str = "openapi") -> ScanModuleResult:
    """Inventory API endpoints and identify security configuration weaknesses in OpenAPI specs."""
    result = ScanModuleResult()
    global_security = spec.get("security") or []
    components = spec.get("components") or {}
    security_schemes = components.get("securitySchemes") or spec.get("securityDefinitions") or {}

    for server in spec.get("servers") or []:
        url = (server.get("url") or "").strip()
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            result.findings.append(
                NormalizedFinding(
                    category="api",
                    title="API server URL configured over unencrypted HTTP",
                    description=f"OpenAPI server entry '{url}' uses plain HTTP instead of HTTPS.",
                    severity="medium",
                    confidence="high",
                    location=f"{spec_name}:{url}",
                    cwe="CWE-319",
                    remediation="Serve all API endpoints exclusively over HTTPS.",
                    evidence_type="openapi_server",
                    evidence_content=f"servers[].url = {url}",
                )
            )

    for scheme_name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue
        scheme_type = (scheme.get("type") or "").lower()
        location_in = (scheme.get("in") or "").lower()
        if scheme_type == "apikey" and location_in == "query":
            result.findings.append(
                NormalizedFinding(
                    category="api",
                    title=f"API key security scheme '{scheme_name}' transmitted in query string",
                    description="Passing API credentials in query parameters exposes them in access logs and referrers.",
                    severity="medium",
                    confidence="high",
                    location=f"{spec_name}:securitySchemes.{scheme_name}",
                    cwe="CWE-598",
                    remediation="Transmit API keys or bearer tokens in HTTP Authorization headers instead of URL queries.",
                    evidence_type="openapi_security_scheme",
                    evidence_content=f"securityScheme={scheme_name}, type=apiKey, in=query",
                )
            )
        elif scheme_type == "http" and (scheme.get("scheme") or "").lower() == "basic":
            result.findings.append(
                NormalizedFinding(
                    category="api",
                    title=f"HTTP Basic authentication configured in scheme '{scheme_name}'",
                    description="Static Basic credentials lack rotation/revocation controls compared to short-lived tokens.",
                    severity="low",
                    confidence="medium",
                    location=f"{spec_name}:securitySchemes.{scheme_name}",
                    cwe="CWE-287",
                    remediation="Prefer short-lived OAuth2/OIDC or JWT bearer tokens with revocation support.",
                    evidence_type="openapi_security_scheme",
                    evidence_content=f"securityScheme={scheme_name}, type=http, scheme=basic",
                )
            )

    paths = spec.get("paths") or {}
    endpoint_count = 0
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method_lower = method.lower()
            if method_lower not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            endpoint_count += 1
            op_security = operation.get("security")
            effective_security = op_security if op_security is not None else global_security
            has_auth = bool(effective_security)

            result.assets.append(
                NormalizedAsset(
                    asset_type="api_endpoint",
                    name=f"{method_lower.upper()} {path}",
                    identifier=f"{method_lower.upper()} {path}",
                    metadata_json={
                        "method": method_lower.upper(),
                        "path": path,
                        "operation_id": operation.get("operationId"),
                        "authenticated": has_auth,
                    },
                )
            )

            lower_path = path.lower()
            is_health = lower_path in {"/health", "/healthz", "/ready", "/metrics"}
            is_auth_entry = any(k in lower_path for k in ("/login", "/register", "/auth/token"))
            is_sensitive = any(hint in lower_path for hint in _SENSITIVE_PATH_HINTS)

            if not has_auth and not is_health and not is_auth_entry and (
                method_lower in _STATE_CHANGING or is_sensitive
            ):
                result.findings.append(
                    NormalizedFinding(
                        category="api",
                        title=f"Unauthenticated API endpoint defined: {method_lower.upper()} {path}",
                        description="Operation has no per-endpoint or global security requirement in the OpenAPI schema.",
                        severity="high" if is_sensitive or method_lower in _STATE_CHANGING else "medium",
                        confidence="medium",
                        location=f"{method_lower.upper()} {path}",
                        cwe="CWE-306",
                        remediation="Attach an explicit authentication/authorization security scheme to this endpoint.",
                        evidence_type="openapi_operation",
                        evidence_content=f"{method_lower.upper()} {path} has empty security requirement",
                        artifact_metadata={"method": method_lower.upper(), "path": path},
                    )
                )

    result.notes["openapi_endpoints"] = endpoint_count
    return result


async def scan_live_api_posture(base_url: str, *, timeout_seconds: float = 8.0) -> ScanModuleResult:
    """Perform passive discovery of publicly exposed OpenAPI/Swagger endpoints on a target."""
    result = ScanModuleResult()
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 4.0))

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": "PentaGen-APIAudit/0.2"},
    ) as client:
        for candidate in ("/openapi.json", "/swagger.json", "/v3/api-docs"):
            url = f"{origin}{candidate}"
            try:
                resp = await client.get(url)
            except httpx.HTTPError:
                continue
            if resp.status_code == 200 and ("openapi" in resp.text[:512] or "swagger" in resp.text[:512]):
                result.assets.append(
                    NormalizedAsset(
                        asset_type="api_schema",
                        name=candidate,
                        identifier=url,
                        metadata_json={"status_code": resp.status_code},
                    )
                )
                result.findings.append(
                    NormalizedFinding(
                        category="api",
                        title=f"Public API schema exposed at {candidate}",
                        description="OpenAPI/Swagger documentation is accessible without authentication.",
                        severity="info",
                        confidence="high",
                        location=url,
                        cwe="CWE-200",
                        remediation="Restrict API schema documentation endpoints in production if unintended.",
                        evidence_type="http_api_schema",
                        evidence_content=f"GET {candidate} returned HTTP 200",
                    )
                )
                try:
                    spec = parse_openapi_document(resp.text)
                    result.merge(scan_openapi_spec(spec, spec_name=url))
                except OpenAPIParseError:
                    pass
                break
    return result

