import ipaddress
import socket
from urllib.parse import urlparse

class ScopeError(ValueError):
    pass

def validate_public_http_target(url: str) -> tuple[str, str]:
    """Reject local/private/reserved destinations. DNS is checked at scan time too.

    Production must additionally enforce network egress restrictions to mitigate DNS
    rebinding and TOCTOU. Never use this helper as the only SSRF defense.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScopeError("Only valid HTTP/HTTPS targets are accepted.")
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost"} or host.endswith(".localhost") or host.endswith(".local"):
        raise ScopeError("Local hostnames are not allowed.")
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        addresses = {str(literal_ip)}
    else:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
        except socket.gaierror as exc:
            raise ScopeError("Target hostname could not be resolved.") from exc
    if not addresses:
        raise ScopeError("Target has no resolved addresses.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ScopeError("Private, loopback, link-local, or reserved IPs are not allowed in hosted mode.")
    return host, parsed.scheme
