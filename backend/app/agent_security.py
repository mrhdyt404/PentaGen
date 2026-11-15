import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any


def hash_token(raw_token: str) -> str:
    """Compute deterministic SHA-256 hex digest for token lookup and storage."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def generate_pairing_token() -> tuple[str, str]:
    """Generate a high-entropy one-time pairing token and its SHA-256 storage hash."""
    raw_token = f"pgp_{secrets.token_urlsafe(32)}"
    return raw_token, hash_token(raw_token)


def generate_node_id() -> str:
    """Generate a unique desktop agent node identifier."""
    return f"node_{uuid.uuid4().hex[:16]}"


def generate_shared_secret() -> str:
    """Generate a 256-bit cryptographically secure shared secret for HMAC authentication."""
    return secrets.token_hex(32)


def generate_envelope_id() -> str:
    """Generate a unique job envelope identifier."""
    return f"env_{uuid.uuid4().hex[:16]}"


def generate_nonce() -> str:
    """Generate a high-entropy 128-bit cryptographic nonce to prevent replay attacks."""
    return secrets.token_hex(16)


def canonical_json(data: Any) -> bytes:
    """Produce deterministic UTF-8 canonical JSON bytes with sorted keys and tight separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_hmac(secret: str, data: bytes) -> str:
    """Compute HMAC-SHA256 hex digest over arbitrary bytes using the agent shared secret."""
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


def verify_hmac(secret: str, data: bytes, expected_signature: str) -> bool:
    """Verify HMAC-SHA256 signature in constant time against timing side-channel attacks."""
    actual_signature = compute_hmac(secret, data)
    return hmac.compare_digest(actual_signature, expected_signature)


def build_envelope_signature_payload(
    envelope_id: str,
    agent_node_id: str | None,
    action: str,
    payload: dict,
    nonce: str,
) -> bytes:
    """Construct canonical byte representation for job envelope signature calculation."""
    envelope_dict = {
        "action": action,
        "agent_node_id": agent_node_id or "",
        "envelope_id": envelope_id,
        "nonce": nonce,
        "payload": payload,
    }
    return canonical_json(envelope_dict)


def sign_job_envelope(
    secret: str,
    envelope_id: str,
    agent_node_id: str | None,
    action: str,
    payload: dict,
    nonce: str,
) -> str:
    """Sign a job envelope using HMAC-SHA256."""
    data = build_envelope_signature_payload(envelope_id, agent_node_id, action, payload, nonce)
    return compute_hmac(secret, data)


def verify_job_envelope(
    secret: str,
    envelope_id: str,
    agent_node_id: str | None,
    action: str,
    payload: dict,
    nonce: str,
    signature: str,
) -> bool:
    """Verify job envelope HMAC-SHA256 integrity and authenticity."""
    data = build_envelope_signature_payload(envelope_id, agent_node_id, action, payload, nonce)
    return verify_hmac(secret, data, signature)


def build_request_signing_message(
    agent_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    """Construct canonical representation for agent HTTP request authentication."""
    body_digest = hashlib.sha256(body).hexdigest()
    canonical = f"{agent_id}:{method.upper()}:{path}:{timestamp}:{nonce}:{body_digest}"
    return canonical.encode("utf-8")


def sign_agent_request(
    secret: str,
    agent_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes = b"",
) -> str:
    """Compute HMAC-SHA256 signature for desktop agent API requests."""
    message = build_request_signing_message(agent_id, method, path, timestamp, nonce, body)
    return compute_hmac(secret, message)


def verify_agent_request(
    secret: str,
    agent_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    signature: str,
    max_age_seconds: int = 300,
) -> tuple[bool, str | None]:
    """Validate request timestamp freshness and HMAC-SHA256 signature."""
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return False, "Invalid or missing timestamp header."

    now = int(time.time())
    if abs(now - ts) > max_age_seconds:
        return False, f"Timestamp is outside allowed freshness window ({max_age_seconds}s tolerance)."

    expected_sig = sign_agent_request(secret, agent_id, method, path, timestamp, nonce, body)
    if not hmac.compare_digest(expected_sig, signature):
        return False, "Request HMAC signature verification failed."

    return True, None
