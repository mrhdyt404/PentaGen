import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt
from jwt import InvalidTokenError
from .config import settings

# Explicit Argon2id parameters aligned with OWASP Password Storage guidelines.
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

ALGORITHM = "HS256"


class TokenError(ValueError):
    """Raised when an access token is invalid, expired, or malformed."""


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored Argon2id hash."""
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_password_rehash(password_hash: str) -> bool:
    """Check whether an existing password hash should be upgraded to current Argon2id params."""
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def generate_refresh_token() -> str:
    """Generate a high-entropy opaque refresh token."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Compute a deterministic SHA-256 hex digest for storing opaque tokens safely."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(
    *,
    user_id: int,
    organization_id: int,
    role: str,
    session_id: str,
) -> tuple[str, int]:
    """Issue a signed JWT access token bound to a user, organization, role, and session ID."""
    now = datetime.now(timezone.utc)
    expires_delta = timedelta(minutes=settings.access_token_minutes)
    payload = {
        "sub": str(user_id),
        "org": organization_id,
        "role": role,
        "sid": session_id,
        "jti": str(uuid.uuid4()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + expires_delta,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)
    return token, int(expires_delta.total_seconds())


def decode_access_token(token: str) -> dict:
    """Validate signature, issuer, audience, timestamps, and required claims on a JWT."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "org", "role", "sid", "exp", "iat", "nbf", "iss", "aud"]},
        )
    except InvalidTokenError as exc:
        raise TokenError("Invalid or expired access token.") from exc

    try:
        int(payload["sub"])
        int(payload["org"])
    except (TypeError, ValueError) as exc:
        raise TokenError("Malformed subject or organization claim.") from exc

    if not isinstance(payload.get("sid"), str) or not payload["sid"]:
        raise TokenError("Missing session identifier claim.")
    return payload
