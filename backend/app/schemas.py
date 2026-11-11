from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl
from .models import Role, ScanStatus, Severity


class UserOut(BaseModel):
    """Public user representation omitting password hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    email: EmailStr
    full_name: str | None
    role: Role
    is_active: bool
    created_at: datetime


class BootstrapRegisterRequest(BaseModel):
    """Initial owner and organization registration payload (only valid before any user exists)."""

    organization_name: str = Field(min_length=2, max_length=160)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str | None = Field(default=None, max_length=160)


class LoginRequest(BaseModel):
    """Credentials payload for password login."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    """Opaque refresh token payload for token rotation."""

    refresh_token: str = Field(min_length=16, max_length=512)


class TokenResponse(BaseModel):
    """Issued access/refresh token pair and active session summary."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    session_id: str
    user: UserOut


class SessionOut(BaseModel):
    """Active or historical authentication session metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: int
    user_agent: str | None
    ip_address: str | None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None
    is_current: bool = False


class UserCreate(BaseModel):
    """Owner-provisioned user creation payload."""

    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str | None = Field(default=None, max_length=160)
    role: Role = Role.viewer


class UserUpdate(BaseModel):
    """Owner-managed role or activation state update."""

    full_name: str | None = Field(default=None, max_length=160)
    role: Role | None = None
    is_active: bool | None = None


class TargetCreate(BaseModel):
    """Register a target along with its initial authorization record."""

    name: str = Field(min_length=2, max_length=160)
    base_url: HttpUrl
    authorization_reference: str = Field(min_length=3, max_length=2048)
    authorization_starts_at: datetime | None = None
    authorization_expires_at: datetime
    allowed_profiles: list[str] = Field(default_factory=lambda: ["safe_baseline"], min_length=1)


class TargetOut(BaseModel):
    """Registered target asset metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    name: str
    base_url: str
    hostname: str
    owner_user_id: int
    created_at: datetime


class AuthorizationCreate(BaseModel):
    """Additional authorization window and scope record for an existing target."""

    evidence_reference: str = Field(min_length=3, max_length=2048)
    starts_at: datetime | None = None
    expires_at: datetime
    allowed_profiles: list[str] = Field(default_factory=lambda: ["safe_baseline"], min_length=1)


class AuthorizationOut(BaseModel):
    """Target authorization record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    target_id: int
    granted_by: int
    approved_by: int | None
    evidence_reference: str
    scope_json: dict
    starts_at: datetime
    expires_at: datetime
    approved: bool
    approved_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ScanCreate(BaseModel):
    """Authorized scan execution request."""

    target_id: int
    project_name: str = Field(min_length=2, max_length=180)
    profile: str = Field(default="safe_baseline", min_length=2, max_length=40)
    confirm_authorized: bool


class ScanOut(BaseModel):
    """Scan execution status record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    project_id: int
    target_id: int
    requested_by: int
    status: ScanStatus
    profile: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class FindingOut(BaseModel):
    """Normalized finding record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    title: str
    description: str
    severity: Severity
    confidence: str
    status: str
    cwe: str | None
    cvss_score: str | None
    remediation: str | None
    created_at: datetime


class AuditLogOut(BaseModel):
    """Read-only audit trail entry."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int | None
    actor_user_id: int | None
    event_type: str
    resource_type: str
    resource_id: str
    details: dict
    created_at: datetime
