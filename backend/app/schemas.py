from datetime import datetime
from typing import Literal
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


class InlineSourceUploadRequest(BaseModel):
    """Structured inline source files submission for static code/dependency analysis."""

    name: str = Field(min_length=2, max_length=160)
    project_id: int | None = None
    files: dict[str, str] = Field(min_length=1)


class OpenAPIImportRequest(BaseModel):
    """OpenAPI 3.x / Swagger 2.0 specification import payload."""

    name: str = Field(min_length=2, max_length=160)
    project_id: int | None = None
    spec_text: str = Field(min_length=10, max_length=2_000_000)


class SourceArtifactOut(BaseModel):
    """Uploaded source bundle or OpenAPI specification metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    project_id: int | None
    uploaded_by: int
    name: str
    source_type: str
    sha256_digest: str
    file_count: int
    total_bytes: int
    created_at: datetime


class AssetOut(BaseModel):
    """Discovered inventory record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    target_id: int | None
    scan_id: int | None
    asset_type: str
    name: str
    identifier: str
    metadata_json: dict
    created_at: datetime


class EvidenceOut(BaseModel):
    """Redacted supporting proof with SHA-256 integrity hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    evidence_type: str
    content_redacted: str
    content_hash: str
    artifact_metadata: dict
    created_at: datetime


class ScanCreate(BaseModel):
    """Authorized scan execution request."""

    target_id: int | None = None
    source_artifact_id: int | None = None
    project_name: str = Field(min_length=2, max_length=180)
    profile: str = Field(default="safe_baseline", min_length=2, max_length=40)
    confirm_authorized: bool


class ScanOut(BaseModel):
    """Scan execution status record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    project_id: int
    target_id: int | None
    source_artifact_id: int | None
    requested_by: int
    status: ScanStatus
    profile: str
    scanner_summary: dict
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class FindingOut(BaseModel):
    """Normalized finding record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    category: str
    title: str
    description: str
    severity: Severity
    confidence: str
    status: str
    cwe: str | None
    cvss_score: str | None
    location: str | None
    fingerprint: str | None
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


class LLMProviderCreate(BaseModel):
    """Register a Cloud OpenAI-compatible or local Ollama provider for an organization."""

    name: str = Field(min_length=2, max_length=120)
    provider_type: Literal["cloud_openai", "ollama"]
    base_url: HttpUrl
    model_name: str = Field(min_length=1, max_length=120)
    api_key_env_var: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{1,79}$")
    is_default: bool = False


class LLMProviderOut(BaseModel):
    """Public LLM provider configuration without secret values."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    name: str
    provider_type: str
    base_url: str
    model_name: str
    api_key_env_var: str | None
    is_default: bool
    is_active: bool
    created_at: datetime


class AIPlanRequest(BaseModel):
    """Request for AI assessment planning."""

    target_id: int | None = None
    source_artifact_id: int | None = None
    goal: str = Field(min_length=3, max_length=500)
    provider_id: int | None = None


class AIAnalyzeRequest(BaseModel):
    """Request for AI triage, false-positive detection, and risk scoring on a scan."""

    provider_id: int | None = None


class AgentTaskOut(BaseModel):
    """Individual orchestrated agent task log."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_name: str
    action_name: str
    status: str
    input_snapshot: dict
    output_json: dict
    error_message: str | None
    created_at: datetime


class AgentRunOut(BaseModel):
    """Multi-agent orchestration run summary."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    scan_id: int | None
    provider_id: int | None
    mode: str
    status: str
    plan_json: dict
    summary_json: dict
    started_at: datetime
    finished_at: datetime | None


class AgentRunDetailOut(AgentRunOut):
    """Orchestration run along with its ordered task execution trail."""

    tasks: list[AgentTaskOut] = Field(default_factory=list)


class FindingAnalysisOut(BaseModel):
    """Advisory AI security analyst & false-positive triage record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    agent_run_id: int
    verdict: str
    is_likely_false_positive: bool
    fp_confidence: str
    risk_score: str
    priority_rank: int
    rationale: str
    remediation_plan: str
    evidence_refs: list
    created_at: datetime


class AIAnalyzeResponse(BaseModel):
    """Combined AI analysis response for a scan."""

    run: AgentRunOut
    analyses: list[FindingAnalysisOut]


class PairingTokenCreate(BaseModel):
    """Request to generate a one-time pairing token for desktop agents."""

    name_hint: str | None = Field(default=None, max_length=120)
    expires_in_minutes: int = Field(default=15, ge=1, le=1440)


class PairingTokenOut(BaseModel):
    """One-time token details returned to owner upon generation."""

    id: int
    token: str
    name_hint: str | None
    expires_at: datetime
    created_at: datetime


class PairDeviceRequest(BaseModel):
    """Desktop agent device registration payload."""

    token: str = Field(min_length=16, max_length=128)
    device_name: str = Field(min_length=2, max_length=160)
    device_fingerprint: str = Field(min_length=8, max_length=128)
    platform_info: dict = Field(default_factory=dict)


class PairDeviceResponse(BaseModel):
    """Credentials returned to desktop agent upon successful pairing."""

    agent_id: str
    shared_secret: str
    organization_id: int
    organization_name: str


class AgentNodeOut(BaseModel):
    """Public paired desktop agent record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: int
    name: str
    device_fingerprint: str
    status: str
    platform_info: dict
    last_seen_at: datetime
    created_at: datetime
    revoked_at: datetime | None


class AgentJobCreate(BaseModel):
    """Request to schedule an authorized assessment job for a desktop agent."""

    target_id: int | None = None
    source_artifact_id: int | None = None
    project_name: str = Field(default="Desktop Assessment", min_length=2, max_length=180)
    action: str = Field(default="safe_baseline", min_length=2, max_length=60)
    agent_node_id: str | None = None
    requires_approval: bool = False
    risk_level: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    params: dict = Field(default_factory=dict)
    confirm_authorized: bool = True


class AgentJobEnvelopeOut(BaseModel):
    """Signed job envelope payload sent to desktop agents."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: int
    agent_node_id: str | None
    scan_id: int
    approval_id: int | None
    action: str
    payload_json: dict
    nonce: str
    signature: str
    status: str
    created_at: datetime


class AgentJobResultSubmission(BaseModel):
    """Execution results and evidence submitted by desktop agent."""

    status: Literal["completed", "failed"]
    findings: list[dict] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    assets: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    error_message: str | None = None


class ApprovalOut(BaseModel):
    """Gated security action approval record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    scan_id: int
    target_id: int | None
    envelope_id: str | None
    requested_action: str
    risk_level: str
    status: str
    decided_by: int | None
    reason: str | None
    risk_assessment_json: dict
    created_at: datetime
    decided_at: datetime | None


class ApprovalDecisionRequest(BaseModel):
    """Reviewer or owner decision on a pending approval."""

    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=3, max_length=1000)
