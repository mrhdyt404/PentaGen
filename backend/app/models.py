import enum
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base


def utcnow() -> datetime:
    """Return naive UTC timestamp compatible with both SQLite and PostgreSQL."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role(str, enum.Enum):
    """Supported RBAC roles within an organization."""

    owner = "owner"
    pentester = "pentester"
    reviewer = "reviewer"
    viewer = "viewer"


class ScanStatus(str, enum.Enum):
    """Lifecycle states of a security scan."""

    queued = "queued"
    running = "running"
    awaiting_approval = "awaiting_approval"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Severity(str, enum.Enum):
    """Normalized severity scale for security findings."""

    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Organization(Base):
    """Tenant boundary that owns users, targets, scans, and audit records."""

    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    """Authenticated platform user scoped to a single organization and role."""

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[Role] = mapped_column(Enum(Role, name="role"), default=Role.viewer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    organization: Mapped["Organization"] = relationship(back_populates="users")
    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """Revocable authentication session storing hashed refresh tokens."""

    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)
    user: Mapped["User"] = relationship(back_populates="sessions")


class Target(Base):
    """Registered target asset owned by an organization."""

    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    base_url: Mapped[str] = mapped_column(String(2048))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    authorizations: Mapped[list["Authorization"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class Authorization(Base):
    """Explicit authorization evidence, scope boundaries, and validity window for a target."""

    __tablename__ = "authorizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    granted_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    evidence_reference: Mapped[str] = mapped_column(String(2048))
    scope_json: Mapped[dict] = mapped_column(JSON, default=dict)
    starts_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    target: Mapped["Target"] = relationship(back_populates="authorizations")


class Project(Base):
    """Logical assessment engagement grouping scans within an organization."""

    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SourceArtifact(Base):
    """Uploaded source code archive or API specification scoped to an organization."""

    __tablename__ = "source_artifacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True, index=True)
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(160))
    source_type: Mapped[str] = mapped_column(String(30))
    sha256_digest: Mapped[str] = mapped_column(String(64), index=True)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Scan(Base):
    """Assessment execution record tied to an authorized target and/or source artifact."""

    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True, index=True)
    source_artifact_id: Mapped[int | None] = mapped_column(
        ForeignKey("source_artifacts.id"), nullable=True, index=True
    )
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, name="scanstatus"), default=ScanStatus.queued)
    profile: Mapped[str] = mapped_column(String(40), default="safe_baseline")
    scanner_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Asset(Base):
    """Discovered DNS, TLS, web technology, API endpoint, or dependency inventory item."""

    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_type: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(255))
    identifier: Mapped[str] = mapped_column(String(1024))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Finding(Base):
    """Normalized security observation discovered during a scan."""

    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    category: Mapped[str] = mapped_column(String(40), default="web", index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="severity"), default=Severity.info)
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="needs_review")
    cwe: Mapped[str | None] = mapped_column(String(30), nullable=True)
    cvss_score: Mapped[str | None] = mapped_column(String(10), nullable=True)
    location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Evidence(Base):
    """Redacted supporting proof and content hash for a finding."""

    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(40))
    content_redacted: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    artifact_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Approval(Base):
    """Human approval record for gated security actions."""

    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    requested_action: Mapped[str] = mapped_column(String(120))
    risk_level: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    """Append-only security and authorization audit log."""

    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str] = mapped_column(String(80))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class LLMProviderConfig(Base):
    """Organization-scoped AI provider definition (secrets remain in environment variables)."""

    __tablename__ = "llm_providers"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    provider_type: Mapped[str] = mapped_column(String(30))  # cloud_openai | ollama
    base_url: Mapped[str] = mapped_column(String(512))
    model_name: Mapped[str] = mapped_column(String(120))
    api_key_env_var: Mapped[str | None] = mapped_column(String(80), nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AgentRun(Base):
    """Execution record for a multi-agent AI analysis or planning run."""

    __tablename__ = "agent_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True, index=True)
    provider_id: Mapped[int | None] = mapped_column(
        ForeignKey("llm_providers.id"), nullable=True, index=True
    )
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    mode: Mapped[str] = mapped_column(String(40), default="hybrid_ai")
    status: Mapped[str] = mapped_column(String(30), default="completed")
    plan_json: Mapped[dict] = mapped_column(JSON, default=dict)
    summary_json: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AgentTask(Base):
    """Individual agent task adhering to the fixed allowlisted action contract."""

    __tablename__ = "agent_tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"), index=True)
    agent_name: Mapped[str] = mapped_column(String(60))
    action_name: Mapped[str] = mapped_column(String(60))
    status: Mapped[str] = mapped_column(String(30), default="completed")
    input_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    output_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class FindingAnalysis(Base):
    """Advisory AI security analyst & false-positive triage record linked to a finding."""

    __tablename__ = "finding_analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    agent_run_id: Mapped[int] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"), index=True)
    verdict: Mapped[str] = mapped_column(String(40), default="needs_verification")
    is_likely_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    fp_confidence: Mapped[str] = mapped_column(String(16), default="0.00")
    risk_score: Mapped[str] = mapped_column(String(16), default="0.0")
    priority_rank: Mapped[int] = mapped_column(Integer, default=3)
    rationale: Mapped[str] = mapped_column(Text)
    remediation_plan: Mapped[str] = mapped_column(Text)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
