from dataclasses import dataclass, field
import hashlib
import re
from sqlalchemy.orm import Session
from ..models import Asset, Evidence, Finding, Scan, Severity

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"(?i)((?:authorization\s*:\s*)?bearer\s+)[A-Za-z0-9._\-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:set-)?cookie\s*:\s*[^=;\s]+=)[^;\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED_GITLAB_TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED_API_KEY]"),
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^:\s/]+:)[^@\s]+(@)"),
        r"\1[REDACTED]\2",
    ),
    (
        re.compile(
            r"""(?i)\b(password|passwd|secret|jwt_secret|api_key|token)\s*[:=]\s*(['"]?)[^\s'"]{4,}\2"""
        ),
        r"\1=[REDACTED]",
    ),
)


def redact_sensitive_text(text: str, max_len: int = 2000) -> str:
    """Strip credentials, tokens, private keys, and cookie secrets from evidence snippets."""
    redacted = text or ""
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) > max_len:
        return f"{redacted[: max_len - 15]}...[TRUNCATED]"
    return redacted


@dataclass(frozen=True)
class NormalizedFinding:
    """Typed scanner observation normalized across all Sprint 2 scanner modules."""

    category: str
    title: str
    description: str
    severity: str
    confidence: str
    remediation: str
    evidence_type: str
    evidence_content: str
    location: str | None = None
    cwe: str | None = None
    cvss_score: str | None = None
    artifact_metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedAsset:
    """Typed discovered inventory item (DNS, TLS, tech, API endpoint, dependency)."""

    asset_type: str
    name: str
    identifier: str
    metadata_json: dict = field(default_factory=dict)


@dataclass
class ScanModuleResult:
    """Container returned by each scanner module."""

    findings: list[NormalizedFinding] = field(default_factory=list)
    assets: list[NormalizedAsset] = field(default_factory=list)
    notes: dict = field(default_factory=dict)

    def merge(self, other: "ScanModuleResult") -> None:
        self.findings.extend(other.findings)
        self.assets.extend(other.assets)
        self.notes.update(other.notes)


def finding_fingerprint(item: NormalizedFinding) -> str:
    """Compute a stable SHA-256 deduplication fingerprint for a normalized finding."""
    raw = f"{item.category}|{item.title}|{item.location or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def persist_scan_outputs(
    db: Session,
    *,
    organization_id: int,
    scan: Scan,
    target_id: int | None,
    result: ScanModuleResult,
) -> tuple[int, int]:
    """Persist deduplicated findings, hashed redacted evidence, and discovered assets."""
    seen_fingerprints: set[str] = set()
    finding_count = 0

    for item in result.findings:
        fp = finding_fingerprint(item)
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)

        finding = Finding(
            organization_id=organization_id,
            scan_id=scan.id,
            category=item.category,
            title=item.title[:255],
            description=item.description,
            severity=Severity(item.severity),
            confidence=item.confidence,
            status="needs_review",
            cwe=item.cwe,
            cvss_score=item.cvss_score,
            location=item.location[:512] if item.location else None,
            fingerprint=fp,
            remediation=item.remediation,
        )
        db.add(finding)
        db.flush()
        finding_count += 1

        safe_evidence = redact_sensitive_text(item.evidence_content)
        if safe_evidence:
            db.add(
                Evidence(
                    organization_id=organization_id,
                    finding_id=finding.id,
                    evidence_type=item.evidence_type[:40],
                    content_redacted=safe_evidence,
                    content_hash=hashlib.sha256(safe_evidence.encode("utf-8")).hexdigest(),
                    artifact_metadata=item.artifact_metadata,
                )
            )

    seen_assets: set[tuple[str, str]] = set()
    asset_count = 0
    for asset_item in result.assets:
        key = (asset_item.asset_type, asset_item.identifier)
        if key in seen_assets:
            continue
        seen_assets.add(key)
        db.add(
            Asset(
                organization_id=organization_id,
                target_id=target_id,
                scan_id=scan.id,
                asset_type=asset_item.asset_type[:40],
                name=asset_item.name[:255],
                identifier=asset_item.identifier[:1024],
                metadata_json=asset_item.metadata_json,
            )
        )
        asset_count += 1

    return finding_count, asset_count
