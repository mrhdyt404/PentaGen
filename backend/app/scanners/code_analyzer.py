import ast
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import uuid
import zipfile
from .evidence import NormalizedAsset, NormalizedFinding, ScanModuleResult, redact_sensitive_text
from .execution_policy import ExecutionPolicyError, run_allowlisted_tool

MAX_BUNDLE_FILES = 400
MAX_TOTAL_UNCOMPRESSED_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_SINGLE_FILE_BYTES = 512 * 1024  # 512 KB

_ALLOWED_TEXT_EXTENSIONS = frozenset(
    {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml",
        ".txt", ".env", ".toml", ".ini", ".cfg", ".sql", ".sh",
    }
)

_SECRET_LINE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("Hardcoded AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("Hardcoded GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "critical"),
    ("Hardcoded private key material", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "critical"),
    (
        "Hardcoded secret or credential assignment",
        re.compile(r"""(?i)\b(?:jwt_secret|secret_key|api_key|db_password|password)\s*=\s*['"][^'"]{8,}['"]"""),
        "high",
    ),
)

_JS_SINK_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str, str], ...] = (
    (
        "Potential XSS via dangerouslySetInnerHTML",
        re.compile(r"\bdangerouslySetInnerHTML\b"),
        "medium",
        "CWE-79",
        "Sanitize HTML with DOMPurify or render safe text nodes instead of dangerouslySetInnerHTML.",
    ),
    (
        "Dynamic code execution via eval() / new Function()",
        re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()"),
        "high",
        "CWE-95",
        "Avoid dynamic code evaluation; use safe parsers or static dispatch tables.",
    ),
    (
        "TLS certificate verification disabled in Node.js",
        re.compile(r"rejectUnauthorized\s*:\s*false"),
        "high",
        "CWE-295",
        "Enable TLS certificate verification in production HTTP clients.",
    ),
)

_KNOWN_ADVISORIES: dict[str, tuple[tuple[int, ...], str, str]] = {
    "pyyaml": ((5, 4, 0), "high", "Upgrade PyYAML >= 5.4 and always use yaml.safe_load."),
    "urllib3": ((1, 26, 18), "medium", "Upgrade urllib3 >= 1.26.18 to address header/cookie leaks."),
    "fastapi": ((0, 109, 1), "medium", "Upgrade FastAPI >= 0.109.1 to address multipart ReDoS."),
    "python-jose": ((99, 0, 0), "medium", "Prefer actively maintained PyJWT over python-jose."),
    "lodash": ((4, 17, 21), "high", "Upgrade lodash >= 4.17.21 to mitigate prototype pollution."),
}


class ArtifactIngestionError(ValueError):
    """Raised when an uploaded source archive or inline bundle fails safety limits."""


@dataclass(frozen=True)
class SourceFileEntry:
    """Validated relative path and UTF-8 content."""

    rel_path: str
    content: str


def _validate_relative_path(raw_path: str) -> str:
    cleaned = raw_path.replace("\\", "/").lstrip("/")
    posix = PurePosixPath(cleaned)
    if not cleaned or posix.is_absolute() or ".." in posix.parts:
        raise ArtifactIngestionError(f"Unsafe file path rejected: {raw_path}")
    return str(posix)


def _persist_bundle(
    files: list[SourceFileEntry],
    *,
    artifacts_root: Path,
    organization_id: int,
) -> tuple[Path, str, int, int]:
    """Write validated text files to an organization-isolated folder and hash deterministically."""
    bundle_dir = artifacts_root / f"org_{organization_id}" / uuid.uuid4().hex
    bundle_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    total_bytes = 0

    for entry in sorted(files, key=lambda x: x.rel_path):
        encoded = entry.content.encode("utf-8")
        total_bytes += len(encoded)
        if total_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ArtifactIngestionError("Total source bundle size exceeds 10 MB limit.")
        digest.update(entry.rel_path.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(encoded)

        dest = (bundle_dir / entry.rel_path).resolve()
        if bundle_dir.resolve() not in dest.parents:
            raise ArtifactIngestionError(f"Path escaped bundle directory: {entry.rel_path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(encoded)

    return bundle_dir, digest.hexdigest(), len(files), total_bytes


def ingest_inline_files(
    files_map: dict[str, str],
    *,
    artifacts_root: Path,
    organization_id: int,
) -> tuple[Path, str, int, int]:
    """Validate and persist inline source files for static analysis."""
    if not files_map or len(files_map) > MAX_BUNDLE_FILES:
        raise ArtifactIngestionError(f"Provide between 1 and {MAX_BUNDLE_FILES} files.")
    entries: list[SourceFileEntry] = []
    for raw_path, content in files_map.items():
        rel = _validate_relative_path(raw_path)
        if len(content.encode("utf-8")) > MAX_SINGLE_FILE_BYTES:
            raise ArtifactIngestionError(f"File '{rel}' exceeds 512 KB limit.")
        entries.append(SourceFileEntry(rel_path=rel, content=content))
    return _persist_bundle(entries, artifacts_root=artifacts_root, organization_id=organization_id)


def ingest_zip_bundle(
    raw_zip_bytes: bytes,
    *,
    artifacts_root: Path,
    organization_id: int,
) -> tuple[Path, str, int, int]:
    """Safely extract readable source files from a ZIP archive with Zip-Slip and Zip-Bomb checks."""
    if len(raw_zip_bytes) > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise ArtifactIngestionError("Uploaded ZIP exceeds 10 MB limit.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_zip_bytes))
    except zipfile.BadZipFile as exc:
        raise ArtifactIngestionError("Uploaded file is not a valid ZIP archive.") from exc

    entries: list[SourceFileEntry] = []
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Reject POSIX symlinks stored in ZIP external attributes.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ArtifactIngestionError(f"Symlink entry rejected: {info.filename}")
            rel = _validate_relative_path(info.filename)
            ext = PurePosixPath(rel).suffix.lower()
            name_lower = PurePosixPath(rel).name.lower()
            if ext not in _ALLOWED_TEXT_EXTENSIONS and not name_lower.startswith("requirements"):
                continue
            if info.file_size > MAX_SINGLE_FILE_BYTES:
                raise ArtifactIngestionError(f"Archive entry '{rel}' exceeds 512 KB limit.")
            if len(entries) >= MAX_BUNDLE_FILES:
                raise ArtifactIngestionError(f"Archive contains more than {MAX_BUNDLE_FILES} source files.")
            raw_bytes = zf.read(info.filename)
            if len(raw_bytes) > MAX_SINGLE_FILE_BYTES:
                raise ArtifactIngestionError(f"Decompressed entry '{rel}' exceeds 512 KB limit.")
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            entries.append(SourceFileEntry(rel_path=rel, content=text))

    if not entries:
        raise ArtifactIngestionError("No analyzable UTF-8 source or manifest files found in archive.")
    return _persist_bundle(entries, artifacts_root=artifacts_root, organization_id=organization_id)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _analyze_python_ast(rel_path: str, source: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return findings

    lines = source.splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        line_no = getattr(node, "lineno", 1)
        snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else name

        if name in {"eval", "exec"}:
            findings.append(
                NormalizedFinding(
                    category="code",
                    title=f"Dangerous dynamic code execution via {name}()",
                    description=f"Calling {name}() can lead to arbitrary code execution if inputs are untrusted.",
                    severity="high",
                    confidence="high",
                    location=f"{rel_path}:{line_no}",
                    cwe="CWE-94",
                    remediation="Replace eval/exec with ast.literal_eval or explicit dispatch.",
                    evidence_type="sast_python_ast",
                    evidence_content=snippet,
                    artifact_metadata={"file": rel_path, "line": line_no, "rule": "py-dynamic-exec"},
                )
            )
        elif name in {"os.system", "os.popen"} or (
            name.startswith("subprocess.")
            and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
        ):
            findings.append(
                NormalizedFinding(
                    category="code",
                    title=f"Shell command execution sink ({name})",
                    description="Shell invocation risks command injection if arguments include external input.",
                    severity="high",
                    confidence="high",
                    location=f"{rel_path}:{line_no}",
                    cwe="CWE-78",
                    remediation="Use subprocess.run([...], shell=False) with strict argument lists.",
                    evidence_type="sast_python_ast",
                    evidence_content=snippet,
                    artifact_metadata={"file": rel_path, "line": line_no, "rule": "py-shell-exec"},
                )
            )
        elif name in {"pickle.loads", "pickle.load"}:
            findings.append(
                NormalizedFinding(
                    category="code",
                    title="Unsafe pickle deserialization",
                    description="Deserializing untrusted pickle payloads allows arbitrary code execution.",
                    severity="high",
                    confidence="high",
                    location=f"{rel_path}:{line_no}",
                    cwe="CWE-502",
                    remediation="Replace pickle with JSON or schema-validated serialization.",
                    evidence_type="sast_python_ast",
                    evidence_content=snippet,
                    artifact_metadata={"file": rel_path, "line": line_no, "rule": "py-unsafe-pickle"},
                )
            )
        elif name == "yaml.load" and not any(
            kw.arg == "Loader" and "Safe" in _call_name(kw.value) for kw in node.keywords
        ):
            findings.append(
                NormalizedFinding(
                    category="code",
                    title="Unsafe yaml.load() without SafeLoader",
                    description="yaml.load without SafeLoader can instantiate arbitrary Python objects.",
                    severity="high",
                    confidence="high",
                    location=f"{rel_path}:{line_no}",
                    cwe="CWE-502",
                    remediation="Use yaml.safe_load() instead of yaml.load().",
                    evidence_type="sast_python_ast",
                    evidence_content=snippet,
                    artifact_metadata={"file": rel_path, "line": line_no, "rule": "py-unsafe-yaml"},
                )
            )
        elif name.endswith(".execute") and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            findings.append(
                NormalizedFinding(
                    category="code",
                    title="Potential SQL injection via formatted query string",
                    description="SQL query appears constructed with string formatting/concatenation inside execute().",
                    severity="high",
                    confidence="medium",
                    location=f"{rel_path}:{line_no}",
                    cwe="CWE-89",
                    remediation="Use parameterized queries or ORM bind parameters.",
                    evidence_type="sast_python_ast",
                    evidence_content=snippet,
                    artifact_metadata={"file": rel_path, "line": line_no, "rule": "py-sql-format"},
                )
            )
        elif name in {"hashlib.md5", "hashlib.sha1"}:
            findings.append(
                NormalizedFinding(
                    category="code",
                    title=f"Weak cryptographic hash function ({name})",
                    description="MD5 and SHA-1 are deprecated for security-sensitive integrity or password hashing.",
                    severity="medium",
                    confidence="medium",
                    location=f"{rel_path}:{line_no}",
                    cwe="CWE-327",
                    remediation="Use SHA-256+ for integrity checks or Argon2id for password hashing.",
                    evidence_type="sast_python_ast",
                    evidence_content=snippet,
                    artifact_metadata={"file": rel_path, "line": line_no, "rule": "py-weak-hash"},
                )
            )
        elif any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords):
            findings.append(
                NormalizedFinding(
                    category="code",
                    title="TLS verification disabled (verify=False)",
                    description="Disabling TLS certificate validation exposes connections to MITM attacks.",
                    severity="medium",
                    confidence="high",
                    location=f"{rel_path}:{line_no}",
                    cwe="CWE-295",
                    remediation="Remove verify=False and supply a valid CA trust bundle if needed.",
                    evidence_type="sast_python_ast",
                    evidence_content=snippet,
                    artifact_metadata={"file": rel_path, "line": line_no, "rule": "py-tls-verify-false"},
                )
            )
    return findings


def _parse_version_tuple(spec: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", spec)
    if not match:
        return None
    parts = [int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)]
    return tuple(parts)


def _check_dependency(
    *,
    rel_path: str,
    pkg_name: str,
    version_spec: str,
    ecosystem: str,
    result: ScanModuleResult,
) -> None:
    pkg_lower = pkg_name.lower().strip()
    result.assets.append(
        NormalizedAsset(
            asset_type="dependency",
            name=f"{ecosystem}:{pkg_lower}",
            identifier=f"{ecosystem}:{pkg_lower}@{version_spec or 'unpinned'}",
            metadata_json={"ecosystem": ecosystem, "package": pkg_lower, "spec": version_spec, "file": rel_path},
        )
    )
    if not version_spec or version_spec.strip() in {"*", "latest"}:
        result.findings.append(
            NormalizedFinding(
                category="dependency",
                title=f"Unpinned {ecosystem} dependency: {pkg_lower}",
                description="Dependency lacks a bounded version specifier, risking unexpected supply-chain changes.",
                severity="low",
                confidence="high",
                location=rel_path,
                cwe="CWE-1104",
                remediation="Pin dependencies using explicit version ranges and lockfiles.",
                evidence_type="dependency_manifest",
                evidence_content=f"{rel_path}: {pkg_lower} ({version_spec or 'no version'})",
            )
        )
        return

    advisory = _KNOWN_ADVISORIES.get(pkg_lower)
    parsed_ver = _parse_version_tuple(version_spec)
    if advisory and parsed_ver and parsed_ver < advisory[0]:
        result.findings.append(
            NormalizedFinding(
                category="dependency",
                title=f"Outdated or vulnerable {ecosystem} package: {pkg_lower} ({version_spec})",
                description=f"{pkg_lower} {version_spec} is below recommended safe baseline {'.'.join(map(str, advisory[0]))}.",
                severity=advisory[1],
                confidence="medium",
                location=rel_path,
                cwe="CWE-1395",
                remediation=advisory[2],
                evidence_type="dependency_advisory",
                evidence_content=f"{rel_path}: {pkg_lower} {version_spec}",
            )
        )


def _analyze_manifest(rel_path: str, content: str, result: ScanModuleResult) -> None:
    name_lower = PurePosixPath(rel_path).name.lower()
    if name_lower.startswith("requirements") and name_lower.endswith(".txt"):
        for raw_line in content.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(.*)$", line)
            if match:
                _check_dependency(
                    rel_path=rel_path,
                    pkg_name=match.group(1),
                    version_spec=match.group(2).strip(),
                    ecosystem="pypi",
                    result=result,
                )
    elif name_lower == "package.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section)
            if isinstance(deps, dict):
                for pkg, spec in deps.items():
                    _check_dependency(
                        rel_path=rel_path,
                        pkg_name=str(pkg),
                        version_spec=str(spec),
                        ecosystem="npm",
                        result=result,
                    )


def _maybe_run_semgrep(bundle_dir: Path, artifacts_root: Path) -> tuple[list[NormalizedFinding], str]:
    try:
        proc = run_allowlisted_tool(
            "semgrep",
            ["--json", "--config", "auto", "--no-git-ignore", "--metrics=off", "."],
            work_dir=bundle_dir,
            allowed_root=artifacts_root,
            timeout_seconds=30,
        )
    except ExecutionPolicyError as exc:
        return [], f"skipped:{exc}"
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        return [], f"error:{type(exc).__name__}"

    if proc.returncode not in (0, 1):
        return [], f"failed_exit_{proc.returncode}"
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], "invalid_json"

    findings: list[NormalizedFinding] = []
    for item in payload.get("results") or []:
        extra = item.get("extra") or {}
        sev_raw = (extra.get("severity") or "WARNING").upper()
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}.get(sev_raw, "medium")
        rel_path = item.get("path", "unknown")
        line = (item.get("start") or {}).get("line", 1)
        findings.append(
            NormalizedFinding(
                category="code",
                title=f"Semgrep: {item.get('check_id', 'rule')}",
                description=extra.get("message") or "Semgrep static analysis match.",
                severity=sev,
                confidence="medium",
                location=f"{rel_path}:{line}",
                remediation="Review and remediate the flagged static analysis pattern.",
                evidence_type="semgrep_match",
                evidence_content=redact_sensitive_text(extra.get("lines") or ""),
                artifact_metadata={"rule_id": item.get("check_id"), "file": rel_path, "line": line},
            )
        )
    return findings, "executed"


def analyze_source_bundle(
    bundle_dir: Path,
    *,
    artifacts_root: Path,
    enable_semgrep_cli: bool = False,
) -> ScanModuleResult:
    """Run SAST, secret scanning, and dependency/SBOM analysis on a persisted source bundle."""
    result = ScanModuleResult()
    resolved_bundle = bundle_dir.resolve()
    resolved_root = artifacts_root.resolve()
    if resolved_bundle != resolved_root and resolved_root not in resolved_bundle.parents:
        raise ArtifactIngestionError("Source bundle path escapes configured artifacts directory.")

    files_analyzed = 0
    for file_path in sorted(resolved_bundle.rglob("*")):
        if not file_path.is_file():
            continue
        rel_path = file_path.relative_to(resolved_bundle).as_posix()
        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        files_analyzed += 1

        ext = file_path.suffix.lower()
        if ext == ".py":
            result.findings.extend(_analyze_python_ast(rel_path, content))
        elif ext in {".js", ".jsx", ".ts", ".tsx"}:
            for line_no, line in enumerate(content.splitlines(), start=1):
                for title, pattern, severity, cwe, remediation in _JS_SINK_PATTERNS:
                    if pattern.search(line):
                        result.findings.append(
                            NormalizedFinding(
                                category="code",
                                title=title,
                                description=f"Static JS/TS pattern matched in {rel_path}.",
                                severity=severity,
                                confidence="medium",
                                location=f"{rel_path}:{line_no}",
                                cwe=cwe,
                                remediation=remediation,
                                evidence_type="sast_pattern",
                                evidence_content=line.strip(),
                                artifact_metadata={"file": rel_path, "line": line_no},
                            )
                        )

        for line_no, line in enumerate(content.splitlines(), start=1):
            for secret_title, pattern, severity in _SECRET_LINE_PATTERNS:
                if pattern.search(line):
                    result.findings.append(
                        NormalizedFinding(
                            category="code",
                            title=secret_title,
                            description="Potential hardcoded secret or key material detected in source bundle.",
                            severity=severity,
                            confidence="high",
                            location=f"{rel_path}:{line_no}",
                            cwe="CWE-798",
                            remediation="Remove hardcoded secrets from source and inject via secret manager or environment.",
                            evidence_type="secret_scan",
                            evidence_content=redact_sensitive_text(line.strip()),
                            artifact_metadata={"file": rel_path, "line": line_no, "redacted": True},
                        )
                    )

        _analyze_manifest(rel_path, content, result)

    semgrep_status = "disabled_using_builtin_sast"
    if enable_semgrep_cli:
        semgrep_findings, semgrep_status = _maybe_run_semgrep(resolved_bundle, resolved_root)
        result.findings.extend(semgrep_findings)

    result.notes["files_analyzed"] = files_analyzed
    result.notes["semgrep_status"] = semgrep_status
    return result

