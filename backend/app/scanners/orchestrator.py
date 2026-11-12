from pathlib import Path
from ..config import settings
from ..models import SourceArtifact, Target
from .api_scanner import parse_openapi_document, scan_live_api_posture, scan_openapi_spec
from .code_analyzer import analyze_source_bundle
from .evidence import NormalizedFinding, ScanModuleResult
from .recon import inspect_tls, run_passive_recon
from .safe_http import inspect_headers
from .web import run_web_baseline


async def execute_scan_profile(
    *,
    profile: str,
    target: Target | None,
    artifact: SourceArtifact | None,
) -> ScanModuleResult:
    """Dispatch non-destructive Sprint 2 scanner modules based on validated profile and inputs."""
    combined = ScanModuleResult()
    executed_modules: list[str] = []

    if profile == "safe_baseline":
        assert target is not None
        header_items = await inspect_headers(target.base_url)
        for item in header_items:
            combined.findings.append(
                NormalizedFinding(
                    category="web",
                    title=item["title"],
                    description=item["description"],
                    severity=item["severity"],
                    confidence=item["confidence"],
                    location=target.base_url,
                    cwe="CWE-693",
                    remediation=item["remediation"],
                    evidence_type="http_header_check",
                    evidence_content=item.get("evidence", ""),
                )
            )
        combined.merge(await inspect_tls(target.base_url, timeout_seconds=settings.scanner_timeout_seconds))
        executed_modules.extend(["safe_http", "tls"])

    elif profile == "recon_passive":
        assert target is not None
        combined.merge(await run_passive_recon(target.base_url, timeout_seconds=settings.scanner_timeout_seconds))
        executed_modules.append("recon_passive")

    elif profile == "web_baseline":
        assert target is not None
        combined.merge(await run_web_baseline(target.base_url, timeout_seconds=settings.scanner_timeout_seconds))
        executed_modules.append("web_baseline")

    elif profile == "api_audit":
        if artifact is not None and artifact.storage_path:
            spec_path = Path(artifact.storage_path) / "openapi.spec"
            if spec_path.exists():
                spec = parse_openapi_document(spec_path.read_text(encoding="utf-8"))
                combined.merge(scan_openapi_spec(spec, spec_name=artifact.name))
                executed_modules.append("openapi_spec")
        if target is not None:
            combined.merge(
                await scan_live_api_posture(target.base_url, timeout_seconds=settings.scanner_timeout_seconds)
            )
            executed_modules.append("live_api_posture")

    elif profile == "code_sast":
        assert artifact is not None and artifact.storage_path
        combined.merge(
            analyze_source_bundle(
                Path(artifact.storage_path),
                artifacts_root=Path(settings.artifacts_dir),
                enable_semgrep_cli=settings.enable_semgrep_cli,
            )
        )
        executed_modules.append("code_sast")

    elif profile == "full_non_destructive":
        if target is not None:
            combined.merge(
                await run_passive_recon(target.base_url, timeout_seconds=settings.scanner_timeout_seconds)
            )
            combined.merge(
                await run_web_baseline(target.base_url, timeout_seconds=settings.scanner_timeout_seconds)
            )
            executed_modules.extend(["recon_passive", "web_baseline"])
        if artifact is not None and artifact.storage_path:
            if artifact.source_type == "openapi_spec":
                spec = parse_openapi_document((Path(artifact.storage_path) / "openapi.spec").read_text(encoding="utf-8"))
                combined.merge(scan_openapi_spec(spec, spec_name=artifact.name))
                executed_modules.append("openapi_spec")
            else:
                combined.merge(
                    analyze_source_bundle(
                        Path(artifact.storage_path),
                        artifacts_root=Path(settings.artifacts_dir),
                        enable_semgrep_cli=settings.enable_semgrep_cli,
                    )
                )
                executed_modules.append("code_sast")

    combined.notes["executed_modules"] = executed_modules
    return combined

