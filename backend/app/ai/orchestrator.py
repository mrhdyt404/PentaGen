from sqlalchemy.orm import Session
from ..audit import record_audit
from ..models import (
    AgentRun,
    AgentTask,
    Asset,
    Evidence,
    Finding,
    FindingAnalysis,
    LLMProviderConfig,
    Scan,
    SourceArtifact,
    Target,
    User,
    utcnow,
)
from .analyst import analyze_finding_security, build_assessment_plan
from .false_positive import evaluate_false_positive
from .providers import build_provider_adapter
from .providers.base import BaseLLMProvider, LLMProviderError

ALLOWED_AGENT_ACTIONS = frozenset(
    {"plan_assessment", "detect_false_positives", "triage_findings", "prioritize_risk"}
)


class OrchestratorContractError(ValueError):
    """Raised when an agent task attempts an action outside the allowlisted contract."""


class PentaGenOrchestrator:
    """Custom multi-agent orchestrator enforcing action contracts, prompt safety, and auditability."""

    def _resolve_provider(
        self,
        db: Session,
        *,
        organization_id: int,
        provider_id: int | None,
    ) -> tuple[LLMProviderConfig | None, BaseLLMProvider | None, str | None]:
        config: LLMProviderConfig | None = None
        if provider_id is not None:
            config = (
                db.query(LLMProviderConfig)
                .filter(
                    LLMProviderConfig.id == provider_id,
                    LLMProviderConfig.organization_id == organization_id,
                    LLMProviderConfig.is_active.is_(True),
                )
                .first()
            )
            if config is None:
                raise OrchestratorContractError("Requested LLM provider was not found or is inactive.")
        else:
            config = (
                db.query(LLMProviderConfig)
                .filter(
                    LLMProviderConfig.organization_id == organization_id,
                    LLMProviderConfig.is_active.is_(True),
                    LLMProviderConfig.is_default.is_(True),
                )
                .first()
            )

        if config is None:
            return None, None, None
        try:
            return config, build_provider_adapter(config), None
        except LLMProviderError as exc:
            return config, None, str(exc)

    def _record_task(
        self,
        db: Session,
        *,
        organization_id: int,
        run_id: int,
        agent_name: str,
        action_name: str,
        input_snapshot: dict,
        output_json: dict,
        error_message: str | None = None,
    ) -> AgentTask:
        if action_name not in ALLOWED_AGENT_ACTIONS:
            raise OrchestratorContractError(f"Agent action '{action_name}' is not allowlisted.")
        task = AgentTask(
            organization_id=organization_id,
            run_id=run_id,
            agent_name=agent_name,
            action_name=action_name,
            status="completed_with_fallback" if error_message else "completed",
            input_snapshot=input_snapshot,
            output_json=output_json,
            error_message=error_message,
        )
        db.add(task)
        return task

    async def generate_plan(
        self,
        db: Session,
        *,
        current_user: User,
        target: Target | None,
        artifact: SourceArtifact | None,
        goal: str,
        provider_id: int | None = None,
    ) -> AgentRun:
        """Create an assessment plan via the Planner Agent and persist run/task records."""
        config, adapter, init_err = self._resolve_provider(
            db, organization_id=current_user.organization_id, provider_id=provider_id
        )
        mode = f"{config.provider_type}:{config.model_name}" if (config and adapter) else "heuristic_fallback"
        run = AgentRun(
            organization_id=current_user.organization_id,
            scan_id=None,
            provider_id=config.id if config else None,
            requested_by=current_user.id,
            mode=mode,
            status="running",
        )
        db.add(run)
        db.flush()

        plan, fallback_err = await build_assessment_plan(
            target=target,
            artifact=artifact,
            goal=goal,
            provider=adapter,
        )
        task_err = fallback_err or init_err
        self._record_task(
            db,
            organization_id=current_user.organization_id,
            run_id=run.id,
            agent_name="planner_agent",
            action_name="plan_assessment",
            input_snapshot={
                "target_id": target.id if target else None,
                "source_artifact_id": artifact.id if artifact else None,
            },
            output_json=plan,
            error_message=task_err,
        )
        run.plan_json = plan
        run.summary_json = {"used_fallback": bool(task_err)}
        run.status = "completed"
        run.finished_at = utcnow()

        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="ai.plan_generated",
            resource_type="agent_run",
            resource_id=str(run.id),
            details={"mode": run.mode, "profiles": plan.get("recommended_profiles", [])},
        )
        db.commit()
        db.refresh(run)
        return run

    async def analyze_scan(
        self,
        db: Session,
        *,
        current_user: User,
        scan: Scan,
        provider_id: int | None = None,
    ) -> tuple[AgentRun, list[FindingAnalysis]]:
        """Run False-Positive Detector, Security Analyst, and Risk Prioritizer over scan findings."""
        config, adapter, init_err = self._resolve_provider(
            db, organization_id=current_user.organization_id, provider_id=provider_id
        )
        mode = f"{config.provider_type}:{config.model_name}" if (config and adapter) else "heuristic_fallback"
        run = AgentRun(
            organization_id=current_user.organization_id,
            scan_id=scan.id,
            provider_id=config.id if config else None,
            requested_by=current_user.id,
            mode=mode,
            status="running",
        )
        db.add(run)
        db.flush()

        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id, Finding.organization_id == current_user.organization_id)
            .order_by(Finding.id.asc())
            .all()
        )
        assets = (
            db.query(Asset)
            .filter(Asset.scan_id == scan.id, Asset.organization_id == current_user.organization_id)
            .all()
        )
        scan_summary = scan.scanner_summary or {}

        fp_outputs: list[dict] = []
        analyst_outputs: list[dict] = []
        analyses: list[FindingAnalysis] = []
        fallback_notes: list[str] = [init_err] if init_err else []
        likely_fp_count = 0

        for finding in findings:
            evidence_rows = (
                db.query(Evidence)
                .filter(
                    Evidence.finding_id == finding.id,
                    Evidence.organization_id == current_user.organization_id,
                )
                .all()
            )

            fp_res, fp_err = await evaluate_false_positive(
                finding, evidence_rows, assets, scan_summary, provider=adapter
            )
            if fp_err:
                fallback_notes.append(f"finding:{finding.id}:{fp_err}")
            if fp_res["is_likely_false_positive"]:
                likely_fp_count += 1
            fp_outputs.append({"finding_id": finding.id, **fp_res})

            analyst_res, an_err = await analyze_finding_security(
                finding, evidence_rows, assets, fp_res, provider=adapter
            )
            if an_err:
                fallback_notes.append(f"finding:{finding.id}:{an_err}")
            analyst_outputs.append({"finding_id": finding.id, **analyst_res})

            analysis = FindingAnalysis(
                organization_id=current_user.organization_id,
                finding_id=finding.id,
                agent_run_id=run.id,
                verdict=fp_res["verdict"],
                is_likely_false_positive=fp_res["is_likely_false_positive"],
                fp_confidence=f"{fp_res['fp_confidence']:.2f}",
                risk_score=analyst_res["risk_score"],
                priority_rank=analyst_res["priority_rank"],
                rationale=analyst_res["analyst_note"],
                remediation_plan=analyst_res["remediation_plan"],
                evidence_refs=fp_res["evidence_ids"],
            )
            db.add(analysis)
            analyses.append(analysis)

            # Update advisory score/status without modifying immutable Evidence rows.
            finding.cvss_score = analyst_res["risk_score"]
            finding.status = "likely_fp" if fp_res["is_likely_false_positive"] else "needs_review"

        err_summary = "; ".join(fallback_notes[:5]) if fallback_notes else None
        self._record_task(
            db,
            organization_id=current_user.organization_id,
            run_id=run.id,
            agent_name="false_positive_detector",
            action_name="detect_false_positives",
            input_snapshot={"scan_id": scan.id, "finding_count": len(findings)},
            output_json={"likely_false_positives": likely_fp_count, "items": fp_outputs},
            error_message=err_summary,
        )
        self._record_task(
            db,
            organization_id=current_user.organization_id,
            run_id=run.id,
            agent_name="security_analyst",
            action_name="triage_findings",
            input_snapshot={"scan_id": scan.id, "asset_count": len(assets)},
            output_json={"analyzed_count": len(analyst_outputs)},
            error_message=err_summary,
        )
        prioritized = sorted(
            analyst_outputs,
            key=lambda item: (item["priority_rank"], -float(item["risk_score"])),
        )
        self._record_task(
            db,
            organization_id=current_user.organization_id,
            run_id=run.id,
            agent_name="risk_prioritizer",
            action_name="prioritize_risk",
            input_snapshot={"finding_count": len(findings)},
            output_json={"top_findings": prioritized[:10]},
        )

        run.summary_json = {
            "findings_analyzed": len(findings),
            "likely_false_positives": likely_fp_count,
            "likely_valid": sum(1 for item in fp_outputs if item["verdict"] == "likely_valid"),
            "needs_verification": sum(1 for item in fp_outputs if item["verdict"] == "needs_verification"),
            "used_fallback": bool(err_summary),
        }
        run.status = "completed"
        run.finished_at = utcnow()

        record_audit(
            db,
            organization_id=current_user.organization_id,
            actor_user_id=current_user.id,
            event_type="ai.scan_analyzed",
            resource_type="agent_run",
            resource_id=str(run.id),
            details={"scan_id": scan.id, "mode": run.mode, **run.summary_json},
        )
        db.commit()
        db.refresh(run)
        for item in analyses:
            db.refresh(item)
        return run, analyses

