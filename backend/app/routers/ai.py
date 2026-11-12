from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..ai.orchestrator import OrchestratorContractError, PentaGenOrchestrator
from ..ai.providers import build_provider_adapter
from ..ai.providers.base import LLMProviderError
from ..audit import record_audit
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import (
    AgentRun,
    AgentTask,
    FindingAnalysis,
    LLMProviderConfig,
    Role,
    Scan,
    SourceArtifact,
    Target,
    User,
)
from ..schemas import (
    AIAnalyzeRequest,
    AIAnalyzeResponse,
    AIPlanRequest,
    AgentRunDetailOut,
    AgentRunOut,
    AgentTaskOut,
    FindingAnalysisOut,
    LLMProviderCreate,
    LLMProviderOut,
)

router = APIRouter(prefix="/ai", tags=["ai"])
_orchestrator = PentaGenOrchestrator()


@router.get("/providers", response_model=list[LLMProviderOut])
def list_providers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List configured Cloud LLM and Ollama providers for the caller's organization."""
    return (
        db.query(LLMProviderConfig)
        .filter(LLMProviderConfig.organization_id == current_user.organization_id)
        .order_by(LLMProviderConfig.id.asc())
        .all()
    )


@router.post("/providers", response_model=LLMProviderOut, status_code=status.HTTP_201_CREATED)
def register_provider(
    payload: LLMProviderCreate,
    current_user: User = Depends(require_roles(Role.owner)),
    db: Session = Depends(get_db),
):
    """Register a Cloud OpenAI-compatible or local Ollama provider (owner only)."""
    if payload.is_default:
        existing_defaults = (
            db.query(LLMProviderConfig)
            .filter(
                LLMProviderConfig.organization_id == current_user.organization_id,
                LLMProviderConfig.is_default.is_(True),
            )
            .all()
        )
        for item in existing_defaults:
            item.is_default = False

    provider = LLMProviderConfig(
        organization_id=current_user.organization_id,
        name=payload.name.strip(),
        provider_type=payload.provider_type,
        base_url=str(payload.base_url).rstrip("/"),
        model_name=payload.model_name.strip(),
        api_key_env_var=payload.api_key_env_var,
        is_default=payload.is_default,
        is_active=True,
        created_by=current_user.id,
    )
    db.add(provider)
    db.flush()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="ai.provider_registered",
        resource_type="llm_provider",
        resource_id=str(provider.id),
        details={
            "provider_type": provider.provider_type,
            "model_name": provider.model_name,
            "is_default": provider.is_default,
        },
    )
    db.commit()
    db.refresh(provider)
    return provider


@router.post("/providers/{provider_id}/health")
async def check_provider_health(
    provider_id: int,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Check connectivity to a registered Cloud LLM or Ollama provider."""
    config = (
        db.query(LLMProviderConfig)
        .filter(
            LLMProviderConfig.id == provider_id,
            LLMProviderConfig.organization_id == current_user.organization_id,
        )
        .first()
    )
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="LLM provider not found.")
    try:
        adapter = build_provider_adapter(config)
    except LLMProviderError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    assert adapter is not None
    return await adapter.health_check()


@router.post("/plan", response_model=AgentRunOut)
async def create_assessment_plan(
    payload: AIPlanRequest,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Use the AI orchestrator planner agent to recommend allowed non-destructive scan profiles."""
    target: Target | None = None
    artifact: SourceArtifact | None = None
    if payload.target_id is not None:
        target = (
            db.query(Target)
            .filter(
                Target.id == payload.target_id,
                Target.organization_id == current_user.organization_id,
            )
            .first()
        )
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")

    if payload.source_artifact_id is not None:
        artifact = (
            db.query(SourceArtifact)
            .filter(
                SourceArtifact.id == payload.source_artifact_id,
                SourceArtifact.organization_id == current_user.organization_id,
            )
            .first()
        )
        if artifact is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Source artifact not found."
            )

    try:
        return await _orchestrator.generate_plan(
            db,
            current_user=current_user,
            target=target,
            artifact=artifact,
            goal=payload.goal,
            provider_id=payload.provider_id,
        )
    except OrchestratorContractError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/scans/{scan_id}/analyze", response_model=AIAnalyzeResponse)
async def analyze_scan(
    scan_id: int,
    payload: AIAnalyzeRequest | None = None,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester, Role.reviewer)),
    db: Session = Depends(get_db),
):
    """Run AI Security Analyst, False-Positive Detector, and Risk Prioritizer on scan findings."""
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.organization_id == current_user.organization_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    try:
        run, analyses = await _orchestrator.analyze_scan(
            db,
            current_user=current_user,
            scan=scan,
            provider_id=payload.provider_id if payload else None,
        )
    except OrchestratorContractError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AIAnalyzeResponse(
        run=AgentRunOut.model_validate(run),
        analyses=[FindingAnalysisOut.model_validate(item) for item in analyses],
    )


@router.get("/runs", response_model=list[AgentRunOut])
def list_agent_runs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List AI orchestrator runs for the caller's organization."""
    return (
        db.query(AgentRun)
        .filter(AgentRun.organization_id == current_user.organization_id)
        .order_by(AgentRun.id.desc())
        .limit(100)
        .all()
    )


@router.get("/runs/{run_id}", response_model=AgentRunDetailOut)
def get_agent_run(
    run_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get an AI orchestrator run and its audited task breakdown."""
    run = (
        db.query(AgentRun)
        .filter(AgentRun.id == run_id, AgentRun.organization_id == current_user.organization_id)
        .first()
    )
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent run not found.")

    tasks = (
        db.query(AgentTask)
        .filter(
            AgentTask.run_id == run.id,
            AgentTask.organization_id == current_user.organization_id,
        )
        .order_by(AgentTask.id.asc())
        .all()
    )
    detail = AgentRunDetailOut.model_validate(run)
    detail.tasks = [AgentTaskOut.model_validate(task) for task in tasks]
    return detail


@router.get("/scans/{scan_id}/analyses", response_model=list[FindingAnalysisOut])
def list_scan_analyses(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List advisory AI finding analyses for a scan, ordered by priority rank."""
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.organization_id == current_user.organization_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return (
        db.query(FindingAnalysis)
        .join(AgentRun, FindingAnalysis.agent_run_id == AgentRun.id)
        .filter(
            AgentRun.scan_id == scan_id,
            FindingAnalysis.organization_id == current_user.organization_id,
        )
        .order_by(FindingAnalysis.priority_rank.asc(), FindingAnalysis.id.desc())
        .all()
    )

