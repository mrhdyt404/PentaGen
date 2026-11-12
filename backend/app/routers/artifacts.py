import hashlib
from pathlib import Path
import uuid
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session
from ..audit import record_audit
from ..config import settings
from ..db import get_db
from ..deps import get_current_user, require_roles
from ..models import Project, Role, SourceArtifact, User
from ..scanners.api_scanner import OpenAPIParseError, parse_openapi_document
from ..scanners.code_analyzer import (
    ArtifactIngestionError,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    ingest_inline_files,
    ingest_zip_bundle,
)
from ..schemas import InlineSourceUploadRequest, OpenAPIImportRequest, SourceArtifactOut

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


def _validate_org_project(db: Session, *, project_id: int | None, organization_id: int) -> None:
    if project_id is None:
        return
    exists = (
        db.query(Project.id)
        .filter(Project.id == project_id, Project.organization_id == organization_id)
        .first()
    )
    if exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")


@router.get("", response_model=list[SourceArtifactOut])
def list_artifacts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List uploaded source code bundles and OpenAPI specifications for the organization."""
    return (
        db.query(SourceArtifact)
        .filter(SourceArtifact.organization_id == current_user.organization_id)
        .order_by(SourceArtifact.id.desc())
        .limit(100)
        .all()
    )


@router.get("/{artifact_id}", response_model=SourceArtifactOut)
def get_artifact(
    artifact_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get metadata for a specific organization artifact."""
    artifact = (
        db.query(SourceArtifact)
        .filter(
            SourceArtifact.id == artifact_id,
            SourceArtifact.organization_id == current_user.organization_id,
        )
        .first()
    )
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found.")
    return artifact


@router.post("/inline", response_model=SourceArtifactOut, status_code=status.HTTP_201_CREATED)
def upload_inline_source(
    payload: InlineSourceUploadRequest,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Ingest structured inline source files for SAST, secret scanning, and dependency analysis."""
    _validate_org_project(db, project_id=payload.project_id, organization_id=current_user.organization_id)
    try:
        bundle_dir, digest, file_count, total_bytes = ingest_inline_files(
            payload.files,
            artifacts_root=Path(settings.artifacts_dir),
            organization_id=current_user.organization_id,
        )
    except ArtifactIngestionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    artifact = SourceArtifact(
        organization_id=current_user.organization_id,
        project_id=payload.project_id,
        uploaded_by=current_user.id,
        name=payload.name.strip(),
        source_type="inline_files",
        sha256_digest=digest,
        file_count=file_count,
        total_bytes=total_bytes,
        storage_path=str(bundle_dir),
    )
    db.add(artifact)
    db.flush()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="artifact.uploaded",
        resource_type="source_artifact",
        resource_id=str(artifact.id),
        details={"source_type": "inline_files", "file_count": file_count, "sha256": digest},
    )
    db.commit()
    db.refresh(artifact)
    return artifact


@router.post("/upload", response_model=SourceArtifactOut, status_code=status.HTTP_201_CREATED)
async def upload_zip_source(
    name: str = Form(..., min_length=2, max_length=160),
    project_id: int | None = Form(default=None),
    file: UploadFile = File(...),
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Ingest a ZIP source archive safely with Zip-Slip and size limits enforced."""
    _validate_org_project(db, project_id=project_id, organization_id=current_user.organization_id)
    raw = await file.read(MAX_TOTAL_UNCOMPRESSED_BYTES + 1)
    if len(raw) > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded ZIP exceeds 10 MB limit.",
        )

    try:
        bundle_dir, digest, file_count, total_bytes = ingest_zip_bundle(
            raw,
            artifacts_root=Path(settings.artifacts_dir),
            organization_id=current_user.organization_id,
        )
    except ArtifactIngestionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    artifact = SourceArtifact(
        organization_id=current_user.organization_id,
        project_id=project_id,
        uploaded_by=current_user.id,
        name=name.strip(),
        source_type="zip_bundle",
        sha256_digest=digest,
        file_count=file_count,
        total_bytes=total_bytes,
        storage_path=str(bundle_dir),
    )
    db.add(artifact)
    db.flush()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="artifact.uploaded",
        resource_type="source_artifact",
        resource_id=str(artifact.id),
        details={"source_type": "zip_bundle", "file_count": file_count, "sha256": digest},
    )
    db.commit()
    db.refresh(artifact)
    return artifact


@router.post("/openapi", response_model=SourceArtifactOut, status_code=status.HTTP_201_CREATED)
def import_openapi_spec(
    payload: OpenAPIImportRequest,
    current_user: User = Depends(require_roles(Role.owner, Role.pentester)),
    db: Session = Depends(get_db),
):
    """Validate and store an OpenAPI/Swagger document for API security assessment."""
    _validate_org_project(db, project_id=payload.project_id, organization_id=current_user.organization_id)
    try:
        parse_openapi_document(payload.spec_text)
    except OpenAPIParseError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    encoded = payload.spec_text.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    bundle_dir = Path(settings.artifacts_dir) / f"org_{current_user.organization_id}" / uuid.uuid4().hex
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "openapi.spec").write_bytes(encoded)

    artifact = SourceArtifact(
        organization_id=current_user.organization_id,
        project_id=payload.project_id,
        uploaded_by=current_user.id,
        name=payload.name.strip(),
        source_type="openapi_spec",
        sha256_digest=digest,
        file_count=1,
        total_bytes=len(encoded),
        storage_path=str(bundle_dir),
    )
    db.add(artifact)
    db.flush()
    record_audit(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        event_type="artifact.openapi_imported",
        resource_type="source_artifact",
        resource_id=str(artifact.id),
        details={"sha256": digest, "bytes": len(encoded)},
    )
    db.commit()
    db.refresh(artifact)
    return artifact

