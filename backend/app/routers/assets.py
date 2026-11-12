from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import get_current_user
from ..models import Asset, User
from ..schemas import AssetOut

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(
    target_id: int | None = Query(default=None),
    scan_id: int | None = Query(default=None),
    asset_type: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List discovered recon, TLS, API endpoint, and dependency inventory items for the organization."""
    query = db.query(Asset).filter(Asset.organization_id == current_user.organization_id)
    if target_id is not None:
        query = query.filter(Asset.target_id == target_id)
    if scan_id is not None:
        query = query.filter(Asset.scan_id == scan_id)
    if asset_type is not None:
        query = query.filter(Asset.asset_type == asset_type)
    return query.order_by(Asset.id.desc()).limit(300).all()

