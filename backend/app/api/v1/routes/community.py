"""
Community Intelligence & Scam Reports Routes (/api/v1/community).
"""

from typing import List, Any
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.mysql import get_db
from app.db.mongodb import get_mongo_db
from app.models.user import User
from app.schemas.community import (
    ScamReportCreate,
    ScamReportResponse,
    CommunityThreatMapPoint
)
from app.services.community_service import community_service
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/community", tags=["Community Intelligence"])


@router.post("/report", response_model=ScamReportResponse, status_code=status.HTTP_201_CREATED)
async def submit_scam_report(
    req: ScamReportCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    mongo_db: Any = Depends(get_mongo_db)
):
    """Submit a community scam report to protect the broader network."""
    return await community_service.create_report(
        db=db,
        mongo_db=mongo_db,
        user=current_user,
        req=req
    )


@router.get("/reports", response_model=List[ScamReportResponse])
async def list_recent_reports(
    limit: int = 25,
    db: AsyncSession = Depends(get_db)
):
    """List recent crowdsourced scam reports."""
    return await community_service.get_recent_reports(db=db, limit=limit)


@router.get("/threat-map", response_model=List[CommunityThreatMapPoint])
async def get_threat_map_points(
    db: AsyncSession = Depends(get_db)
):
    """Retrieve geolocated threat markers for Leaflet.js interactive threat density map."""
    return await community_service.get_threat_map_points(db=db)
