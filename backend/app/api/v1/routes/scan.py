"""
Threat Scan Routes (/api/v1/scan).
Executes live threat scans, zero-day anomaly checks, SHAP explanations, and pre-click checks.
"""

from typing import Any
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.mysql import get_db
from app.db.mongodb import get_mongo_db
from app.models.user import User
from app.schemas.scan import (
    ThreatScanRequest,
    ThreatScanResponse,
    PreClickCheckResponse
)
from app.services.scan_service import scan_service
from app.core.dependencies import get_current_user, get_optional_user

from app.utils.url_validator import validate_strict_url

router = APIRouter(prefix="/scan", tags=["Threat Scanning"])


@router.post("/", response_model=ThreatScanResponse, status_code=status.HTTP_200_OK)
async def perform_threat_scan(
    req: ThreatScanRequest,
    current_user: User = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
    mongo_db: Any = Depends(get_mongo_db)
):
    """
    Execute end-to-end multi-model threat analysis on target:
    - Strictly validates that target is a valid HTTP/HTTPS URL
    - Extracts lexical, structural, and domain features
    - Evaluates Phishing Classifier & Zero-Day Isolation Forest
    - Computes user-personalized risk score
    - Generates SHAP explanation with Plain-Language breakdown
    - Persists audit ledger to SQLite and raw document to MongoDB
    """
    if req.scan_type == "url":
        is_valid, err_msg = validate_strict_url(req.target)
        if not is_valid:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="It is not a valid URL. Please enter a complete URL starting with http:// or https://"
            )

    return await scan_service.execute_scan(
        db=db,
        mongo_db=mongo_db,
        user=current_user,
        req=req
    )


@router.get("/pre-click", response_model=PreClickCheckResponse)
async def check_pre_click(
    url: str,
    tier: str = "Novice"
):
    """
    Lightweight, high-speed pre-navigation verification endpoint.
    Used by browser extensions and pre-click interceptor modals before visiting outbound links.
    """
    return await scan_service.pre_click_check(url=url, user_tier=tier)
