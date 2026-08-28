"""
Scan History & Audit Ledger Routes (/api/v1/history).
Strictly isolated to the authenticated user's records.
"""

from typing import List, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from app.db.mysql import get_db
from app.db.mongodb import get_mongo_db
from app.models.user import User
from app.models.scan_history import ScanHistory
from app.models.risk_score_log import RiskScoreLog
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/history", tags=["Threat History"])


@router.get("/scans", response_model=List[dict])
async def get_user_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve paginated threat scan history for the authenticated user only."""
    offset = (page - 1) * limit
    result = await db.execute(
        select(ScanHistory)
        .where(ScanHistory.user_id == current_user.id)
        .order_by(desc(ScanHistory.scanned_at))
        .offset(offset)
        .limit(limit)
    )
    scans = result.scalars().all()
    
    return [
        {
            "id": s.id,
            "target": s.target_identifier,
            "scan_type": s.scan_type,
            "verdict": s.verdict,
            "risk_score": s.risk_score,
            "scanned_at": s.scanned_at,
            "mongo_raw_id": s.mongo_raw_id,
            "mongo_shap_id": s.mongo_shap_id
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}", response_model=dict)
async def get_scan_details(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    mongo_db: Any = Depends(get_mongo_db)
):
    """Retrieve full deep scan breakdown combining MySQL ledger + MongoDB SHAP explanation."""
    # Ensure user ownership
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or access denied."
        )

    # Fetch risk score log breakdown
    score_res = await db.execute(
        select(RiskScoreLog).where(RiskScoreLog.scan_history_id == scan.id)
    )
    score_log = score_res.scalar_one_or_none()

    # Fetch MongoDB SHAP explanation document
    shap_doc = None
    if scan.mongo_shap_id:
        try:
            shap_doc = await mongo_db["shap_explanations"].find_one({"_id": scan.mongo_shap_id})
        except Exception:
            pass

    return {
        "id": scan.id,
        "target": scan.target_identifier,
        "scan_type": scan.scan_type,
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "scanned_at": scan.scanned_at,
        "breakdown": {
            "phishing_probability": score_log.phishing_probability if score_log else 0.0,
            "zero_day_anomaly_score": score_log.zero_day_anomaly_score if score_log else 0.0,
            "social_engineering_score": score_log.social_eng_score if score_log else 0.0,
            "user_risk_modifier": score_log.user_risk_modifier if score_log else 1.0,
            "final_weighted_score": score_log.final_weighted_score if score_log else scan.risk_score
        } if score_log else None,
        "shap_explanation": shap_doc.get("explanation") if shap_doc else None
    }
