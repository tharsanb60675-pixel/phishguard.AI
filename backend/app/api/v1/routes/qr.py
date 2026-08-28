"""
Real-Time QR Threat Detection & Analysis Routes (/api/v1/qr).
Handles browser extension telemetry, QR payload decoding, multi-model threat scoring,
database persistence, and live real-time Android push.
"""

import json
import base64
import io
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, delete

from app.db.mysql import get_db
from app.models.user import User
from app.models.qr_scan import QRScan, ThreatAnalysis, QRSeverity, QRClassification
from app.models.scan_history import ScanHistory
from app.schemas.qr_threat import (
    QRAnalyzeRequest,
    QRAnalyzeResponse,
    QRImageScanRequest,
    QRImageScanResponse,
    DetectedQRCodeItem,
    QRScanSummaryResponse,
    QRBlockRequest,
    QRUrlAnalyzeRequest,
    QRUrlAnalyzeResponse
)
from app.services.qr_threat_service import qr_threat_engine
from app.services.device_sync_service import device_sync_manager
from app.core.dependencies import get_optional_user, get_current_user

router = APIRouter(prefix="/qr", tags=["Real-Time QR Threat Shield"])


@router.post("/analyze", response_model=QRAnalyzeResponse, status_code=status.HTTP_200_OK)
async def analyze_qr_code(
    req: QRAnalyzeRequest,
    current_user: User = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Analyze decoded QR code payload:
    1. Runs full heuristics, brand spoofing, and ML threat evaluation
    2. Persists scan record to SQLite 'qr_scans' and 'threat_analysis' tables
    3. Broadcasts real-time alert to paired Android companion devices and live web dashboard
    """
    analysis = qr_threat_engine.analyze_payload(req.payload, page_url=req.page_url)
    
    bounding_box_str = json.dumps(req.bounding_box.model_dump()) if req.bounding_box else None
    analysis_reasons_str = json.dumps(analysis["reasons"])

    # 1. Insert into qr_scans table
    qr_record = QRScan(
        user_id=current_user.id if current_user else None,
        page_url=req.page_url[:1000] if req.page_url else None,
        page_title=req.page_title[:500] if req.page_title else None,
        qr_payload=req.payload,
        qr_type=analysis["qrType"],
        domain=analysis["parsedDomain"],
        threat_score=analysis["threatScore"],
        severity=analysis["severity"],
        classification=analysis["classification"],
        confidence=analysis["confidence"],
        analysis_reasons=analysis_reasons_str,
        bounding_box=bounding_box_str,
        is_blocked=analysis["isBlocked"],
        browser=req.browser,
        device=req.device,
        scan_source=req.scan_source,
        timestamp=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc)
    )

    db.add(qr_record)
    await db.flush()  # Obtain qr_record.id

    # 2. Insert into threat_analysis table (cleaning any orphan with same qr_scan_id)
    await db.execute(delete(ThreatAnalysis).where(ThreatAnalysis.qr_scan_id == qr_record.id))
    ind = analysis["indicators"]
    threat_record = ThreatAnalysis(
        qr_scan_id=qr_record.id,
        is_https=ind["is_https"],
        is_ip_address=ind["is_ip_address"],
        is_shortened=ind["is_shortened"],
        has_suspicious_tld=ind["has_suspicious_tld"],
        has_punycode=ind["has_punycode"],
        has_login_keywords=ind["has_login_keywords"],
        has_banking_keywords=ind["has_banking_keywords"],
        has_crypto_keywords=ind["has_crypto_keywords"],
        domain_reputation_score=ind["domain_reputation_score"],
        raw_indicators=json.dumps(ind),
        created_at=datetime.now(timezone.utc)
    )
    db.add(threat_record)

    await db.commit()
    await db.refresh(qr_record)

    # 3. Construct response object
    resp = QRAnalyzeResponse(
        scan_id=qr_record.id,
        payload=qr_record.qr_payload,
        qr_type=qr_record.qr_type,
        domain=qr_record.domain,
        threat_score=qr_record.threat_score,
        severity=qr_record.severity,
        verdict=analysis["verdict"],
        classification=qr_record.classification,
        confidence=qr_record.confidence,
        confidence_level=analysis["confidenceLevel"],
        authenticity=analysis["authenticity"],
        authenticity_reason=analysis["authenticityReason"],
        what_will_happen=analysis["whatWillHappen"],
        checks=analysis["checks"],
        analysis_reasons=analysis["reasons"],
        action_text=analysis["actionText"],
        action_type=analysis["actionType"],
        is_blocked=qr_record.is_blocked,
        bounding_box=req.bounding_box.model_dump() if req.bounding_box else None,
        page_url=qr_record.page_url,
        page_title=qr_record.page_title,
        timestamp=qr_record.timestamp,
        indicators=ind
    )

    # 4. Real-time push to Android companion app & dashboard
    if current_user:
        await device_sync_manager.broadcast_scan(current_user.id, resp.model_dump(mode="json"))

    return resp


from pydantic import BaseModel

class UniversalScanRequest(BaseModel):
    text: Optional[str] = ""
    qr_codes: Optional[List[Dict[str, Any]]] = []
    barcodes: Optional[List[Dict[str, Any]]] = []
    page_url: Optional[str] = ""
    page_title: Optional[str] = ""

@router.post("/analyze-universal", status_code=status.HTTP_200_OK)
async def analyze_universal_scan(
    req: UniversalScanRequest,
    current_user: User = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Essential Key Smart Region Scanner Endpoint (Ctrl + Shift + Q):
    1. Classifies target content (QR Code, Barcode, Valid URL, Text / Message, Mixed Content, or Nothing Supported)
    2. Runs strict type-specific security verification
    3. Broadcasts alert to paired Android companion & Live Dashboard
    """
    result = qr_threat_engine.analyze_universal(
        text=req.text or "",
        qr_codes=req.qr_codes or [],
        barcodes=req.barcodes or [],
        page_url=req.page_url or "",
        page_title=req.page_title or ""
    )
    
    if current_user:
        await device_sync_manager.broadcast_scan(current_user.id, {
            "event_type": "UNIVERSAL_SCAN_COMPLETED",
            "scan": result
        })
    
    return result



@router.post("/analyze-url", response_model=QRUrlAnalyzeResponse, status_code=status.HTTP_200_OK)
async def analyze_qr_url(
    req: QRUrlAnalyzeRequest,
    current_user: User = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Analyze decoded payload from QR camera scanner, image upload, or clipboard.
    Evaluates threat heuristics, saves audit record in scan_history (if user authenticated),
    and returns full actionable verification metadata.
    """
    analysis = qr_threat_engine.analyze_payload(req.decoded_payload, page_url=req.page_url)
    
    is_url = analysis["qrType"] in ("URL", "HTTPS URL", "HTTP URL", "Social-Media Link", "Cryptocurrency / Payment URI")
    
    # Construct security_analysis sub-dict for URL payloads
    security_analysis = None
    if is_url:
        security_analysis = {
            "verdict": "SAFE" if analysis["threatScore"] < 20 else "MALICIOUS" if analysis["threatScore"] >= 80 else "SUSPICIOUS",
            "risk_score": analysis["threatScore"],
            "risk_category": analysis["classification"],
            "confidence": analysis["confidence"],
            "domain": analysis["parsedDomain"],
            "authenticity": analysis["authenticity"],
            "what_will_happen": analysis["whatWillHappen"],
            "is_blocked": analysis["isBlocked"],
            "checks": analysis["checks"]
        }

    # If authenticated, persist audit to ScanHistory
    if current_user and is_url:
        try:
            verdict_val = "SAFE" if analysis["threatScore"] < 20 else "MALICIOUS" if analysis["threatScore"] >= 80 else "SUSPICIOUS"
            scan_hist = ScanHistory(
                user_id=current_user.id,
                scan_type="qr_url",
                target_identifier=req.decoded_payload[:500],
                verdict=verdict_val,
                risk_score=analysis["threatScore"],
                scanned_at=datetime.now(timezone.utc)
            )
            db.add(scan_hist)
            await db.commit()
        except Exception:
            pass

    return QRUrlAnalyzeResponse(
        scan_id=None,
        decoded_payload=req.decoded_payload,
        detected_type="url" if is_url else "text",
        parsed_domain=analysis["parsedDomain"],
        threat_score=analysis["threatScore"],
        severity=analysis["severity"],
        verdict=analysis["verdict"],
        authenticity=analysis["authenticity"],
        authenticity_reason=analysis["authenticityReason"],
        what_will_happen=analysis["whatWillHappen"],
        confidence=analysis["confidenceLevel"],
        security_reason=analysis["reasons"][0] if analysis["reasons"] else "Analysis completed.",
        recommended_action=f"Action: {analysis['actionText']}. {analysis['whatWillHappen']}",
        action_text=analysis["actionText"],
        action_type=analysis["actionType"],
        is_blocked=analysis["isBlocked"],
        security_analysis=security_analysis,
        checks=analysis["checks"],
        reasons=analysis["reasons"]
    )



@router.get("/scans", response_model=List[QRScanSummaryResponse])
async def list_qr_scans(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve paginated QR threat scan telemetry for the authenticated user."""
    result = await db.execute(
        select(QRScan)
        .where(QRScan.user_id == current_user.id)
        .order_by(desc(QRScan.timestamp))
        .offset(offset)
        .limit(limit)
    )
    scans = result.scalars().all()

    output = []
    for s in scans:
        try:
            reasons = json.loads(s.analysis_reasons)
        except Exception:
            reasons = [s.analysis_reasons]
        
        output.append(
            QRScanSummaryResponse(
                id=s.id,
                user_id=s.user_id,
                timestamp=s.timestamp,
                page_url=s.page_url,
                page_title=s.page_title,
                qr_payload=s.qr_payload,
                qr_type=s.qr_type,
                domain=s.domain,
                threat_score=s.threat_score,
                severity=s.severity,
                classification=s.classification,
                analysis_reasons=reasons,
                is_blocked=s.is_blocked,
                browser=s.browser,
                device=s.device,
                scan_source=s.scan_source
            )
        )
    return output


@router.get("/scans/{scan_id}", response_model=dict)
async def get_qr_scan_detail(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve full deep scan breakdown combining qr_scans + threat_analysis tables."""
    result = await db.execute(
        select(QRScan).where(QRScan.id == scan_id, QRScan.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="QR scan record not found or access denied.")

    t_res = await db.execute(
        select(ThreatAnalysis).where(ThreatAnalysis.qr_scan_id == scan.id)
    )
    threat = t_res.scalar_one_or_none()

    try:
        reasons = json.loads(scan.analysis_reasons)
    except Exception:
        reasons = [scan.analysis_reasons]

    try:
        bbox = json.loads(scan.bounding_box) if scan.bounding_box else None
    except Exception:
        bbox = None

    return {
        "scan_id": scan.id,
        "payload": scan.qr_payload,
        "qr_type": scan.qr_type,
        "domain": scan.domain,
        "threat_score": scan.threat_score,
        "severity": scan.severity,
        "classification": scan.classification,
        "confidence": scan.confidence,
        "analysis_reasons": reasons,
        "bounding_box": bbox,
        "is_blocked": scan.is_blocked,
        "page_url": scan.page_url,
        "page_title": scan.page_title,
        "browser": scan.browser,
        "device": scan.device,
        "scan_source": scan.scan_source,
        "timestamp": scan.timestamp,
        "technical_indicators": json.loads(threat.raw_indicators) if threat and threat.raw_indicators else {}
    }


@router.delete("/scans", response_model=dict)
async def delete_all_qr_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Privacy-First API: Purge all QR scan records and technical analysis for user."""
    # Find user scan IDs first
    scan_ids_res = await db.execute(
        select(QRScan.id).where(QRScan.user_id == current_user.id)
    )
    user_scan_ids = scan_ids_res.scalars().all()
    if user_scan_ids:
        await db.execute(
            delete(ThreatAnalysis).where(ThreatAnalysis.qr_scan_id.in_(user_scan_ids))
        )
    await db.execute(
        delete(QRScan).where(QRScan.user_id == current_user.id)
    )
    await db.commit()
    return {"status": "success", "message": "All QR scan history has been securely wiped."}


@router.post("/block", response_model=dict)
async def toggle_block_status(
    req: QRBlockRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Manually update blocking rule for a QR destination domain."""
    if req.scan_id:
        result = await db.execute(
            select(QRScan).where(QRScan.id == req.scan_id, QRScan.user_id == current_user.id)
        )
        scan = result.scalar_one_or_none()
        if scan:
            scan.is_blocked = req.is_blocked
            await db.commit()
    
    return {
        "status": "success",
        "target": req.target,
        "is_blocked": req.is_blocked,
        "message": f"Target {'blocked' if req.is_blocked else 'allowed'} successfully."
    }
