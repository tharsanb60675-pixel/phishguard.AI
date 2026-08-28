"""
Pydantic Schemas for Real-Time QR Threat Detection & Device Pairing.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class BoundingBoxSchema(BaseModel):
    x: float = 0.0
    y: float = 0.0
    width: float = 0.0
    height: float = 0.0


class QRAnalyzeRequest(BaseModel):
    payload: str = Field(..., description="Decoded QR string payload (URL, text, etc.)")
    page_url: Optional[str] = Field(None, description="URL of the webpage where QR appeared")
    page_title: Optional[str] = Field(None, description="Title of the active webpage")
    bounding_box: Optional[BoundingBoxSchema] = None
    scan_source: str = Field("browser-extension", description="Source of scan (e.g. shortcut, manual, extension)")
    browser: str = Field("Chrome", description="Browser client name")
    device: str = Field("Desktop / Laptop", description="Client device description")


class QRAnalyzeResponse(BaseModel):
    scan_id: int
    payload: str
    qr_type: str
    domain: Optional[str] = None
    threat_score: float
    severity: str
    verdict: Optional[str] = "SAFE"
    classification: str
    confidence: float
    confidence_level: Optional[str] = "HIGH"
    authenticity: Optional[str] = "UNVERIFIED"
    authenticity_reason: Optional[str] = None
    what_will_happen: Optional[str] = None
    checks: Optional[List[Dict[str, Any]]] = None
    analysis_reasons: List[str]
    action_text: Optional[str] = "PROCEED"
    action_type: Optional[str] = "proceed"
    is_blocked: bool
    bounding_box: Optional[Dict[str, Any]] = None
    page_url: Optional[str] = None
    page_title: Optional[str] = None
    timestamp: datetime
    indicators: Optional[Dict[str, Any]] = None


class DetectedQRCodeItem(BaseModel):
    payload: str
    type: str
    boundingBox: Optional[Dict[str, Any]] = None
    confidence: float = 0.95
    analysis: QRAnalyzeResponse


class QRImageScanRequest(BaseModel):
    image_base64: str = Field(..., description="Base64 encoded screenshot of the active browser tab")
    page_url: Optional[str] = None
    page_title: Optional[str] = None
    scan_source: str = "shortcut"


class QRImageScanResponse(BaseModel):
    detected: bool
    count: int
    codes: List[DetectedQRCodeItem]
    scan_timestamp: datetime


class QRUrlAnalyzeRequest(BaseModel):
    decoded_payload: str
    client_detected_type: Optional[str] = "url"
    page_url: Optional[str] = None
    page_title: Optional[str] = None


class QRUrlAnalyzeResponse(BaseModel):
    scan_id: Optional[int] = None
    decoded_payload: str
    detected_type: str
    parsed_domain: Optional[str] = None
    threat_score: float
    severity: str
    verdict: str
    authenticity: str
    authenticity_reason: str
    what_will_happen: str
    confidence: str
    security_reason: str
    recommended_action: str
    action_text: str
    action_type: str
    is_blocked: bool
    security_analysis: Optional[Dict[str, Any]] = None
    checks: Optional[List[Dict[str, Any]]] = None
    reasons: Optional[List[str]] = None


class QRScanSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int]
    timestamp: datetime
    page_url: Optional[str]
    page_title: Optional[str]
    qr_payload: str
    qr_type: str
    domain: Optional[str]
    threat_score: float
    severity: str
    classification: str
    analysis_reasons: List[str]
    is_blocked: bool
    browser: str
    device: str
    scan_source: str


class QRBlockRequest(BaseModel):
    scan_id: Optional[int] = None
    target: str
    is_blocked: bool = True


class PairingRequestResponse(BaseModel):
    pairing_code: str
    expires_in_seconds: int
    pairing_qr_payload: str
    token: str


class PairingConfirmRequest(BaseModel):
    pairing_code: str
    device_name: str = "Android Companion"
    device_id: str
    device_type: str = "android"


class PairedDeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_name: str
    device_type: str
    device_id: str
    is_active: bool
    notification_enabled: bool
    min_notify_severity: str
    last_seen: datetime
    created_at: datetime

