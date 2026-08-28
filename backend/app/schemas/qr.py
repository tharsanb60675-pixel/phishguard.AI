"""
Pydantic v2 schemas for the QR Code Scanner module.
These wrap (not duplicate) the existing ThreatScanResponse.
"""

from typing import Optional
from pydantic import BaseModel, Field
from app.schemas.scan import ThreatScanResponse


class QRAnalyzeRequest(BaseModel):
    """
    Incoming request from the QR scanner frontend.
    Carries the raw decoded payload and the client-detected type.
    """
    decoded_payload: str = Field(
        ...,
        description="Raw content decoded from the QR code (URL, text, tel:, mailto:, WIFI:, etc.)"
    )
    client_detected_type: str = Field(
        default="url",
        description="Payload type as classified client-side: url | text | email | phone | wifi | other"
    )


class QRScanResult(BaseModel):
    """
    QR scanner response.
    For URL payloads, wraps the full ThreatScanResponse from the existing scan pipeline.
    For non-URL payloads, only the metadata fields are populated.
    """
    decoded_payload: str
    detected_type: str  # url | text | email | phone | wifi | other

    # URL-only fields — None for non-URL payloads
    parsed_domain: Optional[str] = None
    security_analysis: Optional[ThreatScanResponse] = None

    # Three-level check status (presentation layer — not new logic)
    level1_qr_detection: bool = True          # Always True by this point (decode succeeded)
    level2_url_validation: Optional[bool] = None  # None for non-URL types
    level3_security_analysis: Optional[bool] = None  # None for non-URL types

    # Plain-language reason (from SHAP top feature if available, else static)
    security_reason: Optional[str] = None
    recommended_action: Optional[str] = None
