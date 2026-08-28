"""
Pydantic v2 schemas for Threat Scanning, Risk Scoring, and Explanations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatScanRequest(BaseModel):
    target: str = Field(..., description="Target URL, domain, text message, or email body")
    scan_type: str = Field(default="url", description="Scan type: url, text, email, image")
    pre_click: Optional[bool] = Field(default=False, description="Flag indicating pre-click interceptor check")


class FeatureImportanceItem(BaseModel):
    feature: str
    value: Any
    shap_value: float
    impact: str  # CRITICAL_RISK | HIGH_RISK | MEDIUM_RISK | LOW_RISK | BENIGN_INDICATOR
    human_label: str


class ThreatExplanation(BaseModel):
    base_value: float
    prediction_score: float
    feature_importances: List[FeatureImportanceItem]
    personalized_explanation: str
    user_understanding_level: str
    actionable_advice: str
    remediation_steps: List[str]


class ThreatScoreBreakdown(BaseModel):
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    zero_day_anomaly_score: float = Field(..., ge=0.0, le=1.0)
    social_engineering_score: float = Field(..., ge=0.0, le=1.0)
    user_risk_modifier: float
    final_weighted_score: float = Field(..., ge=0.0, le=100.0)


class ThreatScanResponse(BaseModel):
    scan_id: int
    target: str
    scan_type: str
    verdict: str  # SAFE | SUSPICIOUS | MALICIOUS | ZERO_DAY
    risk_score: float
    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    breakdown: ThreatScoreBreakdown
    explanation: ThreatExplanation
    extracted_features: Dict[str, Any]
    mongo_raw_id: Optional[str] = None
    mongo_shap_id: Optional[str] = None
    scanned_at: datetime
    execution_time_ms: float


class PreClickCheckResponse(BaseModel):
    url: str
    verdict: str
    risk_score: float
    should_block: bool
    reason: str
    explanation_summary: str
