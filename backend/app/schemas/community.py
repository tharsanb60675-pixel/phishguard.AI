"""
Community Threat Feed and Scam Reporting Schemas.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ScamReportCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    scam_category: str = Field(default="phishing")
    reported_target: str = Field(..., min_length=3)
    description: str = Field(..., min_length=10)
    location_name: Optional[str] = "Global / Online"
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class ScamReportResponse(BaseModel):
    id: int
    user_id: int
    title: str
    scam_category: str
    reported_target: str
    description: str
    location_name: str
    latitude: Optional[float]
    longitude: Optional[float]
    status: str
    upvotes: int
    created_at: datetime

    class Config:
        from_attributes = True


class CommunityThreatMapPoint(BaseModel):
    id: int
    title: str
    category: str
    target: str
    location: str
    latitude: float
    longitude: float
    severity: int
    report_count: int
    last_seen: datetime
