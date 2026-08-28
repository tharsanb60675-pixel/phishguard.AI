"""
Scam Report and Community Threat Models.
Handles crowdsourced community threat submissions, moderation, geolocation, and intelligence feeds.
"""

from datetime import datetime, timezone
import enum
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.db.mysql import Base


class ScamCategory(str, enum.Enum):
    PHISHING = "phishing"
    FAKE_STORE = "fake_store"
    CRYPTO_SCAM = "crypto_scam"
    IMPERSONATION = "impersonation"
    TECH_SUPPORT = "tech_support"
    JOB_OFFER = "job_offer"
    LOTTERY = "lottery"
    OTHER = "other"


class ReportStatus(str, enum.Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class ScamReport(Base):
    __tablename__ = "scam_reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    scam_category = Column(String(50), default=ScamCategory.PHISHING.value, nullable=False)
    reported_target = Column(String(500), nullable=False)  # URL, phone number, email address, or handle
    description = Column(Text, nullable=False)
    
    # Geolocation fields for Community Threat Map
    location_name = Column(String(255), default="Global / Online", nullable=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    status = Column(String(50), default=ReportStatus.VERIFIED.value, nullable=False)
    upvotes = Column(Integer, default=1, nullable=False)
    mongo_report_id = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = relationship("User", back_populates="scam_reports")


class CommunityThreat(Base):
    __tablename__ = "community_threats"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    threat_indicator = Column(String(500), unique=True, index=True, nullable=False) # e.g. domain or pattern
    category = Column(String(50), nullable=False)
    severity = Column(Integer, default=3, nullable=False) # 1 (Low) to 5 (Critical)
    reports_count = Column(Integer, default=1, nullable=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    last_reported_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
