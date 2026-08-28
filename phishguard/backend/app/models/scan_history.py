"""
Scan History Model.
Tracks metadata of every threat scan submitted by users, linking to MongoDB raw data & SHAP explanations.
"""

from datetime import datetime, timezone
import enum
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.db.mysql import Base


class ScanType(str, enum.Enum):
    URL = "url"
    TEXT = "text"
    EMAIL = "email"
    IMAGE = "image"
    FILE = "file"


class ScanVerdict(str, enum.Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    ZERO_DAY = "ZERO_DAY"


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    scan_type = Column(String(50), default=ScanType.URL.value, nullable=False)
    target_identifier = Column(String(500), nullable=False)  # Scanned URL or summarized text snippet
    verdict = Column(String(50), default=ScanVerdict.SAFE.value, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)  # Composite score (0 - 100)
    
    # MongoDB document IDs for raw payload & SHAP analysis
    mongo_raw_id = Column(String(100), nullable=True)
    mongo_shap_id = Column(String(100), nullable=True)
    
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = relationship("User", back_populates="scan_history")
    risk_score_log = relationship("RiskScoreLog", back_populates="scan_history", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_user_scanned_at", "user_id", "scanned_at"),
    )
