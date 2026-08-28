"""
User Model for relational database (MySQL / SQLite).
Stores identity, authentication hashes, and adaptive risk profile tier.
"""

from datetime import datetime, timezone
import enum
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Enum
from sqlalchemy.orm import relationship
from app.db.mysql import Base


class RiskTier(str, enum.Enum):
    NOVICE = "Novice"
    INTERMEDIATE = "Intermediate"
    ADVANCED = "Advanced"
    HIGH_RISK = "High-Risk"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    
    email_verified = Column(Boolean, default=False, nullable=False)
    profile_completed = Column(Boolean, default=False, nullable=False)
    
    # Adaptive Cybersecurity Profile attributes
    risk_profile_tier = Column(String(50), default=RiskTier.NOVICE.value, nullable=False)
    vulnerability_index = Column(Float, default=0.5, nullable=False)  # 0.0 (Secure) to 1.0 (Highly Vulnerable)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan_history = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")
    scam_reports = relationship("ScamReport", back_populates="user", cascade="all, delete-orphan")
    risk_score_logs = relationship("RiskScoreLog", back_populates="user", cascade="all, delete-orphan")
    qr_scans = relationship("QRScan", back_populates="user", cascade="all, delete-orphan")
    paired_devices = relationship("PairedDevice", back_populates="user", cascade="all, delete-orphan")


class OTPVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, index=True, nullable=False)
    otp_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    attempt_count = Column(Integer, default=0, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
