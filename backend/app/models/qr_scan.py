"""
QR Scan and Device Pairing Models for PhishGuard AI.
Stores full telemetry, bounding boxes, threat scores, security explanations,
and paired Android companion devices.
"""

from datetime import datetime, timezone
import enum
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship
from app.db.mysql import Base


class QRSeverity(str, enum.Enum):
    SAFE = "SAFE"
    LOW_RISK = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    CRITICAL = "CRITICAL"


class QRClassification(str, enum.Enum):
    BENIGN = "BENIGN"
    PHISHING = "PHISHING"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    SUSPICIOUS_REDIRECT = "SUSPICIOUS_REDIRECT"
    PAYMENT_FRAUD = "PAYMENT_FRAUD"
    MALWARE = "MALWARE"
    UNKNOWN = "UNKNOWN"


class QRScan(Base):
    __tablename__ = "qr_scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)

    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    page_url = Column(String(1000), nullable=True)
    page_title = Column(String(500), nullable=True)
    
    qr_payload = Column(Text, nullable=False)
    qr_type = Column(String(50), default="URL", nullable=False)  # URL, text, payment, wifi, etc.
    domain = Column(String(255), nullable=True, index=True)
    
    threat_score = Column(Float, default=0.0, nullable=False)  # 0 to 100
    severity = Column(String(50), default=QRSeverity.SAFE.value, nullable=False)
    classification = Column(String(50), default=QRClassification.BENIGN.value, nullable=False)
    confidence = Column(Float, default=0.95, nullable=False)
    
    # Human-readable reasons as JSON array or text
    analysis_reasons = Column(Text, nullable=False, default="[]")
    
    # Bounding box & visual location info
    bounding_box = Column(Text, nullable=True)  # JSON string {"x": 100, "y": 200, "width": 180, "height": 180}
    
    is_blocked = Column(Boolean, default=False, nullable=False)
    browser = Column(String(100), default="Chrome", nullable=False)
    device = Column(String(100), default="Desktop / Laptop", nullable=False)
    scan_source = Column(String(50), default="browser-extension", nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = relationship("User", back_populates="qr_scans")
    threat_analysis = relationship("ThreatAnalysis", back_populates="qr_scan", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_qr_scans_user_time", "user_id", "timestamp"),
    )


class ThreatAnalysis(Base):
    __tablename__ = "threat_analysis"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    qr_scan_id = Column(Integer, ForeignKey("qr_scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    
    is_https = Column(Boolean, default=True)
    is_ip_address = Column(Boolean, default=False)
    is_shortened = Column(Boolean, default=False)
    has_suspicious_tld = Column(Boolean, default=False)
    has_punycode = Column(Boolean, default=False)
    has_login_keywords = Column(Boolean, default=False)
    has_banking_keywords = Column(Boolean, default=False)
    has_crypto_keywords = Column(Boolean, default=False)
    domain_reputation_score = Column(Float, default=0.0)
    
    raw_indicators = Column(Text, nullable=True)  # JSON dump of detailed indicators
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    qr_scan = relationship("QRScan", back_populates="threat_analysis")


class PairedDevice(Base):
    __tablename__ = "paired_devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    device_name = Column(String(255), default="Android Mobile", nullable=False)
    device_type = Column(String(50), default="android", nullable=False)
    device_id = Column(String(255), unique=True, index=True, nullable=False)
    pairing_code = Column(String(50), nullable=True)
    auth_token = Column(String(500), nullable=False)
    
    is_active = Column(Boolean, default=True, nullable=False)
    notification_enabled = Column(Boolean, default=True, nullable=False)
    min_notify_severity = Column(String(50), default="SUSPICIOUS", nullable=False)
    
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship("User", back_populates="paired_devices")
