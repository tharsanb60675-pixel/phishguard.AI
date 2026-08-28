from app.db.mysql import Base
from app.models.user import User, RiskTier
from app.models.scan_history import ScanHistory, ScanType, ScanVerdict
from app.models.risk_score_log import RiskScoreLog
from app.models.scam_report import ScamReport, CommunityThreat, ScamCategory, ReportStatus

from app.models.qr_scan import QRScan, ThreatAnalysis, PairedDevice, QRSeverity, QRClassification


__all__ = [
    "Base",
    "User",
    "RiskTier",
    "ScanHistory",
    "ScanType",
    "ScanVerdict",
    "RiskScoreLog",
    "ScamReport",
    "CommunityThreat",
    "ScamCategory",
    "ReportStatus",
    "QRScan",
    "ThreatAnalysis",
    "PairedDevice",
    "QRSeverity",
    "QRClassification"
]
