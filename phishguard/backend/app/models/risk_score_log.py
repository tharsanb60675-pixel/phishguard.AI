"""
Risk Score Log Model.
Stores fine-grained component breakdowns of the composite risk calculation:
- Phishing probability
- Zero-day anomaly score
- Social engineering score
- User risk multiplier
- Final weighted risk score
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.db.mysql import Base


class RiskScoreLog(Base):
    __tablename__ = "risk_score_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_history_id = Column(Integer, ForeignKey("scan_history.id", ondelete="CASCADE"), nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    phishing_probability = Column(Float, default=0.0, nullable=False)   # 0.0 - 1.0
    zero_day_anomaly_score = Column(Float, default=0.0, nullable=False) # 0.0 - 1.0
    social_eng_score = Column(Float, default=0.0, nullable=False)       # 0.0 - 1.0
    user_risk_modifier = Column(Float, default=1.0, nullable=False)     # e.g. 0.8 (Advanced) to 1.3 (Novice)
    final_weighted_score = Column(Float, default=0.0, nullable=False)   # 0.0 - 100.0

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan_history = relationship("ScanHistory", back_populates="risk_score_log")
    user = relationship("User", back_populates="risk_score_logs")
