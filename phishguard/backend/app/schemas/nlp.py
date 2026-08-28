"""
Social Engineering NLP Schemas.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class NLPAnalyzeRequest(BaseModel):
    text_content: str = Field(..., min_length=3)
    sender_context: Optional[str] = Field(default="")


class TacticScore(BaseModel):
    tactic: str
    score: float
    detected_phrases: List[str]
    description: str


class NLPAnalyzeResponse(BaseModel):
    overall_manipulation_score: float
    threat_category: str
    is_social_engineering: bool
    tactics_breakdown: List[TacticScore]
    summary_analysis: str
    remediation_guidance: str
