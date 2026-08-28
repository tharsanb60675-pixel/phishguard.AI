"""
Social Engineering NLP Analysis Routes (/api/v1/nlp).
"""

from fastapi import APIRouter
from app.schemas.nlp import NLPAnalyzeRequest, NLPAnalyzeResponse
from app.ml.social_engineering_nlp import social_engineering_analyzer

router = APIRouter(prefix="/nlp", tags=["Social Engineering NLP"])


@router.post("/analyze", response_model=NLPAnalyzeResponse)
async def analyze_social_engineering(req: NLPAnalyzeRequest):
    """
    Analyze message/email text for psychological manipulation tactics:
    - Urgency & Pressure
    - Authority & Impersonation
    - Fear & Intimidation
    - Scarcity & Baiting
    - Credential Harvesting Triggers
    """
    return social_engineering_analyzer.analyze(
        text_content=req.text_content,
        sender_context=req.sender_context or ""
    )
