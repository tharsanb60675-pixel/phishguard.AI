"""
AI Cyber-Safety Chatbot Routes (/api/v1/chat).
"""

from typing import Any
from fastapi import APIRouter, Depends
from app.db.mongodb import get_mongo_db
from app.models.user import User
from app.schemas.chat import ChatRequest, ChatResponse
from app.services.chat_service import chat_service
from app.core.dependencies import get_optional_user

router = APIRouter(prefix="/chat", tags=["Cyber-Safety Chatbot"])


@router.post("/", response_model=ChatResponse)
async def chat_with_cyber_assistant(
    req: ChatRequest,
    current_user: User = Depends(get_optional_user),
    mongo_db: Any = Depends(get_mongo_db)
):
    """
    Interactive cybersecurity guidance assistant with threat context awareness
    and MongoDB conversational memory.
    """
    return await chat_service.process_chat(
        mongo_db=mongo_db,
        user_id=current_user.id,
        req=req
    )
