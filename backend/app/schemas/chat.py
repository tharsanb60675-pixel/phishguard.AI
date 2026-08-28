"""
Cyber Safety AI Chatbot & AI Helpline Schemas.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: Optional[datetime] = None


class ChatHistoryItem(BaseModel):
    role: str  # "user" | "assistant" | "system"
    content: str


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str = Field(..., min_length=1)
    context_threat_url: Optional[str] = None
    scan_context: Optional[Dict[str, Any]] = None
    message_type: Optional[str] = "chat"  # "chat" | "analyze_message"
    history: Optional[List[Dict[str, str]]] = None


class ChatResponse(BaseModel):
    session_id: str
    response: str
    detected_threats: List[str] = []
    recommended_action: str = ""
    sources: List[str] = []
    threat_level: Optional[str] = None
    analysis_breakdown: Optional[Dict[str, Any]] = None
    ai_provider: Optional[str] = "openai"
    is_live_ai: bool = False
