"""
AI Phishing Simulation & Adaptive Learning Schemas.
"""

from typing import List
from pydantic import BaseModel, Field


class SimulationScenario(BaseModel):
    id: str
    theme: str
    difficulty: str
    sender_name: str
    sender_email: str
    subject: str
    body_html: str
    red_flags: List[str]
    explanation: str


class SimulationActionRequest(BaseModel):
    simulation_id: str
    user_action: str
    response_time_seconds: float


class SimulationActionResponse(BaseModel):
    success: bool
    correct_action: bool
    feedback_title: str
    feedback_message: str
    previous_vulnerability_index: float
    new_vulnerability_index: float
    updated_tier: str
    uncovered_red_flags: List[str]
