"""
AI Phishing Simulation & Adaptive Learning Routes (/api/v1/simulations).
"""

from typing import List, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.mysql import get_db
from app.db.mongodb import get_mongo_db
from app.models.user import User
from app.schemas.simulation import (
    SimulationScenario,
    SimulationActionRequest,
    SimulationActionResponse
)
from app.services.simulation_service import simulation_service
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/simulations", tags=["AI Simulations"])


@router.get("/scenarios", response_model=List[SimulationScenario])
async def get_simulation_scenarios(
    current_user: User = Depends(get_current_user)
):
    """Retrieve simulated attack scenarios tailored to user risk tier."""
    return simulation_service.get_scenarios_for_user(current_user.risk_profile_tier)


@router.post("/action", response_model=SimulationActionResponse)
async def submit_simulation_action(
    req: SimulationActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    mongo_db: Any = Depends(get_mongo_db)
):
    """
    Process user response to simulated attack (REPORTED vs CLICKED vs COMPROMISED)
    and dynamically update vulnerability index.
    """
    return await simulation_service.process_user_action(
        db=db,
        mongo_db=mongo_db,
        user=current_user,
        req=req
    )
