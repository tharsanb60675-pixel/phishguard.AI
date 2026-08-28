"""
Master API Router for v1.
Assembles all feature route controllers.
"""

from fastapi import APIRouter
from app.api.v1.routes.auth import router as auth_router
from app.api.v1.routes.scan import router as scan_router
from app.api.v1.routes.history import router as history_router
from app.api.v1.routes.nlp import router as nlp_router
from app.api.v1.routes.simulation import router as simulation_router
from app.api.v1.routes.chat import router as chat_router
from app.api.v1.routes.community import router as community_router
from app.api.v1.routes.qr import router as qr_router
from app.api.v1.routes.devices import router as devices_router


api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(scan_router)
api_router.include_router(history_router)
api_router.include_router(nlp_router)
api_router.include_router(simulation_router)
api_router.include_router(chat_router)
api_router.include_router(community_router)
api_router.include_router(qr_router)
api_router.include_router(devices_router)

