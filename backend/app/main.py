"""
PhishGuard AI - Main FastAPI Application Entrypoint.
Personalized Threat Detection, Explainable AI (SHAP), and Adaptive Cyber Defense Platform.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.db.mysql import init_db
from app.db.mongodb import mongo_manager
from app.api.v1.api_router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB models & MongoDB connector
    print(f"[DATABASE] Connected to SQLite database file: {settings.DATABASE_URL}")
    await init_db()
    await mongo_manager.connect(settings.MONGODB_URL, settings.MONGODB_DB_NAME)
    yield
    # Shutdown
    await mongo_manager.close()


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Personalized Cybersecurity & Phishing Threat Detection Platform with Explainable AI (SHAP)",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,  # Permits local dev frontends securely
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["System"])
async def health_check():
    """System liveness and readiness probe."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": "1.0.0",
        "mongo_fallback": mongo_manager.is_fallback
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "Welcome to PhishGuard AI API",
        "docs": "/docs",
        "version": "v1"
    }
