"""
Configuration management for PhishGuard AI using Pydantic Settings.
Loads secrets, database connection URIs, and LLM API keys from environment variables.
"""

import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"

    # Security & Authentication
    JWT_SECRET: str = "phishguard_ai_super_secret_jwt_key_2026_capstone_demo_prod"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Relational Database (Supports MySQL & SQLite async)
    DATABASE_URL: str = ""

    def __init__(self, **values):
        super().__init__(**values)
        if not self.DATABASE_URL or "phishguard.db" in self.DATABASE_URL:
            # Resolve absolute path to backend/phishguard.db
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(backend_dir, "phishguard.db").replace("\\", "/")
            self.DATABASE_URL = f"sqlite+aiosqlite:///{db_path}"

    # Document Database (MongoDB)
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "phishguard_unstructured"

    # Real LLM / AI Configuration (OpenAI / OpenAI-Compatible)
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o-mini"
    AI_PROVIDER: str = "openai"

    # Fallback / Legacy AI Key
    AI_API_KEY: str = ""
    AI_MODEL: str = "gpt-4o-mini"

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def effective_openai_key(self) -> str:
        return self.OPENAI_API_KEY or self.AI_API_KEY or os.getenv("OPENAI_API_KEY", "")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
