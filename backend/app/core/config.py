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

    # Relational Database (Supports MySQL & SQLite async & PostgreSQL)
    DATABASE_URL: str = ""

    def __init__(self, **values):
        super().__init__(**values)
        if not self.DATABASE_URL or "phishguard.db" in self.DATABASE_URL or self.DATABASE_URL.startswith("sqlite"):
            # Resolve absolute path to backend/phishguard.db
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(backend_dir, "phishguard.db").replace("\\", "/")
            self.DATABASE_URL = f"sqlite+aiosqlite:///{db_path}"
        elif self.DATABASE_URL.startswith("postgres://"):
            self.DATABASE_URL = self.DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
        elif self.DATABASE_URL.startswith("postgresql://") and not self.DATABASE_URL.startswith("postgresql+asyncpg://"):
            self.DATABASE_URL = self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif self.DATABASE_URL.startswith("mysql://") and not self.DATABASE_URL.startswith("mysql+aiomysql://"):
            self.DATABASE_URL = self.DATABASE_URL.replace("mysql://", "mysql+aiomysql://", 1)

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
    CORS_ORIGINS: str = "*"
    CORS_ORIGIN_REGEX: str = r"^https:\/\/.*\.vercel\.app$"
    FRONTEND_URL: str = ""

    @property
    def cors_origin_list(self) -> List[str]:
        origins = []
        if self.CORS_ORIGINS and self.CORS_ORIGINS.strip() != "*":
            origins.extend([o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()])
        if self.FRONTEND_URL and self.FRONTEND_URL.strip():
            origins.append(self.FRONTEND_URL.strip().rstrip("/"))
        return origins

    @property
    def effective_openai_key(self) -> str:
        return self.OPENAI_API_KEY or self.AI_API_KEY or os.getenv("OPENAI_API_KEY", "")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
