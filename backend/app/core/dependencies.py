"""
FastAPI Dependencies for Authentication, Database Sessions, and Security Guardrails.
"""

from typing import AsyncGenerator, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.core.security import decode_token
from app.db.mysql import get_db
from app.db.mongodb import get_mongo_db
from app.models.user import User

# OAuth2 scheme configured for token endpoint
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False
)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Validate Bearer JWT access token and return active User instance."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token subject payload is missing."
        )

    result = await db.execute(select(User).where(User.id == int(user_id_str)))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    return user


async def get_optional_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Return user if token is provided, or a fallback default user for public sandbox scans."""
    if token:
        try:
            return await get_current_user(token=token, db=db)
        except HTTPException:
            pass

    # Fallback sandbox guest user
    result = await db.execute(select(User).where(User.email == "demo@phishguard.ai"))
    demo_user = result.scalar_one_or_none()
    if not demo_user:
        result_first = await db.execute(select(User).order_by(User.id.asc()).limit(1))
        first_user = result_first.scalar_one_or_none()
        if first_user:
            demo_user = first_user
        else:
            demo_user = User(
                email="demo@phishguard.ai",
                password_hash="$2b$12$e8YyA2z...",
                full_name="Demo Guest",
                risk_profile_tier="Novice",
                vulnerability_index=0.5,
                is_active=True
            )
            db.add(demo_user)
            await db.commit()
            await db.refresh(demo_user)
    return demo_user
