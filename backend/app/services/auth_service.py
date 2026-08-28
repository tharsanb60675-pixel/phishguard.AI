"""
Authentication & User Management Service.
Handles user registration, credential authentication, JWT token refresh, and user profile queries.
"""

from typing import Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi import HTTPException, status

from app.models.user import User, RiskTier, OTPVerification
from app.schemas.auth import UserRegisterRequest, UserLoginRequest, TokenResponse, UserResponse
from app.core.security import get_password_hash, verify_password, create_access_token, create_refresh_token, decode_token
from app.core.config import settings
from app.services.email_service import send_otp_email
from datetime import datetime, timedelta, timezone
import random
import string
from sqlalchemy import update


class AuthService:
    @staticmethod
    async def generate_and_send_otp(db: AsyncSession, user_id: int, email: str):
        otp = "".join(random.choices(string.digits, k=6))
        
        # Invalidate old OTPs
        await db.execute(update(OTPVerification).where(OTPVerification.user_id == user_id, OTPVerification.used == False).values(used=True))
        
        otp_hash = get_password_hash(otp)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        new_otp = OTPVerification(user_id=user_id, otp_hash=otp_hash, expires_at=expires_at)
        db.add(new_otp)
        await db.commit()
        
        success = send_otp_email(email, otp)
        if not success:
            return {"success": False, "message": "Unable to send verification code"}
            
        return {"success": True, "message": "Verification code sent successfully"}

    @staticmethod
    async def send_otp(db: AsyncSession, email: str) -> dict:
        result = await db.execute(select(User).where(User.email == email.lower()))
        user = result.scalar_one_or_none()
        
        if user:
            if user.password_hash != "PENDING_SETUP":
                return {"success": False, "message": "Email already registered. Please sign in."}
            else:
                return await AuthService.generate_and_send_otp(db, user.id, user.email)
                
        new_user = User(
            email=email.lower(),
            password_hash="PENDING_SETUP",
            full_name="",
            risk_profile_tier=RiskTier.NOVICE.value,
            vulnerability_index=0.5,
            is_active=True,
            is_admin=False,
            email_verified=False,
            profile_completed=False
        )

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        return await AuthService.generate_and_send_otp(db, new_user.id, new_user.email)

    @staticmethod
    async def register(db: AsyncSession, req: UserRegisterRequest) -> dict:
        result = await db.execute(select(User).where(User.email == req.email.lower()))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered. Please sign in."
            )

        new_user = User(
            email=req.email.lower(),
            password_hash=get_password_hash(req.password),
            full_name="",
            email_verified=True,  # Bypassed verification
            profile_completed=False,
            risk_profile_tier="Novice",
            vulnerability_index=0.5,
            is_active=True,
            is_admin=False
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        access_token = create_access_token(subject=new_user.id, extra_claims={"email": new_user.email, "tier": new_user.risk_profile_tier})
        refresh_token = create_refresh_token(subject=new_user.id)

        tokens = TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

        return {"status": "success", "user": new_user, "tokens": tokens}

    @staticmethod
    async def authenticate_user(db: AsyncSession, req: UserLoginRequest) -> dict:
        result = await db.execute(select(User).where(User.email == req.email.lower()))
        user = result.scalar_one_or_none()
        
        if not user or user.password_hash == "PENDING_SETUP" or not verify_password(req.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account is disabled. Please contact security admin."
            )
            
        access_token = create_access_token(subject=user.id, extra_claims={"email": user.email, "tier": user.risk_profile_tier})
        refresh_token = create_refresh_token(subject=user.id)

        tokens = TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

        return {"status": "authenticated", "user": user, "tokens": tokens}
        
    @staticmethod
    async def verify_otp(db: AsyncSession, email: str, otp: str) -> dict:
        result = await db.execute(select(User).where(User.email == email.lower()))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
            
        result = await db.execute(
            select(OTPVerification)
            .where(OTPVerification.user_id == user.id, OTPVerification.used == False)
            .order_by(OTPVerification.created_at.desc())
        )
        latest_otp = result.scalars().first()
        
        if not latest_otp:
            raise HTTPException(status_code=400, detail="No active verification code found.")
            
        expires_at = latest_otp.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Verification code expired. Request a new code.")
            
        if latest_otp.attempt_count >= 5:
            latest_otp.used = True
            await db.commit()
            raise HTTPException(status_code=400, detail="Maximum attempts exceeded. Request a new code.")
            
        if not verify_password(otp, latest_otp.otp_hash):
            latest_otp.attempt_count += 1
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid verification code.")
            
        latest_otp.used = True
        user.email_verified = True
        await db.commit()
        
        setup_token = ""
        if user.password_hash == "PENDING_SETUP":
            setup_token = create_access_token(subject=user.id, extra_claims={"scope": "setup", "email": user.email})
            
        return {"success": True, "verified": True, "setup_token": setup_token}

    @staticmethod
    async def setup_password(db: AsyncSession, user: User, password: str) -> dict:
        if user.password_hash != "PENDING_SETUP":
            raise HTTPException(status_code=400, detail="User already has a password.")
            
        user.password_hash = get_password_hash(password)
        await db.commit()
        
        access_token = create_access_token(subject=user.id, extra_claims={"email": user.email, "tier": user.risk_profile_tier})
        refresh_token = create_refresh_token(subject=user.id)

        tokens = TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

        return {"status": "authenticated", "user": user, "tokens": tokens}

    @staticmethod
    async def resend_otp(db: AsyncSession, email: str) -> dict:
        result = await db.execute(select(User).where(User.email == email.lower()))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        return await AuthService.generate_and_send_otp(db, user.id, user.email)
        
    @staticmethod
    async def complete_profile(db: AsyncSession, user: User, full_name: str, risk_profile_tier: str) -> User:
        user.full_name = full_name
        user.risk_profile_tier = risk_profile_tier
        
        if risk_profile_tier == "Advanced":
            user.vulnerability_index = 0.2
        elif risk_profile_tier == "Intermediate":
            user.vulnerability_index = 0.4
        elif risk_profile_tier == "High-Risk":
            user.vulnerability_index = 0.8
        else:
            user.vulnerability_index = 0.5
            
        user.profile_completed = True
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def refresh_access_token(db: AsyncSession, refresh_token_str: str) -> TokenResponse:
        payload = decode_token(refresh_token_str)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token."
            )

        user_id = payload.get("sub")
        result = await db.execute(select(User).where(User.id == int(user_id)))
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive."
            )

        new_access = create_access_token(subject=user.id, extra_claims={"email": user.email, "tier": user.risk_profile_tier})
        new_refresh = create_refresh_token(subject=user.id)

        return TokenResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            token_type="bearer",
            expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )


auth_service = AuthService()
