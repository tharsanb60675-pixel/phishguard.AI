"""
Authentication Routes (/api/v1/auth).
Endpoints for registration, login, token refresh, and user profile management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.mysql import get_db
from app.models.user import User
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    EmailRequest,
    SetupPasswordRequest,
    TokenResponse,
    TokenRefreshRequest,
    UserResponse,
    UserUpdateTierRequest,
    OTPVerifyRequest,
    OTPResendRequest,
    ProfileCompleteRequest
)
from app.services.auth_service import auth_service
from app.core.dependencies import get_current_user
from fastapi.security import OAuth2PasswordBearer
from app.core.security import decode_token

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/send-otp", response_model=dict, status_code=status.HTTP_200_OK)
async def send_otp(
    req: EmailRequest,
    db: AsyncSession = Depends(get_db)
):
    """Handle email entry, create pending user if needed, and send OTP."""
    return await auth_service.send_otp(db, req.email)


@router.post("/register", response_model=dict)
async def register(
    req: UserRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Direct registration bypassing OTP."""
    res = await auth_service.register(db, req)
    if "user" in res:
        res["user"] = UserResponse.model_validate(res["user"]).model_dump(mode='json')
    return res

@router.post("/login", response_model=dict)
async def login(
    req: UserLoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Authenticate user with password and return tokens."""
    res = await auth_service.authenticate_user(db, req)
    if "user" in res:
        res["user"] = UserResponse.model_validate(res["user"]).model_dump(mode='json')
    return res


@router.post("/verify-otp", response_model=dict)
async def verify_otp(
    req: OTPVerifyRequest,
    db: AsyncSession = Depends(get_db)
):
    """Verify OTP and return success status."""
    return await auth_service.verify_otp(db, req.email, req.otp)

@router.post("/setup-password", response_model=dict)
async def setup_password(
    req: SetupPasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Setup password for a new user, requires setup token in auth header."""
    res = await auth_service.setup_password(db, current_user, req.password)
    if "user" in res:
        res["user"] = UserResponse.model_validate(res["user"]).model_dump()
    return res


@router.post("/resend-otp", response_model=dict)
async def resend_otp(
    req: OTPResendRequest,
    db: AsyncSession = Depends(get_db)
):
    """Resend OTP to user."""
    return await auth_service.resend_otp(db, req.email)


@router.post("/profile", response_model=UserResponse)
async def complete_profile(
    req: ProfileCompleteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Complete user profile after OTP verification."""
    return await auth_service.complete_profile(db, current_user, req.full_name, req.risk_profile_tier)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    req: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db)
):
    """Generate a new access token using a valid refresh token."""
    return await auth_service.refresh_access_token(db, req.refresh_token)


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Fetch profile, risk tier, and vulnerability index of the authenticated user."""
    return UserResponse.model_validate(current_user)


@router.put("/tier", response_model=UserResponse)
async def update_user_tier(
    req: UserUpdateTierRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Manually update user's demonstrated risk tier."""
    current_user.risk_profile_tier = req.risk_profile_tier
    if req.vulnerability_index is not None:
        current_user.vulnerability_index = req.vulnerability_index
    await db.commit()
    await db.refresh(current_user)
    return UserResponse.model_validate(current_user)


@router.post("/logout", response_model=dict)
async def logout(current_user: User = Depends(get_current_user)):
    """Log out and revoke current session."""
    return {"status": "success", "message": "Successfully logged out."}
