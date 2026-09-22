"""
Pydantic v2 schemas for Authentication, Registration, and User Profile.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import re

class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[^A-Za-z0-9]', v):
            raise ValueError('Password must contain at least one special character')
        return v

class EmailRequest(BaseModel):
    email: EmailStr

class SetupPasswordRequest(BaseModel):
    password: str = Field(..., min_length=8)

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[^A-Za-z0-9]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


class OTPResendRequest(BaseModel):
    email: EmailStr


class ProfileCompleteRequest(BaseModel):
    full_name: str = Field(..., min_length=2)
    risk_profile_tier: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str]
    email_verified: bool
    profile_completed: bool
    risk_profile_tier: str
    vulnerability_index: float
    is_active: bool
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserUpdateTierRequest(BaseModel):
    risk_profile_tier: str
    vulnerability_index: Optional[float] = Field(None, ge=0.0, le=1.0)
