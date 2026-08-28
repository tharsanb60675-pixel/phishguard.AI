import asyncio
import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from sqlalchemy.ext.asyncio import AsyncSession
from app.db.mysql import AsyncSessionLocal
from app.models.user import User, OTPVerification
from sqlalchemy import select
from app.core.security import verify_password
import json

async def test_db():
    print("Testing DB...")
    async with AsyncSessionLocal() as session:
        # Check users
        result = await session.execute(select(User))
        users = result.scalars().all()
        for u in users:
            print(f"User: {u.email}, Verified: {u.email_verified}, Profile Complete: {u.profile_completed}, Tier: {u.risk_profile_tier}")

if __name__ == "__main__":
    asyncio.run(test_db())
