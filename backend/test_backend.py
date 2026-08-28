"""
Comprehensive Automated Test Suite for PhishGuard AI Backend.
Tests Auth, Threat Scanning, SHAP Explainer, Pre-Click Check, NLP Manipulation, Simulations, and Community Feed.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.mysql import init_db
from app.db.mongodb import mongo_manager


@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_test_environment():
    await init_db()
    await mongo_manager.connect("mongodb://localhost:27017", "phishguard_test")
    yield
    await mongo_manager.close()


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_auth_register_and_login_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register
        import uuid
        test_email = f"test_lead_{uuid.uuid4().hex[:8]}@phishguard.ai"
        reg_payload = {
            "email": test_email,
            "password": "StrongPassword123!",
            "full_name": "Test Security Officer",
            "risk_profile_tier": "Intermediate"
        }
        res_reg = await client.post("/api/v1/auth/register", json=reg_payload)
        assert res_reg.status_code == 201
        data_reg = res_reg.json()
        assert "tokens" in data_reg
        access_token = data_reg["tokens"]["access_token"]
        refresh_token = data_reg["tokens"]["refresh_token"]

        # Authenticate /me with Bearer token
        headers = {"Authorization": f"Bearer {access_token}"}
        res_me = await client.get("/api/v1/auth/me", headers=headers)
        assert res_me.status_code == 200
        assert res_me.json()["email"] == test_email

        # Refresh token
        res_ref = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert res_ref.status_code == 200
        assert "access_token" in res_ref.json()


@pytest.mark.asyncio
async def test_threat_scan_and_shap_explanation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Benign scan test
        res_safe = await client.post(
            "/api/v1/scan/",
            json={"target": "https://google.com/search?q=cybersecurity", "scan_type": "url"}
        )
        assert res_safe.status_code == 200
        safe_data = res_safe.json()
        assert safe_data["verdict"] == "SAFE"
        assert safe_data["risk_score"] < 40.0

        # 2. Malicious Phishing scan test
        phish_target = "http://login-appleid-verify-account-security-alert.suspicious-token.xyz/auth"
        res_phish = await client.post(
            "/api/v1/scan/",
            json={"target": phish_target, "scan_type": "url"}
        )
        assert res_phish.status_code == 200
        phish_data = res_phish.json()
        assert phish_data["verdict"] in ["MALICIOUS", "ZERO_DAY", "SUSPICIOUS"]
        assert phish_data["risk_score"] >= 60.0
        assert "explanation" in phish_data
        assert len(phish_data["explanation"]["feature_importances"]) > 0
        assert phish_data["execution_time_ms"] > 0


@pytest.mark.asyncio
async def test_pre_click_interceptor():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/api/v1/scan/pre-click",
            params={"url": "http://paypal-verification-update-security-passcode.xyz/login"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["should_block"] is True


@pytest.mark.asyncio
async def test_nlp_social_engineering_analyzer():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        urgent_text = "URGENT NOTICE: Your account will be permanently disabled within 24 hours. Click here to verify password immediately."
        res = await client.post(
            "/api/v1/nlp/analyze",
            json={"text_content": urgent_text, "sender_context": "Security Team"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["is_social_engineering"] is True
        assert data["overall_manipulation_score"] >= 0.5


@pytest.mark.asyncio
async def test_community_threat_map_feed():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/community/threat-map")
        assert res.status_code == 200
        points = res.json()
        assert len(points) > 0
        assert "latitude" in points[0]
        assert "longitude" in points[0]
