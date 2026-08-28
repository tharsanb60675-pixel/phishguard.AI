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
async def test_qr_analysis_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Register + login
        reg_res = await c.post('/api/v1/auth/register', json={
            'email': 'qrtest2@phishguard.ai', 'password': 'TestPass123!',
            'full_name': 'QR Tester', 'risk_profile_tier': 'Intermediate'
        })
        
        login = await c.post('/api/v1/auth/login', json={
            'email': 'qrtest2@phishguard.ai', 'password': 'TestPass123!'
        })
        token = login.json()['tokens']['access_token']
        H = {'Authorization': f'Bearer {token}'}

        # TEST 1: Phishing URL
        r1 = await c.post('/api/v1/qr/analyze-url', headers=H, json={
            'decoded_payload': 'https://login-appleid-verify-token.account-security-alert.xyz/auth',
            'client_detected_type': 'url'
        })
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["detected_type"] == "url"
        assert d1["security_analysis"] is not None
        assert d1["security_analysis"]["verdict"] in ["MALICIOUS", "ZERO_DAY", "SUSPICIOUS"]

        # TEST 2: Safe URL
        r2 = await c.post('/api/v1/qr/analyze-url', headers=H, json={
            'decoded_payload': 'https://google.com', 'client_detected_type': 'url'
        })
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["security_analysis"]["verdict"] == "SAFE"

        # TEST 3: Plain text
        r3 = await c.post('/api/v1/qr/analyze-url', headers=H, json={
            'decoded_payload': 'Call me at 5pm tomorrow', 'client_detected_type': 'text'
        })
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["detected_type"] == "text"
        assert d3["security_analysis"] is None

        # TEST 4: Bare domain
        r4 = await c.post('/api/v1/qr/analyze-url', headers=H, json={
            'decoded_payload': 'paypal-secure-verification.net', 'client_detected_type': 'url'
        })
        assert r4.status_code == 200
        d4 = r4.json()
        assert d4["security_analysis"] is not None

        # TEST 5: Check audit history for qr_url scans
        hist = await c.get('/api/v1/history/scans?limit=10', headers=H)
        assert hist.status_code == 200
        raw = hist.json()
        scans = raw if isinstance(raw, list) else raw.get('scans', [])
        qr_scans = [s for s in scans if s['scan_type'] == 'qr_url']
        assert len(qr_scans) >= 2

