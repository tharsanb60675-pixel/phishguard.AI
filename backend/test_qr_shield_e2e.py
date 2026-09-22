import os
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
venv_site_packages = backend_dir / ".venv" / "Lib" / "site-packages"
if venv_site_packages.exists() and str(venv_site_packages) not in sys.path:
    sys.path.insert(0, str(venv_site_packages))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import asyncio
import sqlite3
import httpx
import pytest
from app.services.qr_threat_service import qr_threat_engine

BASE_URL = "http://127.0.0.1:8000/api/v1"
DB_PATH = Path(r"c:\Users\VICTUS\zero\backend\phishguard.db")



def test_threat_scoring_engine():
    print("\n--- [UNIT TEST 1] Testing QR Threat Analysis Engine Heuristics ---")
    
    # 1. Legitimate URL
    safe_res = qr_threat_engine.analyze_payload("https://google.com/search?q=security")
    print(f"  Legitimate Domain Score: {safe_res['threatScore']} (Severity: {safe_res['severity']})")
    assert safe_res['severity'] == "SAFE"
    assert safe_res['threatScore'] <= 20.0

    # 2. Phishing URL with lookalike brand and login keywords
    phish_res = qr_threat_engine.analyze_payload("http://appleid-verify-checkpoint.account-alert.xyz/login-auth")
    print(f"  Brand Phishing Score: {phish_res['threatScore']} (Severity: {phish_res['severity']}, Class: {phish_res['classification']})")
    assert phish_res['severity'] in ("CRITICAL", "HIGH RISK")
    assert phish_res['threatScore'] >= 75.0
    assert any("Apple" in r or "brand" in r.lower() for r in phish_res['reasons'])

    # 3. Direct IP Address URL
    ip_res = qr_threat_engine.analyze_payload("http://192.168.1.100/admin/update")
    print(f"  IP Address URL Score: {ip_res['threatScore']} (Severity: {ip_res['severity']})")
    assert ip_res['threatScore'] >= 40.0

    # 4. Crypto Drainer Lure
    crypto_res = qr_threat_engine.analyze_payload("https://claim-airdrop-eth2026.xyz/wallet-drainer")
    print(f"  Crypto Scam Score: {crypto_res['threatScore']} (Severity: {crypto_res['severity']})")
    assert crypto_res['severity'] in ("CRITICAL", "HIGH RISK")

    print("  [OK] QR Threat Scoring Engine Passed 100% of Scenarios.")


@pytest.mark.asyncio
async def test_backend_persistence_and_sync():
    print("\n--- [INTEGRATION TEST 2] Testing Database Persistence & Device Pairing ---")
    
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # 1. Register a test user
        email = f"shield_tester_{int(asyncio.get_event_loop().time())}@phishguard.ai"
        reg_res = await client.post("/auth/register", json={
            "email": email,
            "password": "Password123!",
            "full_name": "QR Shield Analyst",
            "risk_profile_tier": "Intermediate"
        })
        assert reg_res.status_code in (200, 201), f"Registration failed: {reg_res.text}"
        user_id = reg_res.json()["user"]["id"]
        token = reg_res.json()["tokens"]["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"  Registered Shield Tester ID: {user_id}")

        # 2. Analyze QR Code through API
        scan_payload = "https://login-appleid-verify-token.account-security-alert.xyz/auth"
        scan_res = await client.post("/qr/analyze", json={
            "payload": scan_payload,
            "page_url": "https://web.whatsapp.com",
            "page_title": "WhatsApp Web",
            "bounding_box": {"x": 120, "y": 240, "width": 180, "height": 180},
            "scan_source": "shortcut (Ctrl+Shift+Q)",
            "browser": "Chrome",
            "device": "Laptop"
        }, headers=headers)

        assert scan_res.status_code == 200, f"QR Analyze failed: {scan_res.text}"
        scan_data = scan_res.json()
        scan_id = scan_data["scan_id"]
        print(f"  Created QR Scan ID: {scan_id} (Threat Score: {scan_data['threat_score']}, Blocked: {scan_data['is_blocked']})")

        # 3. Verify Direct SQLite Table Persistence
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, user_id, qr_payload, threat_score, severity, is_blocked FROM qr_scans WHERE id = ?", (scan_id,))
        row = cur.fetchone()
        assert row is not None, "QR Scan record was NOT found in qr_scans table!"
        assert row[1] == user_id, f"User ID mismatch in qr_scans: expected {user_id}, got {row[1]}"
        print(f"  [OK] Verified record in SQLite 'qr_scans' table: ID={row[0]}, Severity={row[4]}, Blocked={bool(row[5])}")

        # Verify threat_analysis child table
        cur.execute("SELECT id, qr_scan_id, has_login_keywords, has_suspicious_tld FROM threat_analysis WHERE qr_scan_id = ?", (scan_id,))
        t_row = cur.fetchone()
        assert t_row is not None, "Technical indicators not found in threat_analysis table!"
        print(f"  [OK] Verified deep indicators in SQLite 'threat_analysis' table (Login Keywords: {bool(t_row[2])}, Suspicious TLD: {bool(t_row[3])})")
        conn.close()

        # 4. Device Pairing Flow
        pair_req_res = await client.post("/devices/pair/request", headers=headers)
        assert pair_req_res.status_code == 200
        pairing_code = pair_req_res.json()["pairing_code"]
        print(f"  Generated Device Pairing Code: {pairing_code}")

        # Confirm pairing from simulated Android device
        device_id = f"android_test_device_{int(asyncio.get_event_loop().time())}"
        confirm_res = await client.post("/devices/pair/confirm", json={
            "pairing_code": pairing_code,
            "device_name": "Google Pixel 8 Pro (Companion)",
            "device_id": device_id,
            "device_type": "android"
        })
        assert confirm_res.status_code == 200, f"Pairing confirm failed: {confirm_res.text}"
        print(f"  [OK] Android Device Paired Successfully: {device_id}")

        # Verify paired_devices table in SQLite
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, user_id, device_name, is_active FROM paired_devices WHERE device_id = ?", (device_id,))
        dev_row = cur.fetchone()
        assert dev_row is not None, "Device not saved in paired_devices table!"
        print(f"  [OK] Verified device in SQLite 'paired_devices' table: ID={dev_row[0]}, Name={dev_row[2]}")
        conn.close()

        # 5. List Scans History API
        history_res = await client.get("/qr/scans", headers=headers)
        assert history_res.status_code == 200
        scans_list = history_res.json()
        assert len(scans_list) >= 1
        print(f"  [OK] Query /qr/scans returned {len(scans_list)} records for User {user_id}")

        # 6. Privacy: Delete All QR Scans
        del_res = await client.delete("/qr/scans", headers=headers)
        assert del_res.status_code == 200
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM qr_scans WHERE user_id = ?", (user_id,))
        count_after = cur.fetchone()[0]
        assert count_after == 0, "Scan history was not purged!"
        print(f"  [OK] Privacy Wipe Verified: 0 scans remaining in SQLite for user {user_id}")
        conn.close()

    print("\n" + "=" * 60)
    print(" ALL QR THREAT DETECTION & ANDROID SYNC TESTS PASSED (100%) ")
    print("=" * 60)


if __name__ == "__main__":
    test_threat_scoring_engine()
    asyncio.run(test_backend_persistence_and_sync())
