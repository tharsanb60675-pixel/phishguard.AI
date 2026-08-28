"""
End-to-End Database Persistence Verification Test for PhishGuard AI.
Verifies registration, login, hashing, scans, scam reports, simulation updates,
and SQLite table records with correct user_id relationships.
"""

import asyncio
import sqlite3
import httpx
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000/api/v1"
DB_PATH = Path(r"c:\Users\VICTUS\zero\backend\phishguard.db")

TEST_EMAIL = "dbtest12345@example.com"
TEST_PASSWORD = "Test@12345"
TEST_NAME = "Database Tester"

async def run_test():
    print(f"[TEST 1] Verifying Database File Location...")
    assert DB_PATH.exists(), f"Database file does not exist at {DB_PATH}"
    print(f"         Database found at: {DB_PATH}")

    # Remove test user if previously created to ensure clean test
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE email = ?", (TEST_EMAIL.lower(),))
    conn.commit()
    conn.close()

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # 1. REGISTER
        print(f"\n[TEST 2] Registering user: {TEST_EMAIL}...")
        reg_payload = {
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": TEST_NAME,
            "risk_profile_tier": "Intermediate"
        }
        reg_res = await client.post("/auth/register", json=reg_payload)
        assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"
        reg_data = reg_res.json()
        user_id = reg_data["user"]["id"]
        tokens = reg_data["tokens"]
        access_token = tokens["access_token"]
        print(f"         Registration API: PASS (User ID: {user_id})")

        # 2. VERIFY SQLITE DIRECTLY AFTER REGISTRATION
        print(f"\n[TEST 3] Verifying SQLite database for user record...")
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, email, password_hash, full_name, risk_profile_tier, vulnerability_index FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        assert row is not None, "User record was NOT found in users table!"
        db_id, db_email, db_hash, db_name, db_tier, db_vuln = row
        print(f"         Found in SQLite: ID={db_id}, Email={db_email}, Tier={db_tier}")
        
        # 3. CONFIRM PASSWORD IS HASHED (NEVER PLAIN TEXT)
        print(f"\n[TEST 4] Verifying Password Hashing...")
        assert db_hash != TEST_PASSWORD, "FATAL: Password is stored as plain text!"
        assert db_hash.startswith("$2b$") or db_hash.startswith("$2a$"), f"Expected bcrypt hash, got: {db_hash[:10]}"
        print(f"         Password Hashed with bcrypt: PASS ({db_hash[:20]}...)")
        conn.close()

        # 4. LOGOUT
        print(f"\n[TEST 5] Logging out session...")
        logout_res = await client.post("/auth/logout", headers={"Authorization": f"Bearer {access_token}"})
        assert logout_res.status_code == 200, f"Logout failed: {logout_res.text}"
        print(f"         Logout API: PASS")

        # 5. LOGIN
        print(f"\n[TEST 6] Logging in with database credentials...")
        login_res = await client.post("/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        login_data = login_res.json()
        assert login_data["user"]["id"] == user_id
        auth_headers = {"Authorization": f"Bearer {login_data['tokens']['access_token']}"}
        print(f"         Login API: PASS (Authenticated User ID: {login_data['user']['id']})")

        # 6. THREAT SCAN (URL)
        print(f"\n[TEST 7] Performing Threat Scan (URL)...")
        scan_target = "https://dbtest12345-secure-portal.com"
        scan_res = await client.post("/scan/", json={"target": scan_target, "scan_type": "url"}, headers=auth_headers)
        assert scan_res.status_code == 200, f"Scan failed: {scan_res.text}"
        scan_data = scan_res.json()
        scan_id = scan_data["scan_id"]
        print(f"         Scan API: PASS (Scan ID: {scan_id}, Verdict: {scan_data['verdict']})")

        # 7. QR CODE ANALYSIS
        print(f"\n[TEST 8] Performing QR Code Security Analysis...")
        qr_target = "https://dbtest12345-qr-link.org"
        qr_res = await client.post("/qr/analyze-url", json={"decoded_payload": qr_target}, headers=auth_headers)
        assert qr_res.status_code == 200, f"QR Scan failed: {qr_res.text}"
        qr_data = qr_res.json()
        print(f"         QR Scan API: PASS (Domain: {qr_data['parsed_domain']})")

        # 8. SUBMIT SCAM REPORT
        print(f"\n[TEST 9] Submitting Community Scam Report...")
        report_payload = {
            "title": "DB Test Phishing Incident 12345",
            "scam_category": "phishing",
            "reported_target": "https://fraud-dbtest12345.com",
            "description": "Suspicious email trying to harvest corporate credentials.",
            "location_name": "New York, USA"
        }
        report_res = await client.post("/community/report", json=report_payload, headers=auth_headers)
        assert report_res.status_code == 201, f"Report failed: {report_res.text}"
        report_data = report_res.json()
        report_id = report_data["id"]
        print(f"         Community Report API: PASS (Report ID: {report_id})")

        # 9. SUBMIT SIMULATION ACTION
        print(f"\n[TEST 10] Submitting AI Simulation Action...")
        sim_res = await client.post("/simulations/action", json={
            "simulation_id": "sim_001",
            "user_action": "REPORTED",
            "response_time_seconds": 8.5
        }, headers=auth_headers)
        assert sim_res.status_code == 200, f"Simulation action failed: {sim_res.text}"
        sim_data = sim_res.json()
        print(f"         Simulation Action API: PASS (Updated Vulnerability: {sim_data['new_vulnerability_index']})")

        # 10. VERIFY ALL SQLITE TABLES DIRECTLY
        print(f"\n[TEST 11] DIRECT SQLITE DATABASE VERIFICATION:")
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # Check scan_history
        cur.execute("SELECT id, user_id, target_identifier, verdict, risk_score FROM scan_history WHERE user_id = ?", (user_id,))
        user_scans = cur.fetchall()
        print(f"         [scan_history table]: Found {len(user_scans)} scans for User {user_id}")
        for s in user_scans:
            print(f"           -> ID: {s[0]}, Target: {s[2]}, Verdict: {s[3]}, Score: {s[4]}")
        assert len(user_scans) >= 2, "Expected at least 2 scans stored in scan_history"

        # Check risk_score_logs
        cur.execute("SELECT id, scan_history_id, user_id, final_weighted_score FROM risk_score_logs WHERE user_id = ?", (user_id,))
        user_logs = cur.fetchall()
        print(f"         [risk_score_logs table]: Found {len(user_logs)} logs for User {user_id}")
        assert len(user_logs) >= 2, "Expected at least 2 logs stored in risk_score_logs"

        # Check scam_reports
        cur.execute("SELECT id, user_id, title, reported_target FROM scam_reports WHERE user_id = ?", (user_id,))
        user_reports = cur.fetchall()
        print(f"         [scam_reports table]: Found {len(user_reports)} reports for User {user_id}")
        for r in user_reports:
            print(f"           -> ID: {r[0]}, Title: {r[2]}, Target: {r[3]}")
        assert len(user_reports) >= 1, "Expected at least 1 report in scam_reports"

        # Check updated vulnerability index in users table
        cur.execute("SELECT vulnerability_index, risk_profile_tier FROM users WHERE id = ?", (user_id,))
        u_vuln, u_tier = cur.fetchone()
        print(f"         [users table updated]: Vulnerability Index: {u_vuln}, Tier: {u_tier}")
        assert u_vuln == sim_data['new_vulnerability_index'], "Vulnerability index was not updated in SQLite users table!"

        conn.close()

        # 11. VERIFY USER ISOLATION (HISTORY API)
        print(f"\n[TEST 12] Verifying User-Specific Scan History API...")
        history_res = await client.get("/history/scans", headers=auth_headers)
        assert history_res.status_code == 200
        history_scans = history_res.json()
        print(f"         User {user_id} sees {len(history_scans)} personal scan history records.")
        assert len(history_scans) == len(user_scans)
        for h in history_scans:
            assert h["target"] in [s[2] for s in user_scans]

    print("\n" + "=" * 60)
    print(" ALL DATABASE PERSISTENCE TESTS PASSED (100% SUCCESS) ")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_test())
