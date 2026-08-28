"""
End-to-End Verification Script for PhishGuard AI.
Directly exercises all backend layers and ML pipelines.
"""

import asyncio
import sys
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.mysql import init_db
from app.db.mongodb import mongo_manager


async def run_verification():
    print("[1/8] Initializing Database & In-Memory Unstructured Store...")
    await init_db()
    await mongo_manager.connect("mongodb://localhost:27017", "phishguard_unstructured")
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health Probe
        print("[2/8] Testing Health Probe (/health)...")
        res = await client.get("/health")
        assert res.status_code == 200, f"Health failed: {res.text}"
        print(f"      -> Health check OK: {res.json()}")

        # 2. Authentication Flow
        print("[3/8] Testing User Registration & JWT Authentication (/api/v1/auth)...")
        email = f"analyst_{int(asyncio.get_event_loop().time())}@phishguard.ai"
        reg_res = await client.post("/api/v1/auth/register", json={
            "email": email,
            "password": "DefensePassword2026!",
            "full_name": "Senior Threat Analyst",
            "risk_profile_tier": "Intermediate"
        })
        assert reg_res.status_code == 201, f"Register failed: {reg_res.text}"
        data = reg_res.json()
        token = data["tokens"]["access_token"]
        refresh_tok = data["tokens"]["refresh_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"      -> User registered: {data['user']['email']}, Tier: {data['user']['risk_profile_tier']}")

        # Verify /me
        me_res = await client.get("/api/v1/auth/me", headers=headers)
        assert me_res.status_code == 200
        print("      -> Token authorization verified (/auth/me)")

        # 3. Threat Scanner & SHAP Explainable AI
        print("[4/8] Testing Threat Scanner & SHAP Explainer (/api/v1/scan)...")
        # Benign Scan
        safe_res = await client.post("/api/v1/scan/", json={"target": "https://wikipedia.org", "scan_type": "url"}, headers=headers)
        assert safe_res.status_code == 200
        safe_data = safe_res.json()
        print(f"      -> Legitimate target verdict: {safe_data['verdict']} (Score: {safe_data['risk_score']})")

        # Malicious / Zero-Day Target Scan
        phish_url = "https://login-appleid-verify-token.account-security-alert.xyz/auth"
        phish_res = await client.post("/api/v1/scan/", json={"target": phish_url, "scan_type": "url"}, headers=headers)
        assert phish_res.status_code == 200
        phish_data = phish_res.json()
        print(f"      -> Malicious target verdict: {phish_data['verdict']} (Score: {phish_data['risk_score']}/100, Level: {phish_data['risk_level']})")
        print(f"      -> SHAP Top Factor: {phish_data['explanation']['feature_importances'][0]['human_label']} (SHAP: {phish_data['explanation']['feature_importances'][0]['shap_value']})")
        print(f"      -> Personalized Advice: {phish_data['explanation']['actionable_advice']}")

        # 4. Pre-Click Check Interceptor
        print("[5/8] Testing Pre-Click Interceptor (/api/v1/scan/pre-click)...")
        pre_res = await client.get("/api/v1/scan/pre-click", params={"url": phish_url})
        assert pre_res.status_code == 200
        print(f"      -> Pre-click check should_block: {pre_res.json()['should_block']}")

        # 5. Social Engineering NLP Engine
        print("[6/8] Testing Social Engineering NLP Engine (/api/v1/nlp/analyze)...")
        nlp_res = await client.post("/api/v1/nlp/analyze", json={
            "text_content": "CRITICAL FINAL NOTICE: Your bank transfer of $2,450 will be permanently frozen unless you click here and confirm your password immediately.",
            "sender_context": "Fraud Department"
        })
        assert nlp_res.status_code == 200
        nlp_data = nlp_res.json()
        print(f"      -> NLP Manipulation Score: {nlp_data['overall_manipulation_score'] * 100}%, Threat: {nlp_data['threat_category']}")

        # 6. AI Phishing Simulation & Adaptive Learning
        print("[7/8] Testing AI Simulation & Dynamic Vulnerability Engine (/api/v1/simulations)...")
        scenarios_res = await client.get("/api/v1/simulations/scenarios", headers=headers)
        assert scenarios_res.status_code == 200
        scenarios = scenarios_res.json()
        print(f"      -> Retrieved {len(scenarios)} simulation scenarios. Testing user action response...")
        
        sim_action_res = await client.post("/api/v1/simulations/action", json={
            "simulation_id": scenarios[0]["id"],
            "user_action": "REPORTED",
            "response_time_seconds": 12.4
        }, headers=headers)
        assert sim_action_res.status_code == 200
        sim_data = sim_action_res.json()
        print(f"      -> Simulation Result: {sim_data['feedback_title']}")
        print(f"      -> Vulnerability Index Updated: {sim_data['previous_vulnerability_index']} -> {sim_data['new_vulnerability_index']} (Tier: {sim_data['updated_tier']})")

        # 7. Cyber-Safety AI Chatbot & Community Threat Feed
        print("[8/8] Testing AI Cyber-Safety Chatbot & Community Threat Feed...")
        chat_res = await client.post("/api/v1/chat/", json={
            "message": "I received an SMS claiming my parcel is held unless I pay $2. Is it safe?"
        }, headers=headers)
        assert chat_res.status_code == 200
        print(f"      -> Chatbot Response: {chat_res.json()['response'][:80]}...")

        map_res = await client.get("/api/v1/community/threat-map")
        assert map_res.status_code == 200
        print(f"      -> Community Threat Map loaded {len(map_res.json())} live geolocated threat markers.")

    await mongo_manager.close()
    print("\n=======================================================")
    print(" ALL 8 BACKEND MODULES VERIFIED SUCCESSFULLY (100% PASS)")
    print("=======================================================")


if __name__ == "__main__":
    asyncio.run(run_verification())
