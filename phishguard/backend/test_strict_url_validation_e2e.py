"""
Strict URL Validation Test Suite for PhishGuard Threat Scanner.
Verifies both Frontend JS validator logic and Backend API validation guardrails.
"""

import httpx
from app.utils.url_validator import validate_strict_url

BASE_URL = "http://127.0.0.1:8000/api/v1/scan/"

INVALID_CASES = [
    "123456789",
    "hello",
    "test",
    "google",
    "google.com",
    "example",
    "@username",
    "test@gmail.com",
    "9876543210",
    "this is a phishing website",
    "javascript:alert(1)",
    "",
    "   ",
    "ftp://example.com",
    "file:///C:/Users",
    "mailto:test@example.com",
    "http://123456789",
    "https://",
    "http://",
    "https://hello world.com",
]

VALID_CASES = [
    "https://google.com",
    "http://example.com",
    "https://www.example.com/login",
    "https://subdomain.example.com/path?test=123",
    "https://example.com:8080/path",
    "https://login-appleid-verify-token.account-security-alert.xyz/auth",
    "http://192.168.1.1/admin",
    "http://localhost:3000/test",
]


def test_python_validator_unit():
    print("\n--- [UNIT TEST 1] Testing Strict URL Validation Helper (Python) ---")
    for raw in INVALID_CASES:
        is_valid, err = validate_strict_url(raw)
        print(f"  [REJECTED] Input: {raw!r:35} -> Valid: {is_valid} (Error: '{err}')")
        assert is_valid is False, f"Expected {raw!r} to be INVALID, but got VALID"

    for raw in VALID_CASES:
        is_valid, err = validate_strict_url(raw)
        print(f"  [ACCEPTED] Input: {raw!r:35} -> Valid: {is_valid}")
        assert is_valid is True, f"Expected {raw!r} to be VALID, but got INVALID: {err}"

    print("  [OK] Unit URL Validator passed 100% of test vectors.")


def test_backend_api_rejection():
    print("\n--- [INTEGRATION TEST 2] Testing Backend API Rejection of Invalid Targets ---")
    
    with httpx.Client(base_url="http://127.0.0.1:8000/api/v1", timeout=10.0) as client:
        # Test Invalid Inputs -> Must return HTTP 400 Bad Request
        for raw in ["123456789", "hello world", "google.com", "test@gmail.com", "javascript:alert(1)"]:
            res = client.post("/scan/", json={"target": raw, "scan_type": "url"})
            print(f"  API POST /scan/ with {raw!r:25} -> HTTP {res.status_code}")
            assert res.status_code == 400, f"Expected HTTP 400 for {raw!r}, got {res.status_code}"
            assert "It is not a valid URL" in res.text

        # Test Valid Inputs -> Must return HTTP 200 OK with Risk Score
        for raw in ["https://google.com", "https://example.com/login", "https://subdomain.example.com/path?test=123"]:
            res = client.post("/scan/", json={"target": raw, "scan_type": "url"})
            print(f"  API POST /scan/ with {raw!r:45} -> HTTP {res.status_code}")
            assert res.status_code == 200, f"Expected HTTP 200 for {raw!r}, got {res.status_code}"
            data = res.json()
            assert "risk_score" in data
            assert "verdict" in data
            assert "explanation" in data
            print(f"    Verdict: {data['verdict']} | Risk Score: {data['risk_score']:.1f}/100")

    print("\n[OK] Backend API Strict URL Rejection passed 100% of test vectors.")


if __name__ == "__main__":
    test_python_validator_unit()
    test_backend_api_rejection()
    print("\n" + "=" * 60)
    print(" ALL STRICT URL VALIDATION TESTS PASSED (100%) ")
    print("=" * 60)
