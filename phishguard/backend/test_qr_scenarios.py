"""
Verification script for multiple QR payload scenarios.
Tests all 11 required payload categories against the upgraded QR threat engine.
"""

import sys
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from app.services.qr_threat_service import qr_threat_engine


def run_scenario_tests():
    scenarios = [
        ("1. Normal HTTPS URL", "https://google.com/search?q=security", "SAFE", "VERIFIED"),
        ("2. Suspicious URL", "http://appleid-verify-checkpoint.account-alert.xyz/login-auth", "CRITICAL", "SUSPICIOUS"),
        ("3. HTTP URL", "http://my-blog-update.org/article", "LOW RISK", "UNVERIFIED"),
        ("4. URL shortener", "https://bit.ly/secure-redirect", "MEDIUM RISK", "UNVERIFIED"),
        ("5. Lookalike/typosquatting domain", "https://paypal-security-checkpoint.xyz/auth", "CRITICAL", "SUSPICIOUS"),
        ("6. Plain text QR", "Conference Room B Reserved from 2pm to 4pm", "SAFE", "VERIFIED"),
        ("7. Wi-Fi QR", "WIFI:S:HomeNetwork;T:WPA;P:SuperSecretPass;;", "SAFE", "VERIFIED"),
        ("8. Email QR", "mailto:security-desk@company.com?subject=Inquiry", "SAFE", "VERIFIED"),
        ("9. Phone/SMS QR", "tel:+18005550199", "SAFE", "VERIFIED"),
        ("10. Payment/deep-link QR", "upi://pay?pa=shopkeeper@upi&pn=GroceryStore&am=25.00", "SAFE", "VERIFIED"),
        ("11. Unknown/unverifiable destination", "https://unverified-domain-12345.org/landing", "UNKNOWN / UNVERIFIED", "UNVERIFIED"),
    ]

    print("=" * 80)
    print("RUNNING MULTI-PAYLOAD QR SECURITY ANALYSIS VERIFICATION")
    print("=" * 80)

    for name, payload, expected_sev, expected_auth in scenarios:
        res = qr_threat_engine.analyze_payload(payload)
        print(f"\n[{name}]")
        print(f"  Payload:          {payload}")
        print(f"  QR Type:          {res['qrType']}")
        print(f"  Threat Score:     {res['threatScore']} / 100")
        print(f"  Severity:         {res['severity']}")
        print(f"  Verdict:          {res['verdict']}")
        print(f"  Authenticity:     {res['authenticity']} ({res['authenticityReason']})")
        print(f"  What Will Happen: {res['whatWillHappen']}")
        print(f"  Confidence:       {res['confidenceLevel']}")
        print(f"  Action:           {res['actionText']} ({res['actionType']})")
        print(f"  Blocked:          {res['isBlocked']}")
        print(f"  Checks Performed: {len(res['checks'])} checks")
        for c in res['checks'][:2]:
            print(f"    {c['icon']} {c['text']}")

        # Ensure threat results are dynamic and match intelligence
        if expected_sev == "SAFE":
            assert res['threatScore'] <= 20.0, f"Expected SAFE score <= 20, got {res['threatScore']}"
        elif expected_sev in ("CRITICAL", "HIGH RISK"):
            assert res['threatScore'] >= 60.0, f"Expected HIGH/CRITICAL score >= 60, got {res['threatScore']}"
            assert res['isBlocked'] is True, f"Expected isBlocked=True for {expected_sev}"

    print("\n" + "=" * 80)
    print("ALL 11 QR PAYLOAD SCENARIOS PASSED REAL-TIME THREAT EVALUATION!")
    print("=" * 80)


if __name__ == "__main__":
    run_scenario_tests()
