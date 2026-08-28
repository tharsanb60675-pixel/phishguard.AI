"""
End-to-End Test Suite for Universal Manual Scanner Upgrade (Ctrl + Shift + Q).
Validates all 15 test cases required by PhishGuard AI specifications.
"""

import sys
import unittest
from app.services.qr_threat_service import qr_threat_engine

class TestUniversalManualScanner(unittest.TestCase):
    def test_01_safe_https_url(self):
        """Case 1: Safe HTTPS URL -> URL DETECTED & SAFE verdict"""
        res = qr_threat_engine.analyze_universal(text="https://google.com/search")
        self.assertEqual(res["detected_type"], "URL DETECTED")
        self.assertTrue(res["threat_score"] < 20)
        self.assertEqual(res["threat_level"], "SAFE")
        self.assertFalse(res["is_blocked"])

    def test_02_suspicious_url(self):
        """Case 2: Suspicious URL -> URL DETECTED & HIGH/MEDIUM RISK verdict"""
        res = qr_threat_engine.analyze_universal(text="http://verify-bank-account.xyz/login")
        self.assertEqual(res["detected_type"], "URL DETECTED")
        self.assertTrue(res["threat_score"] >= 60)
        self.assertTrue(res["is_blocked"])

    def test_03_phishing_looking_url(self):
        """Case 3: Phishing-looking URL -> URL DETECTED & CRITICAL verdict"""
        res = qr_threat_engine.analyze_universal(text="https://appleid.apple-security-auth.top/login")
        self.assertEqual(res["detected_type"], "URL DETECTED")
        self.assertTrue(res["threat_score"] >= 80)
        self.assertTrue(res["is_blocked"])

    def test_04_plain_text_no_url(self):
        """Case 4: Plain text with no URL -> NOTHING SUPPORTED (no URL analyzer)"""
        res = qr_threat_engine.analyze_universal(text="Lorem ipsum dolor sit amet")
        self.assertEqual(res["detected_type"], "NOTHING SUPPORTED")
        self.assertIn("Unable to scan this selected area", res["message"])
        self.assertNotIn("url", res)

    def test_05_normal_notification(self):
        """Case 5: Normal notification -> NOTIFICATION DETECTED & REAL / LIKELY REAL or LOW RISK"""
        res = qr_threat_engine.analyze_universal(text="Your package has been delivered to your front porch by FedEx.")
        self.assertEqual(res["detected_type"], "NOTIFICATION DETECTED")
        self.assertIn(res["status"], ["REAL / LIKELY REAL", "UNKNOWN / UNVERIFIED"])

    def test_06_scam_like_notification(self):
        """Case 6: Scam-like notification -> NOTIFICATION DETECTED & LIKELY FAKE"""
        res = qr_threat_engine.analyze_universal(text="Your bank account will be blocked today. Click this link immediately to enter your password and OTP.")
        self.assertEqual(res["detected_type"], "NOTIFICATION DETECTED")
        self.assertEqual(res["status"], "LIKELY FAKE")
        self.assertTrue(res["threat_score"] >= 75)

    def test_07_notification_containing_url(self):
        """Case 7: Notification containing URL -> NOTIFICATION DETECTED with embedded URL analysis"""
        res = qr_threat_engine.analyze_universal(text="Account alert: Verify your identity immediately at https://secure-bank-login.xyz")
        self.assertEqual(res["detected_type"], "NOTIFICATION DETECTED")
        self.assertIsNotNone(res.get("embedded_url_analysis"))
        self.assertEqual(res["embedded_url_analysis"]["parsedDomain"], "secure-bank-login.xyz")

    def test_08_normal_email_id(self):
        """Case 8: Normal email ID -> EMAIL ID DETECTED & UNVERIFIED/VERIFIED (Not fake just because Gmail)"""
        res = qr_threat_engine.analyze_universal(text="john.doe@gmail.com")
        self.assertEqual(res["detected_type"], "EMAIL ID DETECTED")
        self.assertEqual(res["email"], "john.doe@gmail.com")
        self.assertEqual(res["domain"], "gmail.com")
        self.assertNotEqual(res["authenticity"], "SUSPICIOUS")
        self.assertFalse(res["is_blocked"])

    def test_09_suspicious_email_domain(self):
        """Case 9: Suspicious email domain -> EMAIL ID DETECTED & SUSPICIOUS"""
        res = qr_threat_engine.analyze_universal(text="security-alert@paypal-login-verify.xyz")
        self.assertEqual(res["detected_type"], "EMAIL ID DETECTED")
        self.assertEqual(res["authenticity"], "SUSPICIOUS")
        self.assertTrue(res["threat_score"] >= 60)

    def test_10_email_inside_notification(self):
        """Case 10: Email inside notification -> NOTIFICATION DETECTED with embedded email analysis"""
        res = qr_threat_engine.analyze_universal(text="Urgent security notification: Contact security-team@paypal-login-verify.xyz immediately.")
        self.assertEqual(res["detected_type"], "NOTIFICATION DETECTED")
        self.assertIsNotNone(res.get("embedded_email_analysis"))
        self.assertEqual(res["embedded_email_analysis"]["domain"], "paypal-login-verify.xyz")

    def test_11_qr_containing_url(self):
        """Case 11: QR containing URL -> QR CODE DETECTED -> URL"""
        res = qr_threat_engine.analyze_universal(qr_codes=[{"payload": "https://example.com/login", "boundingBox": None}])
        self.assertEqual(res["detected_type"], "QR CODE DETECTED")
        self.assertEqual(res["qr_type"], "HTTPS URL")

    def test_12_qr_containing_plain_text(self):
        """Case 12: QR containing plain text -> QR CODE DETECTED -> Plain text"""
        res = qr_threat_engine.analyze_universal(qr_codes=[{"payload": "Inventory Item #4920", "boundingBox": None}])
        self.assertEqual(res["detected_type"], "QR CODE DETECTED")
        self.assertEqual(res["qr_type"], "Plain Text")

    def test_13_qr_containing_email(self):
        """Case 13: QR containing email -> QR CODE DETECTED -> Email"""
        res = qr_threat_engine.analyze_universal(qr_codes=[{"payload": "mailto:support@company.com", "boundingBox": None}])
        self.assertEqual(res["detected_type"], "QR CODE DETECTED")
        self.assertEqual(res["qr_type"], "Email Address / mailto")

    def test_14_qr_containing_wifi(self):
        """Case 14: QR containing Wi-Fi -> QR CODE DETECTED -> Wi-Fi"""
        res = qr_threat_engine.analyze_universal(qr_codes=[{"payload": "WIFI:T:WPA;S:MyNetwork;P:Secret123;;", "boundingBox": None}])
        self.assertEqual(res["detected_type"], "QR CODE DETECTED")
        self.assertEqual(res["qr_type"], "Wi-Fi Configuration")

    def test_15_screen_containing_nothing(self):
        """Case 15: Screen containing nothing supported -> NOTHING SUPPORTED"""
        res = qr_threat_engine.analyze_universal(text="", qr_codes=[])
        self.assertEqual(res["detected_type"], "NOTHING SUPPORTED")
        self.assertIn("Unable to scan this selected area", res["message"])

if __name__ == "__main__":
    unittest.main()
