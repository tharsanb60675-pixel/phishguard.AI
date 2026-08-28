"""
End-to-End Test Suite for PhishGuard AI - Essential Key Smart Region Scanner (Ctrl + Shift + Q).
Validates all 12 core test scenarios required by PhishGuard AI specifications:
1. Safe URL
2. Invalid URL
3. Normal Message
4. Scam Message
5. QR Containing URL
6. QR Containing Text
7. Barcode (Numeric vs URL)
8. Mixed Message + URL
9. QR + Surrounding Text
10. Nothing Useful (Blank/Unsupported Area)
11. Decision Guidance Layer (5-tier)
12. Barcode routing
"""

import sys
import unittest
from app.services.qr_threat_service import qr_threat_engine

class TestEssentialKeySmartRegionScanner(unittest.TestCase):
    def test_01_safe_url(self):
        """Test 1: Safe URL -> URL detected & validated & SAFE verdict"""
        res = qr_threat_engine.analyze_universal(text="https://google.com/search")
        self.assertEqual(res["detected_type"], "URL DETECTED")
        self.assertTrue(res["threat_score"] < 20)
        self.assertEqual(res["threat_level"], "SAFE")
        self.assertIn("Proceeding appears reasonable", res["decision_guidance"])
        self.assertFalse(res["is_blocked"])

    def test_02_invalid_url(self):
        """Test 2: Invalid URL -> Not treated as URL; rejected or NOTHING SUPPORTED"""
        res = qr_threat_engine.analyze_universal(text="hello-world")
        self.assertEqual(res["detected_type"], "NOTHING SUPPORTED")
        self.assertIn("Unable to scan this selected area", res["message"])
        self.assertNotIn("url", res)

    def test_03_normal_message(self):
        """Test 3: Normal message -> Text detected & analyzed as message (SAFE/LOW RISK)"""
        res = qr_threat_engine.analyze_universal(text="Your package delivery notice from FedEx: Package left on front porch.")
        self.assertEqual(res["detected_type"], "NOTIFICATION DETECTED")
        self.assertIn(res["status"], ["REAL / LIKELY REAL", "UNKNOWN / UNVERIFIED"])


    def test_04_scam_message(self):
        """Test 4: Scam message -> Text detected & analyzed as scam (LIKELY FAKE, HIGH RISK)"""
        res = qr_threat_engine.analyze_universal(text="Congratulations! You have won ₹50,000. Click immediately to claim your reward before account blocked.")
        self.assertEqual(res["detected_type"], "NOTIFICATION DETECTED")
        self.assertEqual(res["status"], "LIKELY FAKE")
        self.assertTrue(res["threat_score"] >= 75)

    def test_05_qr_containing_url(self):
        """Test 5: QR containing URL -> QR detected & decoded & URL analyzed"""
        res = qr_threat_engine.analyze_universal(qr_codes=[{"payload": "https://example.com/login", "boundingBox": None}])
        self.assertEqual(res["detected_type"], "QR CODE DETECTED")
        self.assertTrue(res["is_valid_url"])
        self.assertEqual(res["qr_type"], "HTTPS URL")

    def test_06_qr_containing_text(self):
        """Test 6: QR containing text -> QR decoded & plain text displayed (no fake URL)"""
        res = qr_threat_engine.analyze_universal(qr_codes=[{"payload": "Inventory Item #4920", "boundingBox": None}])
        self.assertEqual(res["detected_type"], "QR CODE DETECTED")
        self.assertFalse(res["is_valid_url"])
        self.assertEqual(res["qr_type"], "Plain Text")

    def test_07_barcode(self):
        """Test 7: Barcode -> Barcode decoded & numeric product ID verified"""
        res = qr_threat_engine.analyze_universal(barcodes=[{"rawValue": "012345678905", "format": "ean-13"}])
        self.assertEqual(res["detected_type"], "BARCODE DETECTED")
        self.assertEqual(res["barcode_val"], "012345678905")
        self.assertFalse(res["is_url"])
        self.assertEqual(res["threat_score"], 0.0)

    def test_08_mixed_message_url(self):
        """Test 8: Mixed Message + URL -> Message & embedded URL analyzed"""
        res = qr_threat_engine.analyze_universal(text="Your account will be blocked today. Verify immediately at https://secure-login-verify-account.bank-security.xyz")
        self.assertEqual(res["detected_type"], "NOTIFICATION DETECTED")
        self.assertIsNotNone(res.get("embedded_url_analysis"))
        self.assertTrue(res["threat_score"] >= 75)

    def test_09_qr_surrounding_text(self):
        """Test 9: QR + Surrounding text -> Mixed content assessment"""
        res = qr_threat_engine.analyze_universal(
            text="Account Alert notice",
            qr_codes=[{"payload": "https://suspicious.xyz/auth"}],
            barcodes=[{"rawValue": "9780123456789", "format": "isbn"}]
        )
        self.assertEqual(res["detected_type"], "MIXED CONTENT DETECTED")
        self.assertTrue(len(res["components"]) >= 2)

    def test_10_nothing_useful(self):
        """Test 10: Nothing useful / blank area -> Clear error message without fake SAFE"""
        res = qr_threat_engine.analyze_universal(text="", qr_codes=[], barcodes=[])
        self.assertEqual(res["detected_type"], "NOTHING SUPPORTED")
        self.assertIn("Unable to scan this selected area", res["message"])

    def test_11_decision_guidance(self):
        """Test 11: 5-Tier Decision Guidance Layer generation"""
        g_safe = qr_threat_engine.calculate_decision_guidance("SAFE", 10.0)
        g_low = qr_threat_engine.calculate_decision_guidance("LOW RISK", 30.0)
        g_med = qr_threat_engine.calculate_decision_guidance("MEDIUM RISK", 50.0)
        g_high = qr_threat_engine.calculate_decision_guidance("HIGH RISK", 70.0)
        g_crit = qr_threat_engine.calculate_decision_guidance("CRITICAL", 90.0)

        self.assertIn("Proceeding appears reasonable", g_safe)
        self.assertIn("continue with normal caution", g_low)
        self.assertIn("Proceed with caution", g_med)
        self.assertIn("Do not proceed until you independently verify", g_high)
        self.assertIn("Do not proceed. Treat this as potentially malicious", g_crit)

    def test_12_barcode_url(self):
        """Test 12: Barcode containing URL -> routes to URL Threat Intelligence"""
        res = qr_threat_engine.analyze_universal(barcodes=[{"rawValue": "https://example.com/product", "format": "qr_code"}])
        self.assertEqual(res["detected_type"], "BARCODE DETECTED (URL)")
        self.assertTrue(res["is_url"])

if __name__ == "__main__":
    unittest.main()
