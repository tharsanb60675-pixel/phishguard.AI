"""
QR Threat Analysis Engine for PhishGuard AI.
Evaluates decoded QR payloads through multi-layer heuristics, domain intelligence,
brand impersonation detection, authenticity verification, and machine learning scoring rules.
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Tuple
from app.models.qr_scan import QRSeverity, QRClassification

# Trusted apex domains
TRUSTED_DOMAINS = {
    "google.com", "www.google.com", "accounts.google.com", "mail.google.com",
    "wikipedia.org", "www.wikipedia.org", "en.wikipedia.org",
    "github.com", "www.github.com", "microsoft.com", "www.microsoft.com", "login.microsoftonline.com",
    "apple.com", "www.apple.com", "icloud.com", "appleid.apple.com",
    "amazon.com", "www.amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com",
    "paypal.com", "www.paypal.com",
    "youtube.com", "www.youtube.com", "linkedin.com", "www.linkedin.com",
    "netflix.com", "www.netflix.com", "instagram.com", "www.instagram.com",
    "facebook.com", "www.facebook.com", "twitter.com", "x.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "hdfcbank.com", "icicibank.com",
    "gov.in", "gov", "mil", "edu"
}

# High-Risk TLDs frequently used in zero-day quishing & phishing
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "buzz", "cfd", "rest", "cam",
    "sbs", "live", "vip", "work", "loan", "click", "country", "link", "online", "site",
    "surf", "monster", "fun", "gdn", "mom", "quest", "cyou", "fit"
}

# Common URL Shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at"
}

# Targeted Brands commonly impersonated in QR attacks
TARGETED_BRANDS = [
    "apple", "appleid", "paypal", "netflix", "chase", "bankofamerica", "wellsfargo", "microsoft",
    "amazon", "google", "binance", "metamask", "coinbase", "whatsapp", "instagram", "facebook",
    "dhl", "fedex", "usps", "royalmail", "irs", "hdfc", "icici", "sbi", "paytm", "bank-security",
    "account-alert", "secure-portal"
]

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "checkpoint", "auth", "token", "password",
    "update-billing", "account-alert", "secure-portal", "confirm", "wallet-connect", "claim-airdrop",
    "unlock-account", "session-recovery", "wire-transfer", "urgent-action", "security-update",
    "credential", "passcode", "restore-access", "wallet-drainer"
]

SOCIAL_MEDIA_DOMAINS = {
    "instagram.com", "facebook.com", "twitter.com", "x.com", "linkedin.com", "tiktok.com",
    "youtube.com", "reddit.com", "pinterest.com", "threads.net", "snapchat.com"
}


class QRThreatEngine:
    @staticmethod
    def classify_payload_type(payload: str) -> str:
        s = payload.strip()
        low = s.lower()

        # 1. Wi-Fi Configuration
        if low.startswith("wifi:") or low.startswith("wifi;"):
            return "Wi-Fi Configuration"

        # 2. Cryptocurrency / Payment URI
        if low.startswith("upi://") or low.startswith("ethereum:") or low.startswith("bitcoin:") or low.startswith("solana:") or low.startswith("litecoin:"):
            return "Cryptocurrency / Payment URI"

        # 3. Email Address / mailto
        if low.startswith("mailto:") or low.startswith("matmsg:") or low.startswith("smtp:"):
            return "Email Address / mailto"
        if "@" in s and not s.startswith("http") and not s.startswith("upi:") and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s):
            return "Email Address / mailto"

        # 4. Telephone Number / tel
        if low.startswith("tel:") or (re.match(r"^(\+\d{1,4}[-\s]?)?\(?\d{1,4}\)?[-\s]?\d{1,4}[-\s]?\d{1,9}$", s) and len(s) >= 7 and " " not in s.strip()):
            return "Telephone Number / tel"

        # 5. SMS
        if low.startswith("smsto:") or low.startswith("sms:") or low.startswith("mms:"):
            return "SMS"

        # 6. Contact / vCard / MeCard
        if low.startswith("begin:vcard") or low.startswith("mecard:") or "n:" in low and "tel:" in low and "email:" in low:
            return "Contact / vCard"

        # 7. Calendar Event
        if low.startswith("begin:vevent") or low.startswith("begin:vcalendar"):
            return "Calendar / Event Data"

        # 8. App / Deep Link
        if re.match(r"^[a-zA-Z0-9_-]+://", s) and not (low.startswith("http://") or low.startswith("https://") or low.startswith("upi://") or low.startswith("ftp://")):
            return "App / Deep Link"

        # 9. Social Media Link
        if low.startswith("http://") or low.startswith("https://"):
            try:
                domain = urlparse(s).netloc.lower()
                if any(domain == d or domain.endswith("." + d) for d in SOCIAL_MEDIA_DOMAINS):
                    return "Social-Media Link"
            except Exception:
                pass

        # 10. URL (HTTP / HTTPS / Bare domain)
        if low.startswith("https://"):
            return "HTTPS URL"
        if low.startswith("http://"):
            return "HTTP URL"
        if "." in s and " " not in s and len(s) < 150 and not s.startswith("data:"):
            return "URL"

        # 11. Plain Text or Unknown Data
        if re.search(r"[a-zA-Z0-9]", s):
            return "Plain Text"
        return "Unknown / Custom QR Payload"

    @classmethod
    def analyze_payload(cls, payload: str, page_url: str = None) -> Dict[str, Any]:
        """
        Execute comprehensive security analysis on QR payload.
        Returns normalized threatScore (0-100), severity, verdict, classification, confidence,
        authenticity, whatWillHappen, checks list, analysis reasons, and indicators.
        """
        clean_payload = payload.strip()
        qr_type = cls.classify_payload_type(clean_payload)
        
        reasons: List[str] = []
        checks: List[Dict[str, Any]] = []
        raw_score = 0.0
        
        is_url_type = qr_type in ("URL", "HTTPS URL", "HTTP URL", "Social-Media Link", "Cryptocurrency / Payment URI")
        parsed_domain = ""
        is_https = False
        is_ip = False
        is_shortened = False
        has_suspicious_tld = False
        has_punycode = False
        has_login_keywords = False
        has_banking_keywords = False
        has_crypto_keywords = False
        domain_rep_score = 0.0
        
        authenticity = "UNVERIFIED"
        authenticity_reason = "Unable to verify this destination with the available security intelligence."
        what_will_happen = "This QR code opens content."
        confidence_level = "HIGH"
        is_known_apex = False

        if is_url_type:
            norm_url = clean_payload if clean_payload.startswith(("http://", "https://", "upi://", "bitcoin:", "ethereum:")) else f"https://{clean_payload}"
            try:
                parsed = urlparse(norm_url)
                parsed_domain = (parsed.netloc or parsed.path).split(":")[0].lower()
                is_https = norm_url.startswith("https://")
            except Exception:
                parsed_domain = clean_payload.split("/")[0].lower()
                is_https = False

            # Determine What Will Happen
            url_path_query = norm_url.lower()
            if "login" in url_path_query or "signin" in url_path_query or "auth" in url_path_query:
                what_will_happen = "This QR code opens a website login / authentication page."
            elif "wallet" in url_path_query or "drainer" in url_path_query or "airdrop" in url_path_query or clean_payload.startswith(("ethereum:", "bitcoin:", "solana:")):
                what_will_happen = "This QR code attempts to connect to a cryptocurrency wallet."
            elif clean_payload.startswith("upi://"):
                what_will_happen = "This QR code attempts to open a mobile payment application (UPI)."
            elif qr_type == "Social-Media Link":
                what_will_happen = "This QR code opens a social media profile or post."
            else:
                what_will_happen = "This QR code opens a website."

            # Check 1: HTTPS vs HTTP
            if is_https:
                checks.append({"status": "PASS", "icon": "✓", "text": "HTTPS secure encryption detected"})
            elif not clean_payload.startswith(("upi://", "bitcoin:", "ethereum:")):
                raw_score += 20.0
                reasons.append("Unencrypted connection (HTTP instead of secure HTTPS)")
                checks.append({"status": "WARN", "icon": "⚠", "text": "Unencrypted HTTP connection — data transmitted in plain text"})
            else:
                checks.append({"status": "PASS", "icon": "✓", "text": "Direct protocol handler used"})

            # Check 2: Direct IP address destination
            ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
            if re.match(ip_pattern, parsed_domain):
                is_ip = True
                raw_score += 45.0
                reasons.append("Direct IP address destination used to bypass hostname reputation filters")
                checks.append({"status": "FAIL", "icon": "⚠", "text": "Direct IP address host instead of registered domain name"})
                authenticity = "SUSPICIOUS"
                authenticity_reason = "Direct IP host is frequently used by hostile command-and-control servers."
            else:
                checks.append({"status": "PASS", "icon": "✓", "text": "Valid fully-qualified domain name structure"})

            # Check 3: Punycode / IDN Homograph domain
            if "xn--" in parsed_domain:
                has_punycode = True
                raw_score += 40.0
                reasons.append("Punycode (IDN homograph) encoding detected — potential lookalike spoofing")
                checks.append({"status": "FAIL", "icon": "⚠", "text": "Punycode (IDN homograph) encoding detected"})
                authenticity = "SUSPICIOUS"
                authenticity_reason = "Homograph trick detected mimicking a known character set."

            # Check 4: Suspicious / Disposable TLD
            tld = parsed_domain.split(".")[-1] if "." in parsed_domain else ""
            if tld in HIGH_RISK_TLDS:
                has_suspicious_tld = True
                raw_score += 30.0
                reasons.append(f"High-risk top-level domain (.{tld}) commonly associated with disposable phishing campaigns")
                checks.append({"status": "FAIL", "icon": "⚠", "text": f"High-risk disposable TLD (.{tld})"})
                authenticity = "SUSPICIOUS"
                authenticity_reason = f"High-risk TLD (.{tld}) with elevated fraud frequency."

            # Check 5: URL Shortener
            if parsed_domain in URL_SHORTENERS:
                is_shortened = True
                raw_score += 25.0
                reasons.append("URL shortener used — obscures ultimate landing page destination")
                checks.append({"status": "WARN", "icon": "⚠", "text": "URL shortener obscures destination until visited"})
                authenticity = "UNVERIFIED"
                authenticity_reason = "Shortened URL obscures original destination."

            # Check 6: Brand Impersonation / Typosquatting
            matched_brands = [b for b in TARGETED_BRANDS if b in parsed_domain]
            is_official = any(parsed_domain == d or parsed_domain.endswith(f".{d}") for d in TRUSTED_DOMAINS)
            if matched_brands and not is_official:
                raw_score += 50.0
                brand_name = matched_brands[0].capitalize()
                reasons.append(f"Potential brand impersonation: domain mimics '{brand_name}' without official ownership")
                checks.append({"status": "FAIL", "icon": "⚠", "text": f"Lookalike domain mimicking brand '{brand_name}'"})
                authenticity = "SUSPICIOUS"
                authenticity_reason = f"Possible brand impersonation detected for '{brand_name}'."

            # Check 7: Suspicious Keywords in Path / Query
            found_keywords = [k for k in SUSPICIOUS_PATH_KEYWORDS if k in url_path_query]
            if found_keywords:
                has_login_keywords = True
                raw_score += 30.0
                reasons.append(f"Credential harvesting indicators found in URL path: [{', '.join(found_keywords[:3])}]")
                checks.append({"status": "FAIL", "icon": "⚠", "text": f"Suspicious authentication keywords in path: {', '.join(found_keywords[:2])}"})

            # Check 8: Excessive subdomains (DGA/Phishing pattern)
            subdomain_parts = parsed_domain.split(".")
            if len(subdomain_parts) > 4:
                raw_score += 20.0
                reasons.append("Excessive subdomain depth detected — typical indicator of automated phishing kits")
                checks.append({"status": "WARN", "icon": "⚠", "text": "Excessive subdomain hierarchy depth"})

            # Check 9: Crypto Drainer / Airdrop Lure
            if "claim" in url_path_query or "airdrop" in url_path_query or "drainer" in url_path_query:
                has_crypto_keywords = True
                raw_score += 45.0
                reasons.append("Cryptocurrency drainer / fraudulent airdrop claim pattern detected")
                checks.append({"status": "FAIL", "icon": "⚠", "text": "Crypto asset drainer / fake airdrop signature"})
                authenticity = "SUSPICIOUS"
                authenticity_reason = "High-risk fraudulent airdrop claim pattern."

            # Check 10: Known Trusted Apex Domain (Authority Verification)
            if is_official:
                is_known_apex = True
                raw_score = min(raw_score, 10.0)
                reasons.append("Verified legitimate authority domain with established high reputation")
                checks.append({"status": "PASS", "icon": "✓", "text": "Verified official apex domain with established trust history"})
                authenticity = "VERIFIED"
                authenticity_reason = "Official domain with verified reputation."
                confidence_level = "HIGH"

            # Check 11: General Unknown / Unverified Web Domain
            if not is_known_apex and not reasons and raw_score < 15.0:
                if clean_payload.startswith("upi://"):
                    raw_score = 10.0
                    reasons.append("Standard merchant / peer-to-peer UPI payment format.")
                    checks.append({"status": "PASS", "icon": "✓", "text": "Valid UPI payment schema verified"})
                    authenticity = "VERIFIED"
                    authenticity_reason = "Standard UPI mobile payment protocol."
                    confidence_level = "HIGH"
                else:
                    raw_score = 32.0  # Fair unverified baseline
                    reasons.append("Domain reputation could not be verified with local threat intelligence.")
                    checks.append({"status": "WARN", "icon": "⚠", "text": "Domain reputation could not be independently verified"})
                    checks.append({"status": "PASS", "icon": "✓", "text": "No known phishing keywords or blacklisted patterns"})
                    authenticity = "UNVERIFIED"
                    authenticity_reason = "Unable to verify this destination with the available security intelligence."
                    confidence_level = "LOW"

        elif qr_type == "Wi-Fi Configuration":
            what_will_happen = "This QR code configures a Wi-Fi network connection."
            low_payload = clean_payload.lower()
            if "t:nopass" in low_payload or "t:none" in low_payload:
                raw_score = 30.0
                reasons.append("Open unencrypted Wi-Fi network configuration — network traffic may be intercepted.")
                checks.append({"status": "WARN", "icon": "⚠", "text": "Unencrypted Open Wi-Fi Network"})
                authenticity = "UNVERIFIED"
                authenticity_reason = "Open unencrypted network."
                confidence_level = "MEDIUM"
            else:
                raw_score = 8.0
                reasons.append("Standard encrypted Wi-Fi configuration (WPA/WPA2/WPA3).")
                checks.append({"status": "PASS", "icon": "✓", "text": "Standard WPA-secured Wi-Fi protocol"})
                authenticity = "VERIFIED"
                authenticity_reason = "Valid structured Wi-Fi network profile."
                confidence_level = "HIGH"

        elif qr_type == "Email Address / mailto":
            email_target = clean_payload.replace("mailto:", "").replace("MATMSG:TO:", "").split(";")[0].split("?")[0]
            what_will_happen = f"This QR code initiates an email draft to {email_target}."
            raw_score = 10.0
            reasons.append(f"Standard email recipient descriptor ({email_target}).")
            checks.append({"status": "PASS", "icon": "✓", "text": "Valid email dispatch URI"})
            authenticity = "VERIFIED"
            authenticity_reason = "Standard email dispatch format."
            confidence_level = "HIGH"

        elif qr_type == "Telephone Number / tel":
            phone_num = clean_payload.replace("tel:", "").strip()
            what_will_happen = f"This QR code prompts a phone call to {phone_num}."
            raw_score = 8.0
            reasons.append(f"Standard telephone dialer string ({phone_num}).")
            checks.append({"status": "PASS", "icon": "✓", "text": "Standard telephone dialing URI"})
            authenticity = "VERIFIED"
            authenticity_reason = "Standard telephony format."
            confidence_level = "HIGH"

        elif qr_type == "SMS":
            sms_target = clean_payload.replace("smsto:", "").replace("sms:", "").split(":")[0]
            what_will_happen = f"This QR code prepares an SMS text message to {sms_target}."
            if any(k in clean_payload.lower() for k in ["otp", "pin", "password", "bank"]):
                raw_score = 65.0
                reasons.append("SMS payload contains sensitive authentication keywords.")
                checks.append({"status": "FAIL", "icon": "⚠", "text": "SMS contains sensitive credential triggers"})
                authenticity = "SUSPICIOUS"
                authenticity_reason = "SMS lure requesting sensitive credentials."
                confidence_level = "HIGH"
            else:
                raw_score = 12.0
                reasons.append("Standard SMS dispatch string.")
                checks.append({"status": "PASS", "icon": "✓", "text": "Valid SMS messaging format"})
                authenticity = "VERIFIED"
                authenticity_reason = "Standard SMS format."
                confidence_level = "HIGH"

        elif qr_type == "Contact / vCard":
            what_will_happen = "This QR code adds a contact card (vCard) to your address book."
            raw_score = 6.0
            reasons.append("Standard vCard / MeCard electronic business card format.")
            checks.append({"status": "PASS", "icon": "✓", "text": "Standard vCard contact schema verified"})
            authenticity = "VERIFIED"
            authenticity_reason = "Standard contact card schema."
            confidence_level = "HIGH"

        elif qr_type == "Calendar / Event Data":
            what_will_happen = "This QR code adds an event to your calendar."
            raw_score = 6.0
            reasons.append("Standard iCalendar / vEvent calendar entry.")
            checks.append({"status": "PASS", "icon": "✓", "text": "Standard vEvent calendar schema verified"})
            authenticity = "VERIFIED"
            authenticity_reason = "Standard calendar event schema."
            confidence_level = "HIGH"

        elif qr_type == "App / Deep Link":
            what_will_happen = "This QR code attempts to open a native application."
            raw_score = 25.0
            reasons.append("Application deep link format.")
            checks.append({"status": "WARN", "icon": "⚠", "text": "Deep link delegates to external application"})
            authenticity = "UNVERIFIED"
            authenticity_reason = "Application deep link protocol."
            confidence_level = "MEDIUM"

        else:
            # Plain text / Custom
            what_will_happen = "This QR code displays plain text."
            if any(k in clean_payload.lower() for k in ["password", "private key", "seed phrase", "otp", "pin"]):
                raw_score = 75.0
                reasons.append("Payload exposes or requests sensitive authentication credentials.")
                checks.append({"status": "FAIL", "icon": "⚠", "text": "Sensitive credential keywords found in text"})
                authenticity = "SUSPICIOUS"
                authenticity_reason = "Contains exposed authentication secrets."
                confidence_level = "HIGH"
            elif len(clean_payload) > 800:
                raw_score = 25.0
                reasons.append("Unusually large encoded text payload.")
                checks.append({"status": "WARN", "icon": "⚠", "text": "Atypical large text data payload"})
                authenticity = "UNVERIFIED"
                authenticity_reason = "Unverified plain text data."
                confidence_level = "MEDIUM"
            else:
                raw_score = 6.0
                reasons.append("Benign structured text payload with no malicious indicators.")
                checks.append({"status": "PASS", "icon": "✓", "text": "Standard plain text payload verified"})
                authenticity = "VERIFIED"
                authenticity_reason = "Standard plain text content."
                confidence_level = "HIGH"

        # Final threat score calculation (0 to 100)
        final_threat_score = round(min(100.0, max(0.0, raw_score)), 1)
        
        # Determine Severity, Verdict, and Action
        if final_threat_score >= 80.0:
            severity = QRSeverity.CRITICAL.value
            verdict = "CRITICAL THREAT"
            classification = QRClassification.PHISHING.value if (has_login_keywords or has_punycode) else QRClassification.MALWARE.value
            action_text = "STOP PROCEEDING"
            action_type = "stop"
            is_blocked = True
        elif final_threat_score >= 60.0:
            severity = QRSeverity.HIGH_RISK.value
            verdict = "HIGH RISK"
            classification = QRClassification.CREDENTIAL_HARVESTING.value if has_login_keywords else QRClassification.SUSPICIOUS_REDIRECT.value
            action_text = "STOP PROCEEDING"
            action_type = "stop"
            is_blocked = True
        elif final_threat_score >= 40.0:
            severity = QRSeverity.SUSPICIOUS.value
            verdict = "MEDIUM RISK"
            classification = QRClassification.SUSPICIOUS_REDIRECT.value if is_shortened else QRClassification.UNKNOWN.value
            action_text = "PROCEED WITH CAUTION"
            action_type = "caution"
            is_blocked = False
        elif final_threat_score >= 20.0:
            severity = QRSeverity.LOW_RISK.value
            verdict = "UNKNOWN / UNVERIFIED" if authenticity == "UNVERIFIED" else "LOW RISK"
            classification = QRClassification.UNKNOWN.value if authenticity == "UNVERIFIED" else QRClassification.BENIGN.value
            action_text = "PROCEED WITH CAUTION"
            action_type = "caution"
            is_blocked = False
        else:
            severity = QRSeverity.SAFE.value
            verdict = "SAFE"
            classification = QRClassification.BENIGN.value
            action_text = "PROCEED"
            action_type = "proceed"
            is_blocked = False

        if not reasons:
            reasons.append("Destination passed all threat intelligence heuristics and reputation checks.")

        return {
            "threatScore": final_threat_score,
            "threat_score": final_threat_score,
            "severity": severity,
            "verdict": verdict,
            "classification": classification,
            "confidence": 0.96 if confidence_level == "HIGH" else 0.80 if confidence_level == "MEDIUM" else 0.65,
            "confidenceLevel": confidence_level,
            "authenticity": authenticity,
            "authenticityReason": authenticity_reason,
            "whatWillHappen": what_will_happen,
            "checks": checks,
            "reasons": reasons,
            "actionText": action_text,
            "actionType": action_type,
            "parsedDomain": parsed_domain,
            "qrType": qr_type,
            "isBlocked": is_blocked,
            "indicators": {
                "is_https": is_https,
                "is_ip_address": is_ip,
                "is_shortened": is_shortened,
                "has_suspicious_tld": has_suspicious_tld,
                "has_punycode": has_punycode,
                "has_login_keywords": has_login_keywords,
                "has_banking_keywords": has_banking_keywords,
                "has_crypto_keywords": has_crypto_keywords,
                "domain_reputation_score": domain_rep_score
            }
        }

    @classmethod
    def analyze_email_address(cls, email: str) -> Dict[str, Any]:
        """
        Email ID Security Analyzer:
        - Validates syntax
        - Domain reputation (disposable, typosquatting, lookalike, high-risk TLDs)
        - Does NOT declare fake simply because from Gmail/Yahoo/Outlook
        - Calculates risk score, confidence, threat level, authenticity
        """
        raw_email = email.replace("mailto:", "").replace("MATMSG:TO:", "").strip()
        match = re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw_email)
        clean_email = match.group(0) if match else raw_email

        parts = clean_email.split("@")
        if len(parts) != 2:
            return {
                "detected_type": "EMAIL ID DETECTED",
                "email": clean_email,
                "domain": "",
                "threat_score": 42.0,
                "threat_level": "MEDIUM RISK",
                "confidence": 0.70,
                "authenticity": "UNVERIFIED",
                "analysis_reasons": ["Invalid email syntax structure."],
                "checks": [{"status": "WARN", "icon": "⚠", "text": "Invalid email syntax structure"}],
                "recommended_action": "Verify email recipient address before responding.",
                "is_blocked": False
            }

        user_part, domain = parts[0], parts[1].lower()
        tld = domain.split(".")[-1] if "." in domain else ""

        reasons = []
        checks = []
        raw_score = 10.0

        FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "protonmail.com", "proton.me", "aol.com"}
        DISPOSABLE_DOMAINS = {"tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com", "throwaway.com", "dispostable.com", "trashmail.com", "temp-mail.org"}

        is_disposable = domain in DISPOSABLE_DOMAINS
        is_free_provider = domain in FREE_EMAIL_PROVIDERS
        is_official = domain in TRUSTED_DOMAINS

        matched_brands = [b for b in TARGETED_BRANDS if b in domain]

        if is_disposable:
            raw_score += 65.0
            reasons.append(f"Temporary / disposable email domain ({domain}) commonly used in fraudulent activities.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": "Disposable / temporary email domain"})
            authenticity = "SUSPICIOUS"
        elif matched_brands and not is_official:
            raw_score += 60.0
            brand_name = matched_brands[0].capitalize()
            reasons.append(f"Potential brand impersonation: email domain '{domain}' mimics brand '{brand_name}' without official authorization.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": f"Lookalike domain mimicking brand '{brand_name}'"})
            authenticity = "SUSPICIOUS"
        elif tld in HIGH_RISK_TLDS:
            raw_score += 45.0
            reasons.append(f"High-risk top level domain (.{tld}) with elevated phishing frequency.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": f"High-risk disposable TLD (.{tld})"})
            authenticity = "SUSPICIOUS"
        elif is_free_provider:
            raw_score = 15.0
            reasons.append(f"Standard public webmail provider ({domain}). Sender identity is unverified.")
            checks.append({"status": "PASS", "icon": "✓", "text": f"Valid public webmail provider ({domain})"})
            checks.append({"status": "WARN", "icon": "⚠", "text": "Personal email domain cannot guarantee corporate identity"})
            authenticity = "UNVERIFIED"
        elif is_official:
            raw_score = 5.0
            reasons.append(f"Verified official organizational domain ({domain}).")
            checks.append({"status": "PASS", "icon": "✓", "text": "Verified official domain"})
            authenticity = "VERIFIED"
        else:
            raw_score = 28.0
            reasons.append("Email domain active but domain reputation could not be independently verified.")
            checks.append({"status": "WARN", "icon": "⚠", "text": "Domain reputation could not be independently verified"})
            authenticity = "UNVERIFIED"

        if "xn--" in domain:
            raw_score += 40.0
            reasons.append("Punycode (IDN homograph) encoding detected in email domain.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": "Punycode (IDN homograph) encoding detected"})
            authenticity = "SUSPICIOUS"

        score = round(min(100.0, max(0.0, raw_score)), 1)
        if score >= 80:
            threat_level = "CRITICAL"
        elif score >= 60:
            threat_level = "HIGH RISK"
        elif score >= 40:
            threat_level = "MEDIUM RISK"
        elif score >= 20:
            threat_level = "LOW RISK"
        else:
            threat_level = "SAFE"

        return {
            "detected_type": "EMAIL ID DETECTED",
            "email": clean_email,
            "domain": domain,
            "threat_score": score,
            "threat_level": threat_level,
            "confidence": 0.92 if is_official or is_disposable else 0.75,
            "authenticity": authenticity,
            "analysis_reasons": reasons,
            "checks": checks,
            "recommended_action": "STOP PROCEEDING" if score >= 60 else "PROCEED WITH CAUTION" if score >= 20 else "PROCEED",
            "is_blocked": score >= 60
        }

    @classmethod
    def analyze_notification_message(cls, message_text: str, source_app: str = "") -> Dict[str, Any]:
        """
        Notification / Message Security Analyzer (AI Helpline Integration):
        - Analyzes text for phishing, scam language, fake rewards, fake bank, fake gov, urgency/manipulation, OTP/password/payment requests, impersonation
        - Extracts embedded URL and/or Email if present
        - Produces status: REAL / LIKELY REAL, SUSPICIOUS, LIKELY FAKE, UNKNOWN / UNVERIFIED
        """
        from app.ml.social_engineering_nlp import social_engineering_analyzer
        nlp_res = social_engineering_analyzer.analyze(message_text, sender_context=source_app)

        raw_score = nlp_res.overall_manipulation_score * 100.0
        reasons = []
        checks = []

        low = message_text.lower()

        has_urgency = any(k in low for k in ["urgent", "immediately", "today", "within 24 hours", "act now", "deadline", "blocked", "suspended"])
        has_bank_gov = any(k in low for k in ["bank", "irs", "police", "gov", "account", "security team", "customer support", "tax", "court"])
        has_reward = any(k in low for k in ["reward", "winner", "lottery", "prize", "gift card", "crypto", "free", "cash", "bonus"])
        has_secret_req = any(k in low for k in ["otp", "password", "pin", "cvv", "verification code", "credentials", "access code"])
        has_payment_req = any(k in low for k in ["pay", "payment", "wire", "transfer", "crypto", "bitcoin", "fee", "fine"])

        if has_urgency:
            reasons.append("Urgent / threatening psychological pressure tactics detected.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": "High urgency / threat language"})

        if has_bank_gov:
            reasons.append("Impersonation of banking or government entity.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": "Possible bank or authority impersonation"})

        if has_reward:
            reasons.append("Fake reward / financial incentive lure detected.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": "Fake prize / reward bait"})

        if has_secret_req:
            reasons.append("Request for sensitive authentication details (OTP / Password / PIN).")
            checks.append({"status": "FAIL", "icon": "⚠", "text": "Requests OTP, password, or security credential"})

        if has_payment_req:
            reasons.append("Unverified request for immediate payment or financial transfer.")
            checks.append({"status": "FAIL", "icon": "⚠", "text": "Financial payment request"})

        # Check embedded URLs
        url_match = re.search(r"https?://[^\s]+", message_text)
        url_analysis = None
        if url_match:
            extracted_url = url_match.group(0)
            reasons.append(f"Suspicious embedded URL detected: {extracted_url}")
            checks.append({"status": "FAIL", "icon": "⚠", "text": f"Embedded link: {extracted_url}"})
            url_analysis = cls.analyze_payload(extracted_url)
            raw_score = max(raw_score, url_analysis.get("threat_score", 0.0))

        # Check embedded Email
        email_match = re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", message_text)
        email_analysis = None
        if email_match:
            extracted_email = email_match.group(0)
            reasons.append(f"Embedded email address detected: {extracted_email}")
            checks.append({"status": "WARN", "icon": "⚠", "text": f"Embedded contact email: {extracted_email}"})
            email_analysis = cls.analyze_email_address(extracted_email)
            raw_score = max(raw_score, email_analysis.get("threat_score", 0.0))

        # Boost raw_score based on critical scam combinations
        if has_secret_req:
            raw_score = max(raw_score, 85.0)
            if has_urgency or has_bank_gov:
                raw_score = max(raw_score, 91.0)
        elif has_bank_gov and (has_urgency or url_match):
            raw_score = max(raw_score, 82.0)
        elif has_reward and (has_urgency or url_match):
            raw_score = max(raw_score, 85.0)
        elif has_urgency and url_match:
            raw_score = max(raw_score, 80.0)

        score = round(min(100.0, max(0.0, raw_score)), 1)

        if score >= 75.0 or (has_secret_req and (has_urgency or has_bank_gov)):
            status_verdict = "LIKELY FAKE"
            threat_level = "CRITICAL"
        elif score >= 50.0 or has_urgency or url_match:
            status_verdict = "SUSPICIOUS"
            threat_level = "HIGH RISK"
        elif score >= 25.0:
            status_verdict = "UNKNOWN / UNVERIFIED"
            threat_level = "MEDIUM RISK"
        elif len(message_text.strip()) > 10 and not reasons:
            status_verdict = "REAL / LIKELY REAL"
            threat_level = "SAFE"
        else:
            status_verdict = "UNKNOWN / UNVERIFIED"
            threat_level = "LOW RISK"

        if not reasons:
            reasons.append("No obvious psychological manipulation or fraudulent cues detected in message.")
            checks.append({"status": "PASS", "icon": "✓", "text": "No suspicious fraudulent patterns detected"})

        return {
            "detected_type": "NOTIFICATION DETECTED",
            "extracted_message": message_text,
            "status": status_verdict,
            "status_verdict": status_verdict,
            "threat_score": score,
            "threat_level": threat_level,
            "confidence": 0.90 if status_verdict in ("LIKELY FAKE", "REAL / LIKELY REAL") else 0.70,
            "ai_helpline_analysis": nlp_res.summary_analysis,
            "remediation_guidance": nlp_res.remediation_guidance,
            "analysis_reasons": reasons,
            "checks": checks,
            "embedded_url_analysis": url_analysis,
            "embedded_email_analysis": email_analysis,
            "recommended_action": "STOP PROCEEDING" if score >= 60 else "PROCEED WITH CAUTION" if score >= 20 else "PROCEED",
            "is_blocked": score >= 60
        }

    @classmethod
    def classify_universal_target(cls, text: str, qr_codes: List[Dict[str, Any]] = None) -> Tuple[str, Any]:
        """
        Intelligently classifies target into one of:
        - 'QR CODE DETECTED'
        - 'URL DETECTED'
        - 'EMAIL ID DETECTED'
        - 'NOTIFICATION DETECTED'
        - 'NOTHING SUPPORTED'
        """
        if qr_codes and len(qr_codes) > 0:
            return "QR CODE DETECTED", qr_codes[0]

        s = (text or "").strip()
        if not s:
            return "NOTHING SUPPORTED", None

        # Check clean single URL
        url_pattern = r"^https?://[^\s]+$"
        if re.match(url_pattern, s):
            return "URL DETECTED", s

        # Check standalone email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, s):
            return "EMAIL ID DETECTED", s

        # Bare domain / URL shortener like bit.ly/123 or example.com/login
        if (s.startswith("www.") or ".com" in s or ".org" in s or ".xyz" in s or ".top" in s) and " " not in s and len(s) < 150:
            return "URL DETECTED", s if s.startswith("http") else f"https://{s}"

        # If text starts with "mailto:" or "support@"
        if s.lower().startswith("mailto:") or (s.startswith("support@") and " " not in s):
            return "EMAIL ID DETECTED", s

        # Notification / message triggers
        low = s.lower()
        NOTIF_TRIGGERS = [
            "urgent", "urgently", "immediately", "account", "bank", "click", "contact", "alert", "verify",
            "message", "notification", "your", "today", "blocked", "suspended", "notice", "payout", "winner",
            "prize", "reward", "security", "support", "team", "otp", "password", "pin", "code", "payment",
            "transfer", "crypto", "action", "required"
        ]

        has_notif_keyword = any(k in low for k in NOTIF_TRIGGERS)
        has_embedded_url = bool(re.search(r"https?://", s)) or ("www." in low or ".xyz" in low or ".top" in low)
        has_embedded_email = bool(re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", s))

        if has_notif_keyword or has_embedded_url or has_embedded_email:
            return "NOTIFICATION DETECTED", s

        # Plain text without supported targets
        return "NOTHING SUPPORTED", None


    @classmethod
    def calculate_decision_guidance(cls, threat_level: str, threat_score: float) -> str:
        """
        Decision Layer Guidance for AI Helpline & User popups:
        - SAFE: Proceeding appears reasonable based on the available security analysis.
        - LOW RISK: No major threat indicators were detected, but continue with normal caution.
        - MEDIUM RISK: Proceed with caution. Verify the source before continuing.
        - HIGH RISK: Do not proceed until you independently verify the source.
        - CRITICAL: Do not proceed. Treat this as potentially malicious or fraudulent.
        """
        lvl = (threat_level or "").upper()
        if lvl == "SAFE" or threat_score < 20:
            return "Proceeding appears reasonable based on the available security analysis."
        elif lvl == "LOW RISK" or threat_score < 40:
            return "No major threat indicators were detected, but continue with normal caution."
        elif lvl == "MEDIUM RISK" or threat_score < 60:
            return "Proceed with caution. Verify the source before continuing."
        elif lvl == "HIGH RISK" or threat_score < 80:
            return "Do not proceed until you independently verify the source."
        else:
            return "Do not proceed. Treat this as potentially malicious or fraudulent."

    @classmethod
    def analyze_barcode(cls, barcode_val: str, format_name: str = "Barcode") -> Dict[str, Any]:
        """
        Barcode Security Analyzer:
        - Decodes value
        - Checks if decoded value is a valid URL
        - If valid URL -> routes to URL threat analysis
        - If numeric/product code -> classifies as Product ID with SAFE status (no fake threat score)
        """
        val = (barcode_val or "").strip()
        from app.utils.url_validator import validate_strict_url
        is_valid_url, _ = validate_strict_url(val)

        if is_valid_url:
            url_res = cls.analyze_payload(val)
            url_res["detected_type"] = "BARCODE DETECTED (URL)"
            url_res["barcode_val"] = val
            url_res["barcode_format"] = format_name
            url_res["is_url"] = True
            url_res["decision_guidance"] = cls.calculate_decision_guidance(url_res.get("verdict", "SAFE"), url_res.get("threat_score", 0.0))
            return url_res

        is_numeric = val.isdigit() and len(val) >= 8
        reasons = ["Standard 1D product barcode identifier."] if is_numeric else ["Decoded barcode text payload."]
        checks = [{"status": "PASS", "icon": "✓", "text": "Product barcode identifier verified (No web links)"}] if is_numeric else [{"status": "PASS", "icon": "✓", "text": "Valid barcode data"}]

        return {
            "detected_type": "BARCODE DETECTED",
            "barcode_val": val,
            "barcode_format": format_name,
            "is_url": False,
            "threat_score": 0.0 if is_numeric else 10.0,
            "threat_level": "SAFE",
            "confidence": 0.98,
            "authenticity": "VERIFIED" if is_numeric else "UNVERIFIED",
            "analysis_reasons": reasons,
            "checks": checks,
            "recommended_action": "PROCEED",
            "decision_guidance": "Proceeding appears reasonable based on the available security analysis.",
            "is_blocked": False
        }

    @classmethod
    def analyze_mixed_content(cls, text: str = "", qr_codes: List[Dict[str, Any]] = None, barcodes: List[Dict[str, Any]] = None, page_url: str = "") -> Dict[str, Any]:
        """
        Multi-component analysis for mixed content (Text + URL + QR + Barcode).
        Evaluates each component individually and generates a combined security assessment.
        """
        components = []
        max_score = 0.0
        all_reasons = []

        if qr_codes and len(qr_codes) > 0:
            for qr in qr_codes:
                q_payload = qr.get("payload", "") if isinstance(qr, dict) else str(qr)
                q_res = cls.analyze_payload(q_payload, page_url=page_url)
                components.append({"type": "QR CODE", "target": q_payload, "result": q_res})
                if q_res.get("threat_score", 0) > max_score:
                    max_score = q_res.get("threat_score", 0)

        if barcodes and len(barcodes) > 0:
            for bc in barcodes:
                b_val = bc.get("rawValue", bc.get("payload", "")) if isinstance(bc, dict) else str(bc)
                b_fmt = bc.get("format", "Barcode") if isinstance(bc, dict) else "Barcode"
                b_res = cls.analyze_barcode(b_val, b_fmt)
                components.append({"type": "BARCODE", "target": b_val, "result": b_res})
                if b_res.get("threat_score", 0) > max_score:
                    max_score = b_res.get("threat_score", 0)

        if text and len(text.strip()) > 5:
            from app.utils.url_validator import validate_strict_url
            url_match = re.search(r"https?://[^\s]+", text)
            if url_match:
                url_str = url_match.group(0)
                is_valid, _ = validate_strict_url(url_str)
                if is_valid:
                    u_res = cls.analyze_payload(url_str, page_url=page_url)
                    components.append({"type": "EMBEDDED URL", "target": url_str, "result": u_res})
                    if u_res.get("threat_score", 0) > max_score:
                        max_score = u_res.get("threat_score", 0)

            m_res = cls.analyze_notification_message(text)
            components.append({"type": "MESSAGE / TEXT", "target": text[:100], "result": m_res})
            if m_res.get("threat_score", 0) > max_score:
                max_score = m_res.get("threat_score", 0)

        if max_score >= 80:
            overall_level = "CRITICAL"
        elif max_score >= 60:
            overall_level = "HIGH RISK"
        elif max_score >= 40:
            overall_level = "MEDIUM RISK"
        elif max_score >= 20:
            overall_level = "LOW RISK"
        else:
            overall_level = "SAFE"

        for comp in components:
            all_reasons.extend(comp["result"].get("analysis_reasons", comp["result"].get("reasons", [])))

        decision = cls.calculate_decision_guidance(overall_level, max_score)

        return {
            "detected_type": "MIXED CONTENT DETECTED",
            "components": components,
            "threat_score": max_score,
            "threat_level": overall_level,
            "confidence": 0.94,
            "analysis_reasons": list(set(all_reasons)),
            "decision_guidance": decision,
            "recommended_action": "STOP PROCEEDING" if max_score >= 60 else "PROCEED WITH CAUTION" if max_score >= 20 else "PROCEED",
            "is_blocked": max_score >= 60
        }

    @classmethod
    def classify_universal_target(cls, text: str, qr_codes: List[Dict[str, Any]] = None, barcodes: List[Dict[str, Any]] = None) -> Tuple[str, Any]:
        """
        Intelligently classifies target into one of:
        - 'QR CODE DETECTED'
        - 'BARCODE DETECTED'
        - 'URL DETECTED'
        - 'EMAIL ID DETECTED'
        - 'NOTIFICATION DETECTED'
        - 'MIXED CONTENT DETECTED'
        - 'NOTHING SUPPORTED'
        """
        has_qr = qr_codes and len(qr_codes) > 0
        has_bc = barcodes and len(barcodes) > 0
        s = (text or "").strip()

        # Mixed content check
        if (has_qr and (s or has_bc)) or (has_bc and s):
            return "MIXED CONTENT DETECTED", {"qr_codes": qr_codes, "barcodes": barcodes, "text": s}

        if has_qr:
            return "QR CODE DETECTED", qr_codes[0]

        if has_bc:
            return "BARCODE DETECTED", barcodes[0]

        if not s:
            return "NOTHING SUPPORTED", None

        # Validate URL strictly
        from app.utils.url_validator import validate_strict_url
        is_valid_url, _ = validate_strict_url(s)
        if is_valid_url:
            return "URL DETECTED", s

        # Standalone email
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if re.match(email_pattern, s):
            return "EMAIL ID DETECTED", s

        if s.lower().startswith("mailto:") or (s.startswith("support@") and " " not in s):
            return "EMAIL ID DETECTED", s

        # Notification / message triggers
        low = s.lower()
        NOTIF_TRIGGERS = [
            "urgent", "urgently", "immediately", "account", "bank", "click", "contact", "alert", "verify",
            "message", "notification", "your", "today", "blocked", "suspended", "notice", "payout", "winner",
            "prize", "reward", "security", "support", "team", "otp", "password", "pin", "code", "payment",
            "transfer", "crypto", "action", "required", "congratulations", "claim", "won", "reward"
        ]

        has_notif_keyword = any(k in low for k in NOTIF_TRIGGERS)
        has_embedded_url = bool(re.search(r"https?://", s)) or ("www." in low or ".xyz" in low or ".top" in low)
        has_embedded_email = bool(re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", s))

        if has_notif_keyword or has_embedded_url or has_embedded_email:
            return "NOTIFICATION DETECTED", s

        # Plain text without supported targets or invalid URLs (e.g. 'hello-world')
        return "NOTHING SUPPORTED", None

    @classmethod
    def analyze_universal(
        cls,
        text: str = "",
        qr_codes: List[Dict[str, Any]] = None,
        barcodes: List[Dict[str, Any]] = None,
        page_url: str = "",
        page_title: str = ""
    ) -> Dict[str, Any]:
        """
        Universal Essential Key Smart Region Scanner Pipeline:
        1. Classifies target
        2. Executes strict type-specific analyzer
        3. Returns standardized security response with decision guidance and AI Helpline context
        """
        target_type, target_obj = cls.classify_universal_target(text, qr_codes, barcodes)

        if target_type == "MIXED CONTENT DETECTED":
            return cls.analyze_mixed_content(text=text, qr_codes=qr_codes, barcodes=barcodes, page_url=page_url)

        elif target_type == "QR CODE DETECTED":
            qr_payload = target_obj.get("payload") if isinstance(target_obj, dict) else str(target_obj)
            payload_type = cls.classify_payload_type(qr_payload)

            from app.utils.url_validator import validate_strict_url
            is_valid_url, _ = validate_strict_url(qr_payload)

            if is_valid_url:
                res = cls.analyze_payload(qr_payload, page_url=page_url)
            else:
                res = cls.analyze_payload(qr_payload, page_url=page_url)

            decision = cls.calculate_decision_guidance(res.get("verdict", "SAFE"), res.get("threat_score", 0.0))

            return {
                "detected_type": "QR CODE DETECTED",
                "qr_type": payload_type,
                "decoded_payload": qr_payload,
                "is_valid_url": is_valid_url,
                "bounding_box": target_obj.get("boundingBox") if isinstance(target_obj, dict) else None,
                "analysis": res,
                "threat_score": res.get("threat_score", 0.0),
                "threat_level": res.get("verdict", "SAFE"),
                "confidence": res.get("confidence", 0.95),
                "decision_guidance": decision,
                "is_blocked": res.get("isBlocked", False)
            }

        elif target_type == "BARCODE DETECTED":
            b_val = target_obj.get("rawValue", target_obj.get("payload", "")) if isinstance(target_obj, dict) else str(target_obj)
            b_fmt = target_obj.get("format", "Barcode") if isinstance(target_obj, dict) else "Barcode"
            return cls.analyze_barcode(b_val, format_name=b_fmt)

        elif target_type == "URL DETECTED":
            url_res = cls.analyze_payload(target_obj, page_url=page_url)
            decision = cls.calculate_decision_guidance(url_res.get("verdict", "SAFE"), url_res.get("threat_score", 0.0))
            return {
                "detected_type": "URL DETECTED",
                "url": target_obj,
                "domain": url_res.get("parsedDomain", ""),
                "is_https": url_res.get("indicators", {}).get("is_https", target_obj.startswith("https://")),
                "threat_score": url_res.get("threat_score", 0.0),
                "threat_level": url_res.get("verdict", "SAFE"),
                "confidence": url_res.get("confidence", 0.95),
                "authenticity": url_res.get("authenticity", "UNVERIFIED"),
                "analysis_reasons": url_res.get("reasons", []),
                "checks": url_res.get("checks", []),
                "recommended_action": url_res.get("actionText", "PROCEED"),
                "decision_guidance": decision,
                "is_blocked": url_res.get("isBlocked", False)
            }

        elif target_type == "EMAIL ID DETECTED":
            res = cls.analyze_email_address(target_obj)
            res["decision_guidance"] = cls.calculate_decision_guidance(res.get("threat_level", "SAFE"), res.get("threat_score", 0.0))
            return res

        elif target_type == "NOTIFICATION DETECTED":
            res = cls.analyze_notification_message(target_obj, source_app=page_title or "Visible Tab")
            res["decision_guidance"] = cls.calculate_decision_guidance(res.get("threat_level", "SAFE"), res.get("threat_score", 0.0))
            return res

        else:
            return {
                "detected_type": "NOTHING SUPPORTED",
                "message": "Unable to scan this selected area. No supported URL, QR code, barcode, or readable text was detected.",
                "threat_score": 0.0,
                "threat_level": "SAFE",
                "confidence": 1.0,
                "decision_guidance": "No threats detected on blank/unsupported area.",
                "is_blocked": False
            }


qr_threat_engine = QRThreatEngine()



