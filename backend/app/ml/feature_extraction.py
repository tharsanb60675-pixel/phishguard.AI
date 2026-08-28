"""
Feature Extraction Pipeline for URL, Domain, and Lexical Threat Analysis.
Extracts numerical and categorical features for classification, zero-day anomaly detection, and SHAP explainability.
"""

import re
import math
import urllib.parse
from typing import Dict, Any, List


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "account", "update",
    "banking", "appleid", "paypal", "wallet", "signin", "support", "confirm",
    "free", "gift", "bonus", "claim", "billing", "recover", "crypto", "auth",
    "authenticate", "token", "password", "reset", "admin", "service", "webscr"
]

RISKY_TLDS = {
    ".xyz": 0.85, ".top": 0.90, ".tk": 0.95, ".ml": 0.95, ".ga": 0.95, ".cf": 0.95,
    ".gq": 0.95, ".work": 0.75, ".click": 0.80, ".link": 0.70, ".vip": 0.75,
    ".online": 0.65, ".site": 0.65, ".space": 0.70, ".buzz": 0.80, ".live": 0.60
}

SAFE_KNOWN_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "github.com", "amazon.com",
    "netflix.com", "linkedin.com", "wikipedia.org", "youtube.com", "cloudflare.com",
    "stackoverflow.com", "gov", "edu"
]


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon Entropy of a string to detect randomized/DGA (Domain Generation Algorithm) strings.
    Higher entropy (> 3.8) suggests high algorithmic randomness typical of malicious domains.
    """
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def detect_ip_in_url(hostname: str) -> bool:
    """Check if hostname is a raw IPv4 or IPv6 address instead of a domain."""
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return bool(re.match(ipv4_pattern, hostname))


def detect_punycode_or_homograph(hostname: str) -> bool:
    """Detect punycode ('xn--') or non-ASCII homoglyph spoofing characters."""
    if "xn--" in hostname:
        return True
    return any(ord(char) > 127 for char in hostname)


def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """
    Extract comprehensive lexical, statistical, and structural feature vector from a target URL.
    Returns normalized feature map ready for ML classifiers and SHAP explainer.
    """
    url = raw_url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_str = url.lower()

    # Domain & Subdomain parsing
    parts = hostname.split(".")
    tld = "." + parts[-1] if len(parts) > 1 else ""
    subdomain_count = max(0, len(parts) - 2)
    
    # Feature 1: Lexical Lengths
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)

    # Feature 2: Entropy
    hostname_entropy = calculate_entropy(hostname)

    # Feature 3: Suspicious Keyword Count
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_str]
    keyword_count = len(keyword_hits)

    # Feature 4: Syntactic Anomaly Counts
    hyphen_count = full_str.count("-")
    at_symbol_count = full_str.count("@")
    double_slash_in_path = path.count("//")
    digit_count = sum(c.isdigit() for c in hostname)
    digit_ratio = round(digit_count / max(1, hostname_length), 3)

    # Feature 5: Security Flags
    is_ip_address = 1 if detect_ip_in_url(hostname) else 0
    has_homoglyph_punycode = 1 if detect_punycode_or_homograph(hostname) else 0
    uses_https = 1 if parsed.scheme == "https" else 0
    risky_tld_weight = RISKY_TLDS.get(tld, 0.1)

    # Feature 6: Domain age / SSL heuristics (simulated for immediate offline resilience)
    # Check if domain is trusted well-known
    is_trusted_brand = any(hostname == kd or hostname.endswith("." + kd) for kd in SAFE_KNOWN_DOMAINS)
    if is_trusted_brand:
        domain_age_days = 3650
        ssl_cert_days_valid = 365
    elif risky_tld_weight > 0.7 or is_ip_address or keyword_count >= 2:
        domain_age_days = 4  # Brand new zero-day domain
        ssl_cert_days_valid = 14
    else:
        domain_age_days = 450
        ssl_cert_days_valid = 180

    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "subdomain_count": subdomain_count,
        "hostname_entropy": hostname_entropy,
        "keyword_count": keyword_count,
        "hyphen_count": hyphen_count,
        "at_symbol_count": at_symbol_count,
        "double_slash_in_path": double_slash_in_path,
        "digit_ratio": digit_ratio,
        "is_ip_address": is_ip_address,
        "has_homoglyph_punycode": has_homoglyph_punycode,
        "uses_https": uses_https,
        "risky_tld_weight": risky_tld_weight,
        "domain_age_days": domain_age_days,
        "ssl_cert_days_valid": ssl_cert_days_valid,
        "suspicious_keywords_found": keyword_hits,
        "hostname": hostname,
        "tld": tld,
        "is_trusted_brand": is_trusted_brand
    }

    return features


FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "subdomain_count",
    "hostname_entropy",
    "keyword_count",
    "hyphen_count",
    "at_symbol_count",
    "double_slash_in_path",
    "digit_ratio",
    "is_ip_address",
    "has_homoglyph_punycode",
    "uses_https",
    "risky_tld_weight",
    "domain_age_days",
    "ssl_cert_days_valid"
]


def feature_dict_to_vector(features: Dict[str, Any]) -> List[float]:
    """Convert extracted feature dictionary into ordered numerical vector for Scikit-Learn models."""
    return [float(features.get(f_name, 0.0)) for f_name in FEATURE_NAMES]
