"""
Strict URL Validation Utility for PhishGuard Threat Analysis Engine.
"""

import re
from urllib.parse import urlparse
from typing import Tuple


def validate_strict_url(target: str) -> Tuple[bool, str]:
    """
    Validates that target is strictly a valid HTTP/HTTPS URL.
    Returns (is_valid, error_message).
    """
    if not target or not isinstance(target, str):
        return False, "It is not a valid URL"

    trimmed = target.strip()
    if not trimmed:
        return False, "It is not a valid URL"

    # Must start with http:// or https://
    if not re.match(r"^https?://", trimmed, re.IGNORECASE):
        return False, "It is not a valid URL"

    # Reject internal spaces
    if any(c.isspace() for c in trimmed):
        return False, "It is not a valid URL"

    # Reject prohibited schemes
    if re.match(r"^(javascript|data|file|ftp|mailto|about|blob|vbscript):", trimmed, re.IGNORECASE):
        return False, "It is not a valid URL"

    try:
        parsed = urlparse(trimmed)

        # Protocol must be http or https
        if parsed.scheme.lower() not in ("http", "https"):
            return False, "It is not a valid URL"

        hostname = parsed.hostname
        if not hostname:
            return False, "It is not a valid URL"

        # Hostname cannot contain spaces or invalid control characters
        if re.search(r"[\s\r\n\t]", hostname):
            return False, "It is not a valid URL"

        # Cannot be plain single number (e.g. http://123456789)
        if hostname.isdigit():
            return False, "It is not a valid URL"

        # Check IPv4
        ipv4_match = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname)
        if ipv4_match:
            parts = [int(p) for p in hostname.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return True, ""
            return False, "It is not a valid URL"

        # Check localhost or bracketed IPv6
        if hostname == "localhost" or (hostname.startswith("[") and hostname.endswith("]")):
            return True, ""

        # Standard domain must contain at least one dot
        if "." not in hostname:
            return False, "It is not a valid URL"

        domain_parts = hostname.split(".")
        tld = domain_parts[-1]

        # TLD must be at least 2 chars and not all numeric
        if len(tld) < 2 or tld.isdigit() or not re.match(r"^[a-zA-Z0-9-]+$", tld):
            return False, "It is not a valid URL"

        for part in domain_parts:
            if not part or part.startswith("-") or part.endsWith("-") if hasattr(part, "endsWith") else part.endswith("-"):
                return False, "It is not a valid URL"
            if not re.match(r"^[a-zA-Z0-9-]+$", part):
                return False, "It is not a valid URL"

        return True, ""
    except Exception:
        return False, "It is not a valid URL"
