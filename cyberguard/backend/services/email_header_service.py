# backend/services/email_header_service.py
"""Email header parsing and SPF/DKIM/DMARC authentication service for CyberGuard.

Parses raw MIME/RFC 822 email headers to detect domain spoofing,
Return-Path mismatches, and authentication status failures.
"""

import re
from typing import Dict, Tuple

def parse_email_headers(raw_text: str) -> Tuple[Dict[str, int], Dict[str, str]]:
    """Parse raw email headers and return contribution scores + parsed metadata.

    Returns:
        contributions: Dict[str, int] mapping evidence keys to risk weights.
        headers_info: Dict[str, str] extracted header metadata.
    """
    contributions: Dict[str, int] = {}
    headers_info: Dict[str, str] = {}

    lines = raw_text.splitlines()

    # Extract key header fields
    for line in lines:
        if line.lower().startswith("from:"):
            headers_info["from"] = line[5:].strip()
        elif line.lower().startswith("return-path:"):
            headers_info["return_path"] = line[12:].strip("<> ")
        elif line.lower().startswith("reply-to:"):
            headers_info["reply_to"] = line[9:].strip()
        elif line.lower().startswith("authentication-results:"):
            headers_info["auth_results"] = headers_info.get("auth_results", "") + " " + line[23:].strip()
        elif line.lower().startswith("received-spf:"):
            headers_info["spf_header"] = line[13:].strip()

    # 1. Check From vs Return-Path domain mismatch (Email Spoofing)
    from_str = headers_info.get("from", "")
    return_path = headers_info.get("return_path", "")

    from_domain = ""
    if "@" in from_str:
        from_domain = from_str.split("@")[-1].split(">")[0].strip().lower()

    return_domain = ""
    if "@" in return_path:
        return_domain = return_path.split("@")[-1].strip().lower()

    if from_domain and return_domain and from_domain != return_domain:
        contributions["SPOOFED_RETURN_PATH_DOMAIN"] = 45

    # 2. Check SPF Authentication status
    combined_auth = (headers_info.get("auth_results", "") + " " + headers_info.get("spf_header", "")).lower()
    if "spf=fail" in combined_auth or "spf=softfail" in combined_auth:
        contributions["SPF_AUTHENTICATION_FAIL"] = 40

    # 3. Check DKIM Authentication status
    if "dkim=fail" in combined_auth:
        contributions["DKIM_SIGNATURE_FAIL"] = 35

    # 4. Check DMARC Authentication status
    if "dmarc=fail" in combined_auth:
        contributions["DMARC_POLICY_FAIL"] = 45

    return contributions, headers_info
