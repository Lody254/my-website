
import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "account",
    "update",
    "secure",
    "password",
    "banking",
    "confirm",
    "signin",
    "wallet"
]

SHORTENED_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly"
]


def detect_phishing(url):

    result = {
        "risk_score": 0,
        "warnings": [],
        "status": "Low risk"
    }

    url = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname or parsed.scheme not in ["http", "https"]:
            raise ValueError("Invalid URL")

    except ValueError:
        return {
            "risk_score": 100,
            "warnings": ["Invalid website URL"],
            "status": "Invalid URL"
        }

    score = 0
    warnings = []

    # Check HTTPS
    if parsed.scheme != "https":
        score += 15
        warnings.append("Website does not use HTTPS")

    # Check URL length
    if len(url) > 75:
        score += 10
        warnings.append("Unusually long URL")

    # Check IP address
    try:
        ipaddress.ip_address(hostname)
        score += 25
        warnings.append("Website uses an IP address")
    except ValueError:
        pass

    # Check suspicious keywords
    found_words = [
        word for word in SUSPICIOUS_WORDS
        if word in url.lower()
    ]

    if found_words:
        score += min(len(found_words) * 5, 20)
        warnings.append(
            "Suspicious keywords: " + ", ".join(found_words)
        )

    # Check shortened URLs
    if hostname.lower() in SHORTENED_DOMAINS:
        score += 20
        warnings.append("Uses a URL shortening service")

    # Check @ symbol
    if "@" in url:
        score += 20
        warnings.append("URL contains an @ symbol")

    # Check excessive hyphens
    if hostname.count("-") >= 3:
        score += 10
        warnings.append("Domain contains many hyphens")

    # Check multiple subdomains
    if len(hostname.split(".")) >= 5:
        score += 10
        warnings.append("Unusually many subdomains")

    score = min(score, 100)

    if score >= 60:
        status = "High risk"
    elif score >= 30:
        status = "Medium risk"
    else:
        status = "Low risk"

    if not warnings:
        warnings.append(
            "No suspicious patterns detected"
        )

    return {
        "risk_score": score,
        "warnings": warnings,
        "status": status
    }
