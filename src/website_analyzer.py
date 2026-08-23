import re
import ipaddress
from urllib.parse import urlparse

import tldextract


def analyze_website_url(url):
    """
    Safely analyze a website URL without visiting the website.
    """

    findings = []
    score = 0

    # ------------------------------------------
    # BASIC URL VALIDATION
    # ------------------------------------------

    url = url.strip()

    if not url:
        return {
            "url": url,
            "score": 0,
            "risk_level": "UNKNOWN",
            "findings": ["No URL provided"],
            "domain": "",
            "subdomain": "",
            "protocol": ""
        }

    # Add scheme if missing
    test_url = url

    if not re.match(r"^https?://", test_url, re.IGNORECASE):
        test_url = "https://" + test_url

    try:
        parsed = urlparse(test_url)

    except Exception:
        return {
            "url": url,
            "score": 50,
            "risk_level": "MEDIUM RISK",
            "findings": ["Invalid URL format"],
            "domain": "",
            "subdomain": "",
            "protocol": ""
        }

    domain = parsed.netloc.lower()
    protocol = parsed.scheme.lower()
    path = parsed.path.lower()

    # Remove port
    hostname = domain.split(":")[0]

    # ------------------------------------------
    # DOMAIN EXTRACTION
    # ------------------------------------------

    extracted = tldextract.extract(hostname)

    registered_domain = extracted.registered_domain
    subdomain = extracted.subdomain

    # ------------------------------------------
    # CHECK 1 — HTTP
    # ------------------------------------------

    if protocol == "http":

        findings.append(
            "Website uses HTTP instead of HTTPS."
        )

        score += 15

    # ------------------------------------------
    # CHECK 2 — IP ADDRESS
    # ------------------------------------------

    try:

        ipaddress.ip_address(hostname)

        findings.append(
            "Website uses an IP address instead of a domain name."
        )

        score += 30

    except ValueError:

        pass

    # ------------------------------------------
    # CHECK 3 — URL LENGTH
    # ------------------------------------------

    if len(url) > 100:

        findings.append(
            "URL is unusually long."
        )

        score += 10

    elif len(url) > 75:

        findings.append(
            "URL is relatively long."
        )

        score += 5

    # ------------------------------------------
    # CHECK 4 — @ SYMBOL
    # ------------------------------------------

    if "@" in url:

        findings.append(
            "URL contains '@', which can be used for URL obfuscation."
        )

        score += 20

    # ------------------------------------------
    # CHECK 5 — MANY SUBDOMAINS
    # ------------------------------------------

    if subdomain:

        subdomain_count = len(
            subdomain.split(".")
        )

        if subdomain_count >= 3:

            findings.append(
                "URL contains an unusually large number of subdomains."
            )

            score += 15

        elif subdomain_count >= 2:

            findings.append(
                "URL contains multiple subdomains."
            )

            score += 5

    # ------------------------------------------
    # CHECK 6 — SUSPICIOUS KEYWORDS
    # ------------------------------------------

    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "credential",
        "payment",
        "wallet",
        "bank",
        "invoice",
        "unlock"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in url.lower():

            found_keywords.append(keyword)

    if found_keywords:

        findings.append(
            "Suspicious security-related keywords detected: "
            + ", ".join(found_keywords)
        )

        score += min(
            len(found_keywords) * 5,
            20
        )

    # ------------------------------------------
    # CHECK 7 — DOMAIN HAS HYPHENS
    # ------------------------------------------

    if "-" in registered_domain:

        findings.append(
            "Domain contains hyphens, which can sometimes be used "
            "in look-alike phishing domains."
        )

        score += 5

    # ------------------------------------------
    # CHECK 8 — DOMAIN LENGTH
    # ------------------------------------------

    if len(hostname) > 50:

        findings.append(
            "Domain name is unusually long."
        )

        score += 10

    # ------------------------------------------
    # CHECK 9 — PATH DEPTH
    # ------------------------------------------

    path_parts = [
        part for part in path.split("/")
        if part
    ]

    if len(path_parts) >= 5:

        findings.append(
            "URL contains a deeply nested path."
        )

        score += 5

    # ------------------------------------------
    # CHECK 10 — ENCODED CHARACTERS
    # ------------------------------------------

    if "%" in url:

        findings.append(
            "URL contains encoded characters."
        )

        score += 5

    # ------------------------------------------
    # FINAL SCORE
    # ------------------------------------------

    score = min(score, 100)

    # ------------------------------------------
    # RISK LEVEL
    # ------------------------------------------

    if score >= 70:

        risk_level = "HIGH RISK"

    elif score >= 40:

        risk_level = "MEDIUM RISK"

    else:

        risk_level = "LOW RISK"

    # ------------------------------------------
    # RETURN RESULT
    # ------------------------------------------

    return {
        "url": url,
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "domain": registered_domain,
        "subdomain": subdomain,
        "protocol": protocol
    }