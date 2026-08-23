import re
from urllib.parse import urlparse


def extract_urls(email_text):
    """Extract HTTP/HTTPS URLs from email text."""

    return re.findall(
        r"https?://[^\s<>\"]+",
        email_text
    )


def analyze_url(url):
    """Analyze a URL for basic suspicious characteristics."""

    findings = []
    score = 0

    try:
        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # No domain
        if not domain:
            findings.append("URL does not contain a valid domain")
            score += 20
            return {
                "url": url,
                "domain": domain,
                "score": score,
                "findings": findings
            }

        # IP address instead of normal domain
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        if re.match(ip_pattern, domain):
            findings.append(
                "URL uses an IP address instead of a domain name"
            )
            score += 25

        # Suspicious keywords
        suspicious_words = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "confirm",
            "password",
            "signin"
        ]

        for word in suspicious_words:

            if word in domain:

                findings.append(
                    f"Suspicious keyword in domain: {word}"
                )

                score += 10

        # HTTP instead of HTTPS
        if parsed.scheme.lower() == "http":

            findings.append(
                "URL does not use HTTPS"
            )

            score += 15

        # Long domain
        if len(domain) > 40:

            findings.append(
                "Unusually long domain name"
            )

            score += 10

        score = min(score, 100)

        return {
            "url": url,
            "domain": domain,
            "score": score,
            "findings": findings
        }

    except Exception as error:

        return {
            "url": url,
            "domain": "",
            "score": 30,
            "findings": [
                f"URL analysis error: {error}"
            ]
        }


def analyze_urls(email_text):
    """Extract and analyze all URLs in an email."""

    urls = extract_urls(email_text)

    results = []

    for url in urls:

        results.append(
            analyze_url(url)
        )

    return results