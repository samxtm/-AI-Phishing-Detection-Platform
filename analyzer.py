import re

from src.url_analyzer import analyze_urls
from src.header_analyzer import analyze_headers
from src.risk_engine import calculate_overall_risk


def analyze_email(email_text):

    indicators = []

    # -----------------------------------------
    # TEXT ANALYSIS
    # -----------------------------------------

    text_score = 0

    text = email_text.lower()

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "account will be suspended",
        "final warning",
        "verify now"
    ]

    for word in urgency_words:

        if word in text:

            indicators.append(
                f"Urgency language detected: '{word}'"
            )

            text_score += 10

    credential_words = [
        "password",
        "login",
        "username",
        "verify your account",
        "confirm your account",
        "bank details",
        "credit card",
        "otp"
    ]

    for word in credential_words:

        if word in text:

            indicators.append(
                f"Sensitive information request detected: '{word}'"
            )

            text_score += 15

    threat_words = [
        "suspended",
        "blocked",
        "terminated",
        "legal action",
        "penalty",
        "warning"
    ]

    for word in threat_words:

        if word in text:

            indicators.append(
                f"Threat/fear language detected: '{word}'"
            )

            text_score += 10

    text_score = min(
        text_score,
        100
    )

    # -----------------------------------------
    # URL ANALYSIS
    # -----------------------------------------

    url_results = analyze_urls(
        email_text
    )

    url_score = 0

    for result in url_results:

        url_score = max(
            url_score,
            result["score"]
        )

        for finding in result["findings"]:

            indicators.append(
                f"URL: {finding}"
            )

    # -----------------------------------------
    # HEADER ANALYSIS
    # -----------------------------------------

    header_result = analyze_headers(
        email_text
    )

    header_score = header_result["score"]

    for finding in header_result["findings"]:

        indicators.append(
            f"Header: {finding}"
        )

    # -----------------------------------------
    # OVERALL RISK
    # -----------------------------------------

    risk = calculate_overall_risk(
        text_score,
        url_score,
        header_score
    )

    return {

        "score": risk["score"],

        "risk_level": risk["risk_level"],

        "indicators": indicators,

        "urls": [
            result["url"]
            for result in url_results
        ],

        "url_analysis": url_results,

        "header_analysis": header_result,

        "text_score": text_score,

        "url_score": url_score,

        "header_score": header_score
    }