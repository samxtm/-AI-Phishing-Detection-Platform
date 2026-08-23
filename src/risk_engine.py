def calculate_overall_risk(
    text_score,
    url_score,
    header_score
):
    """
    Combine different security signals
    into one overall phishing risk score.
    """

    # Weighted scoring
    overall_score = (
        text_score * 0.50
        + url_score * 0.30
        + header_score * 0.20
    )

    overall_score = round(
        min(overall_score, 100)
    )

    if overall_score >= 70:

        risk_level = "HIGH RISK"

    elif overall_score >= 40:

        risk_level = "MEDIUM RISK"

    else:

        risk_level = "LOW RISK"

    return {
        "score": overall_score,
        "risk_level": risk_level
    }