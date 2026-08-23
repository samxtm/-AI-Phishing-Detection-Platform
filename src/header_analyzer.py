import re


def extract_email_header(email_text):
    """
    Extract basic email header information
    when headers are included in the pasted email.
    """

    headers = {}

    patterns = {
        "from": r"(?im)^from:\s*(.+)$",
        "to": r"(?im)^to:\s*(.+)$",
        "subject": r"(?im)^subject:\s*(.+)$",
        "reply_to": r"(?im)^reply-to:\s*(.+)$",
        "return_path": r"(?im)^return-path:\s*(.+)$",
    }

    for field, pattern in patterns.items():

        match = re.search(
            pattern,
            email_text
        )

        if match:
            headers[field] = match.group(1).strip()

    return headers


def analyze_headers(email_text):

    headers = extract_email_header(
        email_text
    )

    findings = []
    score = 0

    # Reply-To mismatch
    from_address = headers.get("from", "")
    reply_to = headers.get("reply_to", "")

    if from_address and reply_to:

        from_domain = from_address.split("@")[-1].lower()
        reply_domain = reply_to.split("@")[-1].lower()

        if from_domain != reply_domain:

            findings.append(
                "From and Reply-To domains do not match"
            )

            score += 25

    # Suspicious sender keywords
    suspicious_sender_words = [
        "admin",
        "security",
        "support",
        "verify",
        "alert"
    ]

    for word in suspicious_sender_words:

        if word in from_address.lower():

            findings.append(
                f"Sender contains security-related keyword: {word}"
            )

            score += 5

    score = min(score, 100)

    return {
        "headers": headers,
        "score": score,
        "findings": findings
    }