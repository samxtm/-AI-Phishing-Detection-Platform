import ollama


def get_ai_explanation(text, analysis_result):
    """
    Generate an AI cybersecurity explanation.

    Supports both:
    - Email phishing analysis
    - Website phishing analysis
    """

    # ==================================================
    # GET COMMON INFORMATION SAFELY
    # ==================================================

    score = analysis_result.get("score", 0)

    risk_level = analysis_result.get(
        "risk_level",
        "UNKNOWN"
    )

    # Email uses "indicators"
    indicators = analysis_result.get(
        "indicators",
        []
    )

    # Website uses "findings"
    findings = analysis_result.get(
        "findings",
        []
    )

    # Website information
    domain = analysis_result.get(
        "domain",
        "Unknown"
    )

    subdomain = analysis_result.get(
        "subdomain",
        "None"
    )

    protocol = analysis_result.get(
        "protocol",
        "Unknown"
    )


    # ==================================================
    # DETECT ANALYSIS TYPE
    # ==================================================

    if findings:

        analysis_type = "website"

    elif indicators:

        analysis_type = "email"

    elif "domain" in analysis_result:

        analysis_type = "website"

    else:

        analysis_type = "email"


    # ==================================================
    # WEBSITE PROMPT
    # ==================================================

    if analysis_type == "website":

        prompt = f"""
You are a cybersecurity analyst specializing in
phishing website detection.

Analyze the following website URL.

IMPORTANT:
- The website itself has NOT been visited.
- Only analyze the URL and rule-based findings.
- Do not say the website is definitely malicious.
- Explain the evidence clearly.
- Give practical safety recommendations.

WEBSITE URL:
{text}

RULE-BASED ANALYSIS:

Risk Score:
{score}/100

Risk Level:
{risk_level}

Domain:
{domain}

Subdomain:
{subdomain}

Protocol:
{protocol}

Security Findings:
{findings}

Provide your analysis using these sections:

### Why the URL may be suspicious

Explain the important warning signs.

### Suspicious indicators

Explain each relevant finding.

### Recommended action

Explain what the user should do.

### Should the user visit this website?

Give a clear recommendation.

### Final Security Recommendation

Give a short beginner-friendly conclusion.

Do not claim certainty unless the evidence supports it.
"""


    # ==================================================
    # EMAIL PROMPT
    # ==================================================

    else:

        prompt = f"""
You are a cybersecurity assistant specializing in
phishing email analysis.

Analyze the following email.

EMAIL:
{text}

RULE-BASED ANALYSIS:

Risk Score:
{score}/100

Risk Level:
{risk_level}

Indicators:
{indicators}

Explain:

### Why this email may be phishing

### Suspicious indicators

### What the user should do

### Should the user click links or provide information?

Keep the explanation simple and suitable for
a beginner studying cybersecurity.

Do not claim certainty unless the evidence supports it.
"""


    # ==================================================
    # CALL LLAMA 3
    # ==================================================

    response = ollama.chat(
        model="llama3",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )


    # ==================================================
    # RETURN RESPONSE
    # ==================================================

    return response["message"]["content"]