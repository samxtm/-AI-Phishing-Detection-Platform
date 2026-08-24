# ============================================================
# 🛡️ AI PHISHING DETECTION PLATFORM
# Responsive Desktop + Mobile Streamlit Application
# ============================================================

import streamlit as st
from datetime import datetime
import pandas as pd
import ollama
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

from analyzer import analyze_email
from ollama_ai import get_ai_explanation
from src.website_analyzer import analyze_website_url
from database.database import initialize_database, save_scan, get_all_scans, clear_scans, authenticate_user
from auth import show_authentication
from chat_assistant import render_floating_chatbot  # <-- Floating chat assistant import

# ============================================================
# ⚙️ PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="AI Phishing Detection Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# 🎨 MOBILE + DESKTOP CSS (UI STYLING)
# ============================================================
st.markdown(
    """
<style>
    /* MAIN CONTAINER */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1400px;
    }

    /* TYPOGRAPHY */
    h1, h2, h3 { font-family: 'Inter', sans-serif; }
    h1 { font-weight: 700; color: #1E3A8A; }
    h2 { font-weight: 650; margin-top: 1rem; }

    /* BUTTONS */
    .stButton > button {
        border-radius: 8px;
        min-height: 45px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    /* METRIC CARDS */
    [data-testid="stMetric"] {
        padding: 20px;
        border-radius: 12px;
        border: 1px solid rgba(128,128,128,0.20);
        background: linear-gradient(145deg, rgba(255,255,255,0.05), rgba(128,128,128,0.05));
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        transition: transform 0.2s ease;
    }
    [data-testid="stMetric"]:hover { transform: scale(1.02); }
    [data-testid="stMetricLabel"] {
        font-weight: 600;
        font-size: 1.1rem;
        color: #64748b;
    }

    /* TOP NAV BAR STYLING */
    div[data-testid="stRadio"] > div {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        justify-content: center;
        background: rgba(128, 128, 128, 0.05);
        padding: 10px;
        border-radius: 12px;
        border: 1px solid rgba(128, 128, 128, 0.1);
    }

    /* MOBILE RESPONSIVENESS */
    @media (max-width: 768px) {
        .block-container {
            padding-left: 1rem;
            padding-right: 1rem;
            padding-top: 1.5rem;
        }
        h1 { font-size: 1.8rem !important; }
        h2 { font-size: 1.4rem !important; }
        [data-testid="stMetric"] { padding: 15px; }
        [data-testid="stMetricValue"] { font-size: 1.5rem; }
    }
</style>
""",
    unsafe_allow_html=True
)

# ============================================================
# 🗄️ DATABASE INITIALIZATION
# ============================================================
initialize_database()

# ============================================================
# 🔐 AUTHENTICATION STATE MANAGEMENT
# ============================================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "user" not in st.session_state:
    st.session_state.user = None

if not st.session_state.logged_in:
    show_authentication()
    st.stop()

current_user = st.session_state.get("user")

if not current_user:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.error("⚠️ Your session could not be found. Please login again.")
    st.stop()

current_user_id = current_user.get("id")
current_username = current_user.get("username", "User")

if current_user_id is None:
    st.error("⚠️ Unable to identify the logged-in user.")
    st.stop()

# Extract clean display name (removes email domain if registered using email)
display_name = current_username.split("@")[0] if current_username else "User"

# ============================================================
# 🤖 AI AGENT CONTEXT — SESSION STATE
# Holds the most recent Email/Website analysis so the floating
# AI chat assistant can reference real results instead of giving
# generic answers. Does NOT touch scan history in the database.
# ============================================================
if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None


# ============================================================
# 📄 PDF REPORT GENERATOR LOGIC
# ============================================================
def create_pdf_report(report_type, scan_time, score, risk_level, details, ai_explanation="", extra_data=None):
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], alignment=TA_CENTER, fontSize=20, spaceAfter=20)
    heading_style = ParagraphStyle("ReportHeading", parent=styles["Heading2"], fontSize=14, spaceBefore=14, spaceAfter=8)
    normal_style = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontSize=10, leading=14)
    small_style = ParagraphStyle("SmallBody", parent=styles["BodyText"], fontSize=9, leading=12)

    story = []

    story.append(Paragraph("AI PHISHING DETECTION REPORT", title_style))
    story.append(Paragraph(f"<b>Report Type:</b> {escape(str(report_type))}", normal_style))
    story.append(Paragraph(f"<b>Scan Time:</b> {escape(str(scan_time))}", normal_style))
    story.append(Paragraph(f"<b>User:</b> {escape(str(display_name))}", normal_style))
    story.append(Spacer(1, 15))

    story.append(Paragraph("Risk Assessment", heading_style))
    risk_data = [["Risk Score", f"{score}/100"], ["Risk Level", str(risk_level)]]
    risk_table = Table(risk_data, colWidths=[2.2 * inch, 3.5 * inch])
    risk_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 15))

    if extra_data:
        story.append(Paragraph("Analysis Information", heading_style))
        for key, value in extra_data.items():
            story.append(Paragraph(f"<b>{escape(str(key))}:</b> {escape(str(value))}", normal_style))
            story.append(Spacer(1, 4))

    story.append(Paragraph("Security Findings", heading_style))
    if details:
        for detail in details:
            story.append(Paragraph(f"• {escape(str(detail))}", normal_style))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No suspicious findings detected.", normal_style))

    if ai_explanation:
        story.append(Paragraph("AI Security Analysis", heading_style))
        for line in str(ai_explanation).splitlines():
            line = line.strip()
            if not line:
                story.append(Spacer(1, 5))
                continue
            line = line.replace("**", "").replace("### ", "").replace("## ", "")
            story.append(Paragraph(escape(line), small_style))
            story.append(Spacer(1, 3))

    story.append(Spacer(1, 20))
    story.append(Paragraph("<b>Security Notice:</b> This report is an automated security assessment...", small_style))

    document.build(story)
    buffer.seek(0)
    return buffer.getvalue()


# ============================================================
# 🤖 WEBSITE AI EXPLANATION PROMPT (LLAMA 3)
# ============================================================
def get_website_ai_explanation(website_result):
    findings = website_result.get("findings", [])
    findings_text = "\n".join(f"- {finding}" for finding in findings)

    prompt = f"""
You are a cybersecurity assistant specializing in phishing website and URL analysis.
Analyze the following website URL.

IMPORTANT:
- The website has NOT been visited.
- Do not claim the website is definitely malicious.
- Base your analysis only on URL structure and rule-based findings.
- Explain the result in simple language.

WEBSITE URL: {website_result.get("url", "")}
DOMAIN: {website_result.get("domain", "")}
RULE-BASED RISK SCORE: {website_result.get("score", 0)}/100
RISK LEVEL: {website_result.get("risk_level", "UNKNOWN")}
SECURITY FINDINGS:
{findings_text}

Explain:
1. Why the URL may be suspicious.
2. Which characteristics are concerning.
3. Give a short final security recommendation.
"""
    response = ollama.chat(model="llama3", messages=[{"role": "user", "content": prompt}])
    return response["message"]["content"]


# ============================================================
# 📍 SIDEBAR UI & NAVIGATION
# ============================================================
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/3251/3251347.png", width=60)
    st.title("Phishing Detector")
    st.success(f"👤 Logged in as: **{display_name}**")

    st.divider()

    # --- RISK LEVEL GUIDE ---
    st.subheader("⚠️ Risk Level Guide")
    st.markdown("🟢 **LOW** (0–39)<br>🟡 **MEDIUM** (40–69)<br>🔴 **HIGH** (70–100)", unsafe_allow_html=True)
    st.divider()

    # --- ABOUT SECTION ---
    with st.expander("ℹ️ About This Project"):
        st.markdown(
            """
            **AI Phishing Platform v2.0**  
            By **NOOB🤡**.

            * **AI Engine:** Llama 3 via Ollama
            * **Analysis:** Heuristic rule engines & URL structural parsing
            * **Security:** Local-first processing & SQLite tenant isolation
            """
        )

    st.divider()

    # --- LOGOUT BUTTON ---
    if st.button("🚪 Logout", type="secondary", use_container_width=True, key="btn_logout_sidebar"):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.rerun()

    st.caption("AI Phishing Detection Platform V2.0")
    st.caption("Powered by Llama 3")


# ============================================================
# 🌟 APPLICATION HEADER
# ============================================================
st.title("🛡️ AI Phishing Detection Platform")
st.markdown(f"Welcome back, **{display_name}**. Protect yourself by analyzing suspicious emails and URLs using rule-based algorithms and AI.")


# ============================================================
# 🧭 TOP NAVIGATION BAR
# ============================================================
st.write("")
selected_nav = st.radio(
    "Main Menu Navigation",
    ["📊 Security Dashboard", "📧 Email Analyzer", "🌐 Website Analyzer"],
    horizontal=True,
    label_visibility="collapsed"
)
st.write("")

# ============================================================
# 🤖 AI AGENT CHAT — FLOATING BUTTON
# Renders the persistent bottom-right floating chat button/popover.
# ============================================================
render_floating_chatbot()

st.divider()


# ============================================================
# 📊 VIEW 1: SECURITY DASHBOARD
# ============================================================
if selected_nav == "📊 Security Dashboard":

    col_title, col_btn = st.columns([3, 1])
    with col_title:
        st.subheader("📊 Security Dashboard Overview")
    with col_btn:

        # --- CLEAR HISTORY TOGGLE ---
        if "show_clear_confirm" not in st.session_state:
            st.session_state.show_clear_confirm = False

        if st.button("🗑️ Clear History", type="secondary", use_container_width=True):
            st.session_state.show_clear_confirm = not st.session_state.show_clear_confirm

    # --- PASSWORD VERIFICATION FOR CLEAR HISTORY ---
    if st.session_state.get("show_clear_confirm", False):
        with st.container(border=True):
            st.warning("⚠️ Security Verification: Enter your password to clear all scan history.")
            entered_password = st.text_input("Account Password:", type="password", key="clear_history_pwd")

            col_confirm, col_cancel = st.columns(2)
            with col_confirm:
                if st.button("Confirm Wipe", type="primary", use_container_width=True):
                    verified_user = authenticate_user(current_username, entered_password)

                    if verified_user:
                        try:
                            clear_scans(user_id=current_user_id)
                            st.success("Scan history cleared successfully!")
                            st.session_state.show_clear_confirm = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to clear history: {e}")
                    else:
                        st.error("❌ Incorrect password. Action aborted.")
            with col_cancel:
                if st.button("Cancel", use_container_width=True):
                    st.session_state.show_clear_confirm = False
                    st.rerun()

    # --- FETCH DASHBOARD DATA ---
    try:
        dashboard_scans = get_all_scans(user_id=current_user_id)
    except Exception as error:
        st.error(f"Unable to load dashboard data: {error}")
        dashboard_scans = []

    dashboard_df = pd.DataFrame(dashboard_scans) if dashboard_scans else pd.DataFrame()

    total_scans = len(dashboard_df) if not dashboard_df.empty else 0
    email_scans, website_scans = 0, 0
    high_risk, medium_risk, low_risk = 0, 0, 0

    if not dashboard_df.empty:
        if "scan_type" in dashboard_df.columns:
            email_scans = len(dashboard_df[dashboard_df["scan_type"] == "Email"])
            website_scans = len(dashboard_df[dashboard_df["scan_type"] == "Website"])
        if "risk_level" in dashboard_df.columns:
            high_risk = len(dashboard_df[dashboard_df["risk_level"] == "HIGH RISK"])
            medium_risk = len(dashboard_df[dashboard_df["risk_level"] == "MEDIUM RISK"])
            low_risk = len(dashboard_df[dashboard_df["risk_level"] == "LOW RISK"])

    # --- RENDER METRICS ---
    with st.container(border=True):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Scans Performed", total_scans)
        with col2:
            st.metric("🚨 High Risk Found", high_risk, delta_color="inverse")
        with col3:
            st.metric("📧 Email Scans", email_scans)
        with col4:
            st.metric("🌐 Website Scans", website_scans)

    # --- RENDER RECENT ACTIVITY TABLE ---
    if not dashboard_df.empty:
        with st.container(border=True):
            st.subheader("🕒 Recent Scan Activity")
            recent_scans = dashboard_df.head(5)
            st.dataframe(recent_scans, use_container_width=True, hide_index=True)
    else:
        st.info("No scan history found. Perform an Email or Website analysis to populate your dashboard.")


# ============================================================
# 📧 VIEW 2: EMAIL ANALYZER
# ============================================================
elif selected_nav == "📧 Email Analyzer":

    st.header("📧 Email Phishing Analyzer")
    st.caption("Paste the raw text or headers of a suspicious email below.")

    email_text = st.text_area("Email Content:", height=200, placeholder="Subject: Urgent Verification\n\nClick here to reset your password...")
    analyze_email_button = st.button("🔍 Analyze Email", type="primary", use_container_width=True)

    if analyze_email_button:
        if not email_text.strip():
            st.warning("⚠️ Please paste an email before analyzing.")
        else:
            with st.spinner("🔎 Analyzing email content and headers..."):
                result = analyze_email(email_text)
                scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                save_scan(
                    user_id=current_user_id,
                    scan_time=scan_time,
                    scan_type="Email",
                    target="Email Scan",
                    risk_score=result["score"],
                    risk_level=result["risk_level"],
                    findings_count=len(result.get("indicators", []))
                )

            # --- RENDER EMAIL RESULTS ---
            with st.container(border=True):
                st.subheader("📊 Threat Assessment")
                email_score = result["score"]
                email_risk = result["risk_level"]

                c1, c2 = st.columns([1, 3])
                with c1:
                    st.metric("Risk Score", f"{email_score}/100")
                with c2:
                    st.progress(min(max(email_score / 100, 0), 1))
                    if email_risk == "HIGH RISK": st.error("🚨 HIGH RISK: Strong phishing indicators detected.")
                    elif email_risk == "MEDIUM RISK": st.warning("⚠️ MEDIUM RISK: Suspicious characteristics detected.")
                    else: st.success("🟢 LOW RISK: No major phishing indicators detected.")

            with st.expander("🚨 Detected Phishing Indicators", expanded=True):
                if result.get("indicators"):
                    for indicator in result["indicators"]:
                        st.write(f"🔸 {indicator}")
                else:
                    st.success("No suspicious indicators detected.")

            # --- FETCH Llama 3 EXPLANATION ---
            with st.expander("🤖 Llama 3 Deep Analysis", expanded=True):
                with st.spinner("🤖 Llama 3 is analyzing context..."):
                    try:
                        explanation = get_ai_explanation(email_text, result)
                        st.markdown(explanation)
                    except Exception as error:
                        st.error(f"AI analysis failed: {error}")
                        explanation = "AI Analysis unavailable."

            st.session_state.current_analysis = {
                "type": "Email",
                "target": "Email Scan",
                "score": result["score"],
                "risk_level": result["risk_level"],
                "findings": result.get("indicators", []),
                "extra": {
                    "Text Analysis Score": f"{result.get('text_score', 0)}/100",
                    "URLs Found": len(result.get("urls", [])),
                },
            }

            # --- PDF GENERATION ---
            email_extra_data = {
                "User": display_name,
                "Text Analysis Score": f"{result.get('text_score', 0)}/100",
                "URLs Found": len(result.get("urls", []))
            }
            email_pdf = create_pdf_report("Phishing Email Analysis", scan_time, result["score"], result["risk_level"], result.get("indicators", []), explanation, email_extra_data)

            st.download_button(
                label="📥 Download Professional PDF Report",
                data=email_pdf,
                file_name="phishing_email_report.pdf",
                mime="application/pdf",
                use_container_width=True
            )


# ============================================================
# 🌐 VIEW 3: WEBSITE ANALYZER
# ============================================================
elif selected_nav == "🌐 Website Analyzer":

    st.header("🌐 Phishing Website Analyzer")
    st.info("⚠️ This analyzer evaluates the URL structure securely without automatically visiting the live website.")

    website_url = st.text_input("🌐 Enter Suspicious URL:", placeholder="https://secure-login-update.example.com")
    analyze_website_button = st.button("🔍 Analyze URL", type="primary", use_container_width=True)

    if analyze_website_button:
        if not website_url.strip():
            st.warning("⚠️ Please enter a website URL.")
        else:
            with st.spinner("🌐 Analyzing domain and URL structure..."):
                website_result = analyze_website_url(website_url)
                scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                save_scan(
                    user_id=current_user_id,
                    scan_time=scan_time,
                    scan_type="Website",
                    target=website_result.get("domain", "Unknown URL"),
                    risk_score=website_result.get("score", 0),
                    risk_level=website_result.get("risk_level", "UNKNOWN"),
                    findings_count=len(website_result.get("findings", []))
                )

            # --- RENDER WEBSITE RESULTS ---
            with st.container(border=True):
                st.subheader("📊 URL Threat Assessment")
                web_score = website_result.get("score", 0)
                web_risk = website_result.get("risk_level", "UNKNOWN")

                c1, c2 = st.columns([1, 3])
                with c1:
                    st.metric("Risk Score", f"{web_score}/100")
                with c2:
                    st.progress(min(max(web_score / 100, 0), 1))
                    if web_risk == "HIGH RISK": st.error("🚨 HIGH RISK: Extremely suspicious URL pattern.")
                    elif web_risk == "MEDIUM RISK": st.warning("⚠️ MEDIUM RISK: Some questionable URL characteristics.")
                    else: st.success("🟢 LOW RISK: URL appears structurally normal.")

            with st.expander("🔎 Technical URL Findings", expanded=True):
                st.write(f"**Domain:** `{website_result.get('domain', 'N/A')}`")
                st.write(f"**Protocol:** `{website_result.get('protocol', 'N/A')}`")
                st.divider()
                if website_result.get("findings"):
                    for finding in website_result.get("findings", []):
                        st.write(f"🔸 {finding}")
                else:
                    st.success("No structural red flags found.")

            # --- FETCH Llama 3 EXPLANATION ---
            with st.expander("🤖 Llama 3 Domain Analysis", expanded=True):
                with st.spinner("🤖 Generating contextual URL report..."):
                    try:
                        web_explanation = get_website_ai_explanation(website_result)
                        st.markdown(web_explanation)
                    except Exception as error:
                        st.error(f"AI analysis failed: {error}")
                        web_explanation = "AI Analysis unavailable."

            st.session_state.current_analysis = {
                "type": "Website",
                "target": website_result.get("domain", "N/A"),
                "score": web_score,
                "risk_level": web_risk,
                "findings": website_result.get("findings", []),
                "extra": {
                    "Domain": website_result.get("domain", "N/A"),
                    "Protocol": website_result.get("protocol", "N/A"),
                },
            }

            # --- PDF GENERATION ---
            web_extra_data = {
                "User": display_name,
                "Domain": website_result.get("domain", "N/A"),
                "Protocol": website_result.get("protocol", "N/A")
            }
            web_pdf = create_pdf_report("Phishing URL Analysis", scan_time, web_score, web_risk, website_result.get("findings", []), web_explanation, web_extra_data)

            st.download_button(
                label="📥 Download URL PDF Report",
                data=web_pdf,
                file_name="phishing_url_report.pdf",
                mime="application/pdf",
                use_container_width=True
            )
