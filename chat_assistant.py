# ============================================================
# 🤖 CYBERSHIELD AI ASSISTANT — chat_assistant.py
# Floating cybersecurity chat agent, connected to live
# phishing/email/website analysis results.
# ============================================================
#
# WHAT THIS FILE DOES:
#   - Renders a floating "AI Chat" popover (bottom-right) that stays
#     available across every page of the app (called once from app.py).
#   - Keeps a persistent conversation in st.session_state["chat_messages"].
#   - Reads st.session_state["current_analysis"] (set by app.py after an
#     Email or Website scan) and injects it into the AI's context so the
#     assistant can explain the user's ACTUAL results instead of a
#     generic answer.
#   - Talks to a local Ollama model, with graceful fallback messaging if
#     Ollama is not running / not installed / errors out.
#
# ORIGINAL BEHAVIOR PRESERVED:
#   - render_floating_chatbot() is still the single public entry point,
#     called from app.py exactly as before.
#   - Same fixed bottom-right popover approach (no extra JS required).
#   - Same st.session_state["chat_messages"] structure
#     ({"role": ..., "content": ...}), so nothing else in the app breaks.
# ============================================================

import streamlit as st
import ollama


# ============================================================
# ⚙️ AI ASSISTANT CONFIGURATION
# Change the model name here if you use a different local model.
# ============================================================
OLLAMA_MODEL = "llama3"

WELCOME_MESSAGE = (
    "Hello! I'm **CyberShield AI**, your local Llama 3 security assistant. "
    "I can explain phishing indicators, walk you through your latest scan "
    "results, or answer general cybersecurity questions. How can I help?"
)

# ============================================================
# 🧠 CYBERSECURITY SYSTEM INSTRUCTIONS
# This is the persona / guardrails given to the model on every call.
# Modify this block to change how the assistant behaves or what
# topics it focuses on.
# ============================================================
SYSTEM_PROMPT = """You are CyberShield AI, a friendly and knowledgeable cybersecurity assistant
embedded inside a phishing detection platform.

Your primary areas of expertise are:
- Phishing (email and website)
- Email security, spoofing, SPF, DKIM, DMARC
- URL / website analysis and suspicious link patterns
- Social engineering
- Malicious attachments
- Password security and MFA
- General network security awareness

Guidelines you must always follow:
1. Explain technical concepts in simple, beginner-friendly language.
2. If the user asks about "their" analysis, current score, or why something
   was flagged, and analysis context is provided below, base your answer on
   that actual data instead of a generic answer.
3. Clearly separate three things when relevant:
   - The ANALYZER RESULT (the rule-based score/finding, which is deterministic).
   - Your AI EXPLANATION (informational interpretation, not a guaranteed verdict).
   - Your SECURITY RECOMMENDATION (practical safe next step).
4. Never claim to guarantee that something is or is not malware/phishing with
   100% certainty. Use language like "appears", "is consistent with", "may indicate".
5. Where appropriate, encourage safe behavior: don't click suspicious links,
   don't enter credentials on unverified sites, verify senders independently,
   report suspicious emails, use MFA, and avoid downloading unknown attachments.
6. Keep answers concise and easy to read, using short paragraphs or bullet points.
"""


# ============================================================
# 🔗 AI AGENT CONTEXT — Build the analysis context block
# Converts st.session_state["current_analysis"] (set in app.py after a
# scan) into a readable text block that gets injected into the prompt.
# ============================================================
def _format_analysis_context(analysis: dict) -> str:
    """Turn the current analysis dict into a plain-text context block."""
    if not analysis or not isinstance(analysis, dict):
        return ""

    scan_type = analysis.get("type", "Unknown")
    target = analysis.get("target", "N/A")
    score = analysis.get("score", "N/A")
    risk_level = analysis.get("risk_level", "N/A")
    findings = analysis.get("findings", []) or []
    extra = analysis.get("extra", {}) or {}

    lines = [
        f"Current {scan_type} Analysis:",
        f"Target: {target}",
        f"Risk Score: {score}/100",
        f"Risk Level: {risk_level}",
    ]

    if findings:
        lines.append("Indicators / Findings:")
        for item in findings:
            lines.append(f"- {item}")
    else:
        lines.append("Indicators / Findings: none detected")

    if extra:
        lines.append("Additional Details:")
        for key, value in extra.items():
            lines.append(f"- {key}: {value}")

    return "\n".join(lines)


# ============================================================
# 🤖 AI RESPONSE GENERATION
# Builds the full prompt (system + context + history) and calls
# Ollama. Handles Ollama being unavailable without crashing the app.
# ============================================================
def generate_ai_response(user_message: str, chat_history: list, analysis: dict | None) -> str:
    """
    Generate an assistant reply using the local Ollama model.

    - user_message: latest user text (already appended to chat_history)
    - chat_history: full st.session_state["chat_messages"] list
    - analysis: st.session_state.get("current_analysis") or None
    """
    if not user_message or not user_message.strip():
        return "It looks like your message was empty — could you type your question again?"

    context_block = _format_analysis_context(analysis)

    system_content = SYSTEM_PROMPT
    if context_block:
        system_content += (
            "\n\nThe user currently has the following scan result available. "
            "Use it when relevant:\n\n" + context_block
        )

    # Build the message list for Ollama: system prompt + prior conversation.
    formatted_messages = [{"role": "system", "content": system_content}]
    for message in chat_history:
        role = message.get("role", "user")
        content = message.get("content", "")
        # Ollama expects roles: system / user / assistant
        if role not in ("user", "assistant", "system"):
            role = "user"
        formatted_messages.append({"role": role, "content": content})

    try:
        response = ollama.chat(model=OLLAMA_MODEL, messages=formatted_messages)
        reply = response.get("message", {}).get("content", "").strip()
        if not reply:
            return "I wasn't able to generate a response that time — could you rephrase your question?"
        return reply

    except ConnectionError:
        return (
            "⚠️ **AI Assistant unavailable**\n\n"
            "Ollama is not currently running.\n\n"
            "Start Ollama and try again. (`ollama serve`, then make sure the "
            f"`{OLLAMA_MODEL}` model is pulled.)"
        )
    except Exception as error:
        # Catch-all so a local AI outage never crashes the Streamlit app.
        return (
            "⚠️ **AI Assistant unavailable**\n\n"
            "I couldn't reach the local Ollama model right now, so I can't "
            "generate a response. Make sure Ollama is running and the "
            f"`{OLLAMA_MODEL}` model is installed, then try again.\n\n"
            f"_Technical detail: {error}_"
        )


# ============================================================
# 💬 QUICK QUESTIONS
# Shown when the chat has no user-driven conversation yet, to help
# users get started quickly.
# ============================================================
QUICK_QUESTIONS = [
    ("🔍 Explain my latest analysis", "Can you explain my latest analysis result and why it got that risk score?"),
    ("🎣 What is phishing?", "What is phishing?"),
    ("🌐 Is this website dangerous?", "How do I tell if a website is dangerous?"),
    ("📧 How do I spot a phishing email?", "How do I identify a phishing email?"),
    ("🛡️ How can I protect myself?", "How can I protect myself from phishing attacks?"),
]


def _send_message(prompt_text: str):
    """Append a user message, generate a reply, and store both in history."""
    prompt_text = (prompt_text or "").strip()
    if not prompt_text:
        return

    st.session_state.chat_messages.append({"role": "user", "content": prompt_text})

    analysis = st.session_state.get("current_analysis")
    with st.spinner("Thinking..."):
        reply = generate_ai_response(prompt_text, st.session_state.chat_messages, analysis)

    st.session_state.chat_messages.append({"role": "assistant", "content": reply})


# ============================================================
# 🖼️ FLOATING AI AGENT CHAT — Main UI entry point
# Renders the fixed bottom-right button/popover, chat history,
# quick questions, input box, and clear-chat control.
# Called once per page from app.py: render_floating_chatbot()
# ============================================================
def render_floating_chatbot():
    # --------------------------------------------------------
    # AI CHAT SESSION STATE
    # Controls conversation history. Initialized once; persists
    # across reruns/navigation for the duration of the session.
    # --------------------------------------------------------
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = [
            {"role": "assistant", "content": WELCOME_MESSAGE}
        ]

    # current_analysis is populated by app.py after an Email/Website scan.
    # Default it here so the chatbot never errors if no scan has run yet.
    if "current_analysis" not in st.session_state:
        st.session_state.current_analysis = None

    # --------------------------------------------------------
    # TRUE BOTTOM-RIGHT FIXED FLOATING STYLING
    # (unchanged approach — reliable, no extra JS needed)
    # --------------------------------------------------------
    st.markdown(
        """
        <style>
        div.fixed-chat-container {
            position: fixed !important;
            bottom: 25px !important;
            right: 25px !important;
            z-index: 999999 !important;
        }
        div.fixed-chat-container [data-testid="stPopoverBody"] {
            width: 360px !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="fixed-chat-container">', unsafe_allow_html=True)

    with st.popover("🤖 AI Chat"):
        # ---- Header ----
        st.markdown("### 🤖 CyberShield AI Assistant")
        st.markdown("🟢 **Online** &nbsp;·&nbsp; Local Llama 3 via Ollama")
        st.caption(
            "Your cybersecurity assistant for phishing detection, email analysis, "
            "website security, and threat awareness."
        )

        # ---- Analysis context indicator ----
        analysis = st.session_state.get("current_analysis")
        if analysis:
            st.info(
                f"📎 Using your latest **{analysis.get('type', 'scan')}** analysis "
                f"(Risk: {analysis.get('risk_level', 'N/A')}) as context.",
                icon="📎",
            )

        st.divider()

        # ---- Clear Chat control ----
        col_label, col_clear = st.columns([3, 1])
        with col_clear:
            if st.button("🗑️ Clear", use_container_width=True, key="chat_clear_btn"):
                st.session_state.chat_messages = [
                    {"role": "assistant", "content": WELCOME_MESSAGE}
                ]
                st.rerun()

        # ---- Quick Questions (only shown before any real conversation) ----
        has_user_messages = any(m["role"] == "user" for m in st.session_state.chat_messages)
        if not has_user_messages:
            st.markdown("**Quick Questions**")
            for label, question in QUICK_QUESTIONS:
                if st.button(label, key=f"quick_{label}", use_container_width=True):
                    _send_message(question)
                    st.rerun()

        # ---- Scrollable chat history ----
        history_box = st.container(height=280)
        with history_box:
            for message in st.session_state.chat_messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])

        # ---- Chat input ----
        if prompt := st.chat_input("Ask a security question...", key="fixed_floating_chat_input"):
            _send_message(prompt)
            st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)
