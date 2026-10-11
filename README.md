# 🛡️ AI Phishing Detection Platform

An enterprise-grade, multi-tenant cybersecurity application designed to detect and analyze phishing threats across emails and web URLs. Built as a 4th-year capstone project, this platform combines deterministic heuristic rule engines with local Large Language Model (LLM) contextual reasoning.

---

## 🚀 Key Features

* **📊 Interactive Security Dashboard:** Centralized overview tracking total scans, risk classifications (Low, Medium, High), and multi-tenant scan history.
* **📧 Email Phishing Analyzer:** Parses raw email headers and text for social engineering red flags, suspicious links, urgency markers, and spoofing indicators.
* **🌐 Secure Website URL Analyzer:** Performs deep structure analysis on suspicious domains and protocols (`tldextract`) *without* automatically executing or visiting live malicious sites.
* **🤖 Local AI Intelligence (Llama 3):** Powered by Ollama running Llama 3 locally to provide deep, context-aware security explanations and risk evaluations.
* **📄 Professional PDF Report Generation:** Instantly compile audit-ready security assessment reports using ReportLab.
* **🔐 Secure User Authentication:** Multi-tenant architecture with encrypted password hashing and password-verified history clearing.
* **📱 Responsive Design:** Custom-styled UI optimized for both desktop and mobile viewports with a modern top navigation bar.

---

## 🛠️ Technology Stack

* **Frontend & UI:** Streamlit (Python-based web framework), Custom CSS for responsive design.
* **Backend & Logic:** Python 3.11+, Pandas.
* **AI & NLP:** Ollama (Llama 3 Local LLM).
* **Security & Parsing:** `tldextract` (domain structure analysis).
* **Reporting:** ReportLab (Dynamic PDF compilation).
* **Database & Auth:** SQLite (Relational storage with foreign-key isolation and secure credential validation).


⚙️ Installation & Local Setup
Clone the Repository:

Bash
git clone [https://github.com/samxtm/-AI-Phishing-Detection-Platform.git](https://github.com/samxtm/-AI-Phishing-Detection-Platform.git)
cd -AI-Phishing-Detection-Platform
Create and Activate a Virtual Environment:

Bash
python -m venv venv
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
Install Dependencies:

Bash
pip install -r requirements.txt
Ensure Ollama is Running Locally:
Make sure Ollama is installed and running with Llama 3 pulled:

Bash
ollama pull llama3
Run the Application:

Bash
streamlit run app.py
🛠️ User & Database Management (Admin Guide)
If you need to check registered users or manage database records directly from your local environment without using the UI app:

Visual Inspection: Open phishing_detection.db using DB Browser for SQLite.

Command-Line Tool: Run the local admin script in your terminal:

Bash
python admin.py
This interactive utility allows you to list all registered users and safely delete user accounts along with their associated scan histories.

🔒 Security & Privacy Notice
Local-First AI: Threat analysis runs locally via Ollama, ensuring sensitive email contents or private URLs are never sent to third-party cloud APIs.

Safe URL Inspection: The URL analyzer evaluates structural syntax and domain anomalies without triggering automated web crawlers or browser-based drive-by downloads.
---

## 📂 Project Structure

```text
├── app.py                # Main Streamlit frontend & navigation controller
├── auth.py               # User authentication & session state management
├── analyzer.py           # Heuristic email phishing detection engine
├── ollama_ai.py          # Local Llama 3 AI integration wrapper
├── admin.py              # Command-line database & user management utility
├── run_app.py            # PyInstaller wrapper script for desktop packaging
├── database/
│   └── database.py       # SQLite connection, schema setup, and query handlers
├── src/
│   └── website_analyzer.py # URL structural threat analysis engine
├── .streamlit/
│   └── config.toml       # Streamlit UI configuration
└── requirements.txt      # Project dependencies

👨‍💻 Author
Developed as a 4th-Year Capstone Project.
