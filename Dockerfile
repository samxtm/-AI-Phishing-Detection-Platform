# ============================================================
# 🛡️ AI PHISHING DETECTION PLATFORM - DOCKERFILE
# Multi-platform production-ready container for Docker Hub
# ============================================================

# Use official lightweight Python 3.11 runtime
FROM python:3.11-slim

# Prevent Python from writing .pyc files, buffer logs, and configure Streamlit defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    OLLAMA_HOST=http://host.docker.internal:11434

# Set working directory inside container
WORKDIR /app

# Install system dependencies (build-essential, curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies (strip Windows-only dependencies like pywin32)
RUN pip install --no-cache-dir --upgrade pip && \
    sed -i '/pywin32/d' requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Ensure directory for SQLite database exists
RUN mkdir -p /app/database

# Expose default Streamlit port
EXPOSE 8501

# Healthcheck to verify container readiness
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Launch the Streamlit application
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
