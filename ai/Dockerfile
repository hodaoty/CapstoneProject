FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# =========================================================
# NEW: cài docker CLI chuẩn từ Docker repo
# =========================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add Docker official GPG key
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add Docker repo
RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  > /etc/apt/sources.list.d/docker.list

# Install docker CLI ONLY
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# =========================================================
# CHECK: bắt buộc phải pass
# =========================================================
RUN which docker && docker --version

RUN pip install requests

COPY ai /app/ai

RUN pip install --no-cache-dir \
    pandas \
    joblib \
    scikit-learn \
    lightgbm \
    elasticsearch==8.13.2 \
    colorama

CMD ["python", "/app/ai/run/realtime_defender.py"]