FROM python:3.11-slim

LABEL maintainer="raphaelguterres"
LABEL org.opencontainers.image.title="SAFE Enterprise Defense Platform"
LABEL org.opencontainers.image.description="Enterprise-preview SOC/XDR/EDR-lite platform"
LABEL org.opencontainers.image.version="0.1.0-enterprise-preview"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAFE_ENV=container \
    IDS_ENV=container \
    IDS_HOST=0.0.0.0 \
    IDS_PORT=5000 \
    HTTPS_ONLY=false \
    IDS_AUTH=true \
    IDS_DASHBOARD_AUTH=true

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    libpcap-dev \
    libpcap0.8 \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.docker.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.docker.txt

COPY . .

RUN mkdir -p /data /app/logs
VOLUME ["/data", "/app/logs"]

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health', timeout=5)" || exit 1

CMD ["python", "app.py"]
