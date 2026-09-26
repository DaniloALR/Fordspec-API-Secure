# syntax=docker/dockerfile:1.7

FROM python:3.14-slim-bookworm AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt

FROM python:3.14-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="fordspec-api" \
      org.opencontainers.image.description="FordSpec AI API (DevSecOps)" \
      org.opencontainers.image.licenses="Proprietary"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=production

RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /var/log/fordspec && chown 10001:10001 /var/log/fordspec

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
RUN /opt/venv/bin/python -m pip uninstall -y pip setuptools 2>/dev/null || true \
 && /usr/local/bin/python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true \
 && rm -rf /usr/local/lib/python3.*/ensurepip /usr/local/bin/pip* /opt/venv/bin/pip*
COPY app ./app
COPY iot ./iot
COPY seed ./seed
COPY scripts ./scripts
COPY migrations ./migrations
COPY alembic.ini .

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
