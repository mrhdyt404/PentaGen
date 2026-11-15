# Multi-stage hardened production Dockerfile for PentaGen API Backend
# 1. Builder Stage
FROM python:3.12-slim AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# 2. Runtime Hardened Stage
FROM python:3.12-slim AS runner

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    PATH="/install/bin:$PATH" \
    PYTHONPATH="/install/lib/python3.12/site-packages:$PYTHONPATH"

# Install minimal runtime shared libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python dependencies from builder
COPY --from=builder /install /install

# Create non-root dedicated security user
RUN groupadd -g 10001 pentagen && \
    useradd -u 10001 -g pentagen -s /bin/false -d /app pentagen && \
    mkdir -p /app/storage /app/artifacts && \
    chown -R pentagen:pentagen /app

# Copy application source code
COPY --chown=pentagen:pentagen backend /app/backend

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health || exit 1

CMD ["sh", "-c", "alembic -c backend/alembic.ini upgrade head && exec uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 4 --proxy-headers --forwarded-allow-ips='*'"]
