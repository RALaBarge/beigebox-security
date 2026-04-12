# Multi-stage build for beigebox-security

FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY beigebox_security beigebox_security/
COPY tests tests/

# Install dependencies
RUN pip install --no-cache-dir -e .

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create non-root user first
RUN useradd -m -u 1000 appuser

# Copy application
COPY beigebox_security beigebox_security/
COPY --chown=appuser:appuser data ./data/

# Set permissions
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8001/health', timeout=5)"

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    BEIGEBOX_SECURITY_HOST=0.0.0.0 \
    BEIGEBOX_SECURITY_PORT=8001 \
    BEIGEBOX_SECURITY_DEBUG=false

EXPOSE 8001

CMD ["python", "-m", "uvicorn", "beigebox_security.api:app", "--host", "0.0.0.0", "--port", "8001"]
