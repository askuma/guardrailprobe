FROM python:3.12-slim

LABEL maintainer="Ashutosh Kumar <ashutosh.kumar1089@gmail.com>"
LABEL description="guardrailprobe — AI guardrail benchmark tool (dashboard + CLI)"
LABEL org.opencontainers.image.source="https://github.com/askuma/guardrailprobe"

WORKDIR /app

# System build deps required for cryptography (pyhanko), httpx, spaCy, lxml, and grpcio
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install the package with all optional vendor SDK extras.
# GUARDRAILPROBE_SKIP_SPACY=1 defers the spaCy model download to the next step
# so we can download it explicitly and cache it in a separate layer.
COPY pyproject.toml hatch_build.py README.md ./
COPY guardrailprobe/ ./guardrailprobe/

ENV GUARDRAILPROBE_SKIP_SPACY=1
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir -e ".[guardrails_ai,presidio,aws,nemo]"

# Download the spaCy model (required by Presidio for NER-based PII detection).
# Skipped at build time if GUARDRAILPROBE_SKIP_SPACY=1 is passed to docker build --build-arg.
ARG SKIP_SPACY=0
RUN if [ "$SKIP_SPACY" = "0" ]; then python -m spacy download en_core_web_lg; fi

# Install GuardrailsAI free hub validators (non-fatal — falls back to regex scorer)
RUN pip install --no-cache-dir detect-secrets && \
    guardrails hub install hub://guardrails/detect_pii --quiet 2>/dev/null || true && \
    guardrails hub install hub://guardrails/secrets_present --quiet 2>/dev/null || true && \
    pip cache purge 2>/dev/null || true

# Output directories and entrypoint
RUN mkdir -p /app/reports /app/docs/benchmarks /app/certs /app/site-packages

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Non-root user
RUN useradd -m -u 1000 guardrailprobe && \
    chown -R guardrailprobe:guardrailprobe /app

USER guardrailprobe

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

EXPOSE 8080

# entrypoint.sh checks /app/site-packages for host-installed ML packages
# (LlamaFirewall, LLM Guard) and sets PYTHONPATH before starting the app.
#
# Default: start the Flask dashboard.
# Override CMD to run one-shot benchmarks:
#   docker run ... guardrailprobe run --year 2026 --month 6 --output-dir /app/reports
ENTRYPOINT ["/entrypoint.sh"]
CMD ["guardrailprobe", "dashboard", "--host", "0.0.0.0", "--port", "8080"]
