# =============================================================================
# STAGE 1: Wheel Builder
# =============================================================================
FROM python:3.12-slim-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install lightweight network-layer stack with Section 3.2 runtime pins
RUN pip install --no-compile \
    "apify>=2.0.0,<3.0.0" \
    "crawlee>=0.4.0" \
    "pydantic>=2.8.0,<2.10.0" \
    "browserforge<1.2.4" \
    "curl-cffi>=0.7.3" \
    "orjson>=3.10.0" \
    && find /opt/venv -type d -name "__pycache__" -exec rm -rf {} + \
    && find /opt/venv -type f -name "*.pyc" -delete

# =============================================================================
# STAGE 2: Ultra-Slim Production Runtime (<125MB image, 128MB RAM limit)
# =============================================================================
FROM python:3.12-slim-bookworm AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONMALLOC=malloc \
    MALLOC_ARENA_MAX=2

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r apify && useradd -r -g apify -d /app -s /sbin/nologin apify

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY .actor ./.actor
COPY tls_resilient_harvester.py ./tls_resilient_harvester.py
COPY main.py ./main.py

USER apify

CMD ["python", "-O", "main.py"]
