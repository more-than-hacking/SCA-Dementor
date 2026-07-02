# ─────────────────────────────────────────────────────────────────────────────
# Dementor — The SCA Hunter
# Reachability-aware Software Composition Analysis. Open-source; bring your own
# LLM key (Gemini/OpenAI/Anthropic) to unlock the AI reachability engine.
#
#   docker build -t dementor-sca .
#   docker run --rm -p 5000:5000 --env-file .env dementor-sca
#   → http://localhost:5000
#
# Simpler still:  docker compose up   (see docker-compose.yaml)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    DEMENTOR_IN_DOCKER=1

# git: clone target repos for scanning.  curl: container HEALTHCHECK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first so the layer caches across code changes.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# App code (.dockerignore keeps secrets, clones and generated state out).
COPY . .

# Create runtime dirs (persisted via volumes) and a non-root user that owns them.
RUN mkdir -p /app/REPOSITORIES /app/.cache /app/config \
    && touch /app/scan_jobs.jsonl \
    && useradd --create-home --uid 10001 dementor \
    && chown -R dementor:dementor /app
USER dementor

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:5000/ || exit 1

# server.py binds 0.0.0.0:5000 with the auto-reloader OFF by default
# (DEMENTOR_RELOAD must NOT be set — the reloader kills background scan threads).
CMD ["python", "server.py"]
