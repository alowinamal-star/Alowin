# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# PromptShield AI — single-container build.
#   Stage 1 compiles the React/Vite dashboard.
#   Stage 2 runs FastAPI, which serves /api/* and the built SPA on one port.
# ---------------------------------------------------------------------------

# ---------- Stage 1: dashboard build ----------
FROM node:26-alpine AS frontend
RUN apk upgrade --no-cache
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: API + SPA runtime ----------
FROM python:3.13-alpine
# The date keys the build cache so this layer installs today's OS fixes.
RUN echo "os-refresh 2026-11-22" && apk upgrade --no-cache
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY backend/requirements.txt ./requirements.txt
# pymongo/bson ship no musl wheels, so compile them and drop the toolchain again.
RUN apk add --no-cache --virtual .build-deps gcc musl-dev python3-dev libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY backend/ ./backend/
COPY --from=frontend /build/dist ./backend/frontend_dist

ENV PORT=8000 \
    HOME=/home/appjet
RUN mkdir -p /app/backend/data /home/appjet \
    && chown -R 10001:10001 /app /home/appjet

USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "cd /app/backend && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
