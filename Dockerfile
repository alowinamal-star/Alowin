# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# PromptShield AI — single container.
#   Stage 1 compiles the React/Vite dashboard.
#   Stage 2 runs FastAPI, which serves /api/* and the built SPA on one port.
# Only the paths the build actually needs are copied, so the host's
# node_modules, caches and local SQLite data never enter the image.
# ---------------------------------------------------------------------------

# ---------- Stage 1: dashboard build ----------
FROM node:26-alpine AS frontend
RUN apk upgrade --no-cache
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/index.html frontend/vite.config.js ./
COPY frontend/src ./src
RUN npm run build

# ---------- Stage 2: API + SPA runtime ----------
FROM python:3.13-alpine
# The date keys the build cache so this layer installs today's OS fixes.
RUN echo "os-refresh 2026-11-22" && apk upgrade --no-cache
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install from the fully resolved lockfile: the image gets exactly the direct and
# transitive versions that dependency scanning can resolve, not a floating set.
COPY backend/requirements.lock ./requirements.lock
# pymongo/bson publish no musl wheels, so compile them and drop the toolchain.
RUN apk add --no-cache --virtual .build-deps gcc musl-dev python3-dev libffi-dev \
    && pip install --no-cache-dir -r requirements.lock \
    && apk del .build-deps

# Application code + the trained classifier artifact.
COPY backend/app ./backend/app
COPY backend/ml ./backend/ml
COPY --from=frontend /build/dist ./backend/frontend_dist

ENV PORT=8000 \
    HOME=/home/appjet
RUN mkdir -p /app/backend/data /home/appjet \
    && chown -R 10001:10001 /app /home/appjet

USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "cd /app/backend && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
