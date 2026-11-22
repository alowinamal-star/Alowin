"""PromptShield AI — FastAPI application.

Serves the JSON API under ``/api`` and the built single-page dashboard from
``frontend/dist`` (copied to ``backend/frontend_dist`` in the container) so the
whole product runs as one process on one port.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import auth, config, db, seed
from .routers import (
    auth_routes,
    dashboard_routes,
    firewall_routes,
    scan_routes,
    system_routes,
    testing_routes,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("promptshield")

DESCRIPTION = """
**PromptShield AI** is a context-aware indirect prompt-injection detection and
prevention platform. External content (PDF, TXT, HTML, email, URL) is extracted,
analysed by a hybrid rule + multilingual + statistical engine, scored 0-100,
quarantined when necessary, and passed to the AI stage strictly as untrusted
data. An independent Smart Action Firewall validates every tool call.

Scores are application-specific heuristics, not a universal security standard.
"""


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.ensure_collections()
    auth.seed_users()
    try:
        seed.seed_demo_scans()
    except Exception:  # pragma: no cover - seeding must never block startup
        log.exception("Demo seeding failed; starting with the existing data set")
    log.info("%s %s ready (storage=%s)", config.APP_NAME, config.APP_VERSION, db.get_store().backend_name)
    yield


app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    description=DESCRIPTION,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

if config.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

for module in (system_routes, auth_routes, scan_routes, firewall_routes, dashboard_routes, testing_routes):
    app.include_router(module.router)


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error."}, status_code=500)


_DIST = config.FRONTEND_DIST
if (_DIST / "index.html").is_file():
    if (_DIST / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=str(_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        """Serve static assets and fall back to index.html for client routes."""
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "Not found."}, status_code=404)
        candidate = (_DIST / full_path).resolve()
        if full_path and candidate.is_file() and _DIST.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_DIST / "index.html")

else:  # API-only mode (development: Vite dev server proxies /api)

    @app.get("/", include_in_schema=False)
    def api_root() -> dict:
        return {
            "app": config.APP_NAME,
            "version": config.APP_VERSION,
            "docs": "/api/docs",
            "note": "Frontend build not found. Run `npm run build` in frontend/ or use the Vite dev server.",
        }
