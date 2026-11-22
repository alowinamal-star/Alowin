"""Runtime configuration for PromptShield AI.

Every value is environment driven so the same image runs locally, in CI and in
production. Nothing here reads secrets from disk or from the frontend bundle.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/


def _path(env_name: str, default: Path) -> Path:
    raw = os.environ.get(env_name, "").strip()
    return Path(raw).expanduser().resolve() if raw else default


DATA_DIR = _path("DATA_DIR", BASE_DIR / "data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Generated classifier produced by backend/ml/train.py (committed to the repo).
MODEL_PATH = _path("MODEL_PATH", BASE_DIR / "ml" / "model.json")
# Dataset splits used by the Adaptive Testing Laboratory.
DATASET_DIR = _path("DATASET_DIR", BASE_DIR / "data" / "dataset")
# Built SPA copied into the image (frontend/dist).
FRONTEND_DIST = _path("FRONTEND_DIST", BASE_DIR / "frontend_dist")

# --- Storage -------------------------------------------------------------
# When MONGODB_URI is present the platform stores everything in MongoDB.
# Otherwise it falls back to an embedded SQLite document store so the
# prototype is runnable with zero external services.
MONGODB_URI = os.environ.get("MONGODB_URI", "").strip()
MONGODB_DB = os.environ.get("MONGODB_DB", "promptshield").strip()

# --- Auth ----------------------------------------------------------------
# If unset, a random signing key is generated once and persisted in the store
# so issued tokens survive a restart.
SECRET_KEY_ENV = os.environ.get("PROMPTSHIELD_SECRET", "").strip()
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", str(8 * 3600)))
SEED_ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@promptshield.ai").strip()
SEED_ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "Admin@12345")
# Demo analyst/viewer accounts for the hackathon walkthrough. Set
# SEED_DEMO_USERS=0 to disable them and the /api/auth/demo-accounts endpoint.
SEED_DEMO_USERS = os.environ.get("SEED_DEMO_USERS", "1") != "0"
SEED_DEMO_PASSWORD = os.environ.get("SEED_DEMO_PASSWORD", "Demo@12345")

# --- Limits --------------------------------------------------------------
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
MAX_TEXT_CHARS = int(os.environ.get("MAX_TEXT_CHARS", "200000"))
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "240"))
RATE_LIMIT_SCAN_PER_MINUTE = int(os.environ.get("RATE_LIMIT_SCAN_PER_MINUTE", "60"))

# --- URL scanning / SSRF protection -------------------------------------
URL_FETCH_TIMEOUT = float(os.environ.get("URL_FETCH_TIMEOUT", "8"))
URL_MAX_REDIRECTS = int(os.environ.get("URL_MAX_REDIRECTS", "3"))
URL_MAX_BYTES = int(os.environ.get("URL_MAX_BYTES", str(2 * 1024 * 1024)))
# Only enable for local demos; allows fetching loopback/private hosts.
ALLOW_PRIVATE_URL_FETCH = os.environ.get("ALLOW_PRIVATE_URL_FETCH", "0") == "1"

# --- Optional external LLM ----------------------------------------------
# The AI-processing stage runs fully offline unless an operator explicitly
# configures a provider. No document content leaves the server by default.
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "").strip().rstrip("/")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "").strip()
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini").strip()
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "25"))

# --- Firewall policy ----------------------------------------------------
# Recipient domains the agent may email without human approval.
EMAIL_ALLOWLIST = [
    d.strip().lower()
    for d in os.environ.get("FIREWALL_EMAIL_ALLOWLIST", "promptshield.ai,example.com").split(",")
    if d.strip()
]
# Monetary amount above which a transfer needs human approval.
TRANSFER_APPROVAL_THRESHOLD = float(os.environ.get("TRANSFER_APPROVAL_THRESHOLD", "500"))
# Hard ceiling: never auto-approved regardless of role.
TRANSFER_HARD_LIMIT = float(os.environ.get("TRANSFER_HARD_LIMIT", "10000"))

APP_NAME = "PromptShield AI"
APP_VERSION = "1.0.0"

# Browser origins allowed to call the API cross-origin (comma separated).
# The bundled SPA is served same-origin, so this stays empty by default.
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]

# Seed the demonstration scans (real pipeline runs) on first boot so the
# dashboard is meaningful immediately. Set SEED_DEMO_SCANS=0 to start empty.
SEED_DEMO_SCANS = os.environ.get("SEED_DEMO_SCANS", "1") != "0"

RISK_BANDS = [
    (0, 29, "low"),
    (30, 59, "medium"),
    (60, 79, "high"),
    (80, 100, "critical"),
]


def risk_band(score: float) -> str:
    for low, high, label in RISK_BANDS:
        if low <= score <= high:
            return label
    return "critical" if score > 100 else "low"
