"""System endpoints: health, version/runtime info and demo samples."""
from __future__ import annotations

import platform
import sys
import time

from fastapi import APIRouter, Depends

from .. import auth, config, db, samples

router = APIRouter(prefix="/api", tags=["system"])
_STARTED_AT = time.time()


@router.get("/health")
def health() -> dict:
    store = db.get_store()
    return {
        "status": "ok",
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "storage": store.backend_name,
        "storage_ready": bool(store.health().get("ok")),
        "uptime_seconds": round(time.time() - _STARTED_AT, 1),
    }


@router.get("/system/info")
def system_info(user: dict = Depends(auth.require("read"))) -> dict:
    store = db.get_store()
    return {
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "storage_backend": store.backend_name,
        "counts": {
            "scans": store.count("scans"),
            "threats": store.count("threats"),
            "actions": store.count("actions"),
            "approvals": store.count("approvals"),
            "audit": store.count("audit"),
            "users": store.count("users"),
        },
        "limits": {
            "max_upload_bytes": config.MAX_UPLOAD_BYTES,
            "max_text_chars": config.MAX_TEXT_CHARS,
            "scan_rate_per_minute": config.RATE_LIMIT_SCAN_PER_MINUTE,
        },
        "llm": {"configured": bool(config.LLM_BASE_URL and config.LLM_API_KEY), "model": config.LLM_MODEL if config.LLM_BASE_URL else None},
        "runtime": {"python": sys.version.split()[0], "platform": platform.platform()},
        "detector": {"model": "logistic-regression (hashed char n-grams + rule features)", "threshold": 0.5},
    }


@router.get("/samples")
def demo_samples(user: dict = Depends(auth.require("read"))) -> dict:
    """Bundled demonstration payloads (scenario A-E) for the scanners."""
    return {"samples": samples.public_samples()}
