"""Dashboard, threat, history, analytics and audit endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import auth, config, db, service

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard/statistics")
def dashboard_statistics(user: dict = Depends(auth.require("read"))) -> dict:
    """Aggregated counters computed from stored scans, never hardcoded."""
    stats = service.dashboard_statistics()
    stats["risk_bands"] = [{"label": label, "min": low, "max": high} for low, high, label in config.RISK_BANDS]
    stats["score_disclaimer"] = (
        "The 0-100 risk score is an application-specific heuristic used to drive this "
        "platform's decisions. It is not a universal or certified security standard."
    )
    return stats


@router.get("/analytics")
def analytics(days: int = Query(14, ge=1, le=90), user: dict = Depends(auth.require("read"))) -> dict:
    return service.analytics(days=days)


@router.get("/threats")
def list_threats(
    limit: int = Query(50, ge=1, le=200),
    risk_band: str | None = None,
    threat_status: str | None = Query(None, alias="status"),
    category: str | None = None,
    user: dict = Depends(auth.require("read")),
) -> dict:
    threats = service.list_threats(limit=limit, risk_band=risk_band, status=threat_status, category=category)
    return {"threats": threats, "count": len(threats)}


@router.get("/threats/{threat_id}")
def get_threat(threat_id: str, user: dict = Depends(auth.require("read"))) -> dict:
    scan = service.get_scan(threat_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat not found.")
    return scan


@router.patch("/threats/{threat_id}")
def update_threat(
    threat_id: str, payload: dict, user: dict = Depends(auth.require("scan"))
) -> dict:
    """Move a threat through the analyst workflow (open → reviewing → mitigated/dismissed)."""
    new_status = str(payload.get("status", "")).strip().lower()
    allowed = {"open", "reviewing", "mitigated", "dismissed"}
    if new_status not in allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"status must be one of {sorted(allowed)}")
    updated = service.update_threat_status(threat_id, new_status, user, note=str(payload.get("note", ""))[:500])
    if not updated:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat not found.")
    db.audit(user, "threat.status_changed", f"Threat {threat_id} -> {new_status}")
    return updated


@router.get("/history")
def history(
    limit: int = Query(100, ge=1, le=500),
    source_type: str | None = None,
    decision: str | None = None,
    user: dict = Depends(auth.require("read")),
) -> dict:
    return {"history": service.list_scans(limit=limit, source_type=source_type, decision=decision)}


@router.get("/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), user: dict = Depends(auth.require("audit"))) -> dict:
    return {"events": db.get_store().find("audit", limit=limit, sort_by="created_at")}
