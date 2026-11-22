"""Service layer: scan persistence, threat listing, dashboard and analytics.

Routers stay thin; all aggregation lives here so the same numbers are used by
the dashboard, the history page and the analytics page.
"""
from __future__ import annotations

from typing import Optional

from . import db
from .security.risk import DECISION_LABELS

MALICIOUS_DECISIONS = {"flag_for_review", "quarantine", "block", "require_human_approval"}


def record_scan(analysis: dict, actor: dict, extraction: Optional[dict] = None) -> dict:
    """Persist a completed analysis and register a threat record if needed."""
    scan = {
        "id": analysis["scan_id"],
        "created_at": db.utcnow(),
        "actor": actor.get("email", "unknown"),
        "actor_role": actor.get("role", "analyst"),
        "source_name": analysis["source_name"],
        "source_type": analysis["source_type"],
        "risk_score": analysis["risk_score"],
        "risk_band": analysis["risk_band"],
        "decision": analysis["decision"],
        "decision_label": DECISION_LABELS.get(analysis["decision"], analysis["decision"]),
        "summary": analysis["summary"],
        "threat_categories": analysis["threat_categories"],
        "category_labels": analysis["category_labels"],
        "languages_detected": analysis["languages_detected"],
        "evidence": analysis["evidence"],
        "reasoning": analysis["reasoning"],
        "recommended_action": analysis["recommended_action"],
        "scores": analysis["scores"],
        "model": analysis["model"],
        "obfuscation": analysis["obfuscation"],
        "document_context": analysis["document_context"],
        "hidden_segments": analysis.get("hidden_segments", []),
        "metadata": analysis.get("metadata", {}),
        "characters": analysis["characters"],
        "word_count": analysis["word_count"],
        "text_preview": analysis["text_preview"],
        "sanitized_content": analysis["sanitized_content"],
        "untrusted_envelope": analysis["untrusted_envelope"],
        "extraction": {
            "kind": (extraction or {}).get("kind"),
            "filename": (extraction or {}).get("filename"),
            "warnings": (extraction or {}).get("warnings", []),
            "metadata": (extraction or {}).get("metadata", {}),
        },
    }
    db.insert("scans", scan)

    if analysis["decision"] in MALICIOUS_DECISIONS:
        db.insert(
            "threats",
            {
                "id": db.new_id("threat"),
                "created_at": scan["created_at"],
                "scan_id": scan["id"],
                "actor": scan["actor"],
                "source_name": scan["source_name"],
                "source_type": scan["source_type"],
                "risk_score": scan["risk_score"],
                "risk_band": scan["risk_band"],
                "decision": scan["decision"],
                "decision_label": scan["decision_label"],
                "summary": scan["summary"],
                "threat_categories": scan["threat_categories"],
                "category_labels": scan["category_labels"],
                "languages_detected": scan["languages_detected"],
                "evidence": scan["evidence"][:6],
                "reasoning": scan["reasoning"],
                "recommended_action": scan["recommended_action"],
                "blocked": scan["decision"] in {"block", "quarantine"},
                "status": "open",
                "severity": scan["risk_band"],
            },
        )

    db.audit(
        actor,
        "scan.completed",
        f"{scan['source_type']} scan of '{scan['source_name']}' scored {scan['risk_score']} ({scan['decision']})",
        {"scan_id": scan["id"], "risk_band": scan["risk_band"]},
    )
    return scan


def get_scan(scan_id: str) -> Optional[dict]:
    return db.get("scans", scan_id)


def list_scans(limit: int = 50, source_type: Optional[str] = None, actor: Optional[str] = None) -> list[dict]:
    predicate = None
    if source_type or actor:
        def predicate(doc: dict) -> bool:  # noqa: E306
            if source_type and doc.get("source_type") != source_type:
                return False
            if actor and doc.get("actor") != actor:
                return False
            return True

    return db.get_store().find("scans", predicate=predicate, limit=limit)


def list_threats(limit: int = 100, status: Optional[str] = None, band: Optional[str] = None) -> list[dict]:
    def predicate(doc: dict) -> bool:  # noqa: E306
        if status and doc.get("status") != status:
            return False
        if band and doc.get("risk_band") != band:
            return False
        return True

    return db.get_store().find("threats", predicate=predicate if (status or band) else None, limit=limit)


def update_threat_status(threat_id: str, status: str, actor: dict) -> Optional[dict]:
    updated = db.get_store().update("threats", threat_id, {"status": status, "reviewed_by": actor.get("email")})
    if updated:
        db.audit(actor, "threat.status", f"Threat {threat_id} marked {status}", {"threat_id": threat_id})
    return updated


def dashboard_statistics() -> dict:
    store = db.get_store()
    scans = store.find("scans", limit=2000)
    threats = store.find("threats", limit=2000)
    approvals = store.find("approvals", limit=500)
    actions = store.find("firewall_actions", limit=2000)

    total = len(scans)
    malicious = [s for s in scans if s["decision"] in MALICIOUS_DECISIONS]
    blocked = [s for s in scans if s["decision"] in {"block", "quarantine"}]
    critical = [s for s in scans if s["risk_band"] == "critical"]
    safe = [s for s in scans if s["decision"] == "allow_untrusted"]

    detection_rate = round(100.0 * len(malicious) / total, 1) if total else 0.0
    block_rate = round(100.0 * len(blocked) / max(1, len(malicious)), 1) if malicious else 0.0
    avg_risk = round(sum(s["risk_score"] for s in scans) / total, 1) if total else 0.0

    by_category: dict[str, int] = {}
    by_language: dict[str, int] = {}
    for scan in scans:
        for category in scan.get("threat_categories", []):
            by_category[category] = by_category.get(category, 0) + 1
        for language in scan.get("languages_detected", []):
            by_language[language] = by_language.get(language, 0) + 1

    by_source: dict[str, int] = {}
    for scan in scans:
        key = scan.get("source_type", "text")
        by_source[key] = by_source.get(key, 0) + 1

    # 14-day activity series (real data, zero-filled).
    from datetime import datetime, timedelta, timezone

    today = datetime.now(timezone.utc).date()
    series = []
    for offset in range(13, -1, -1):
        day = today - timedelta(days=offset)
        day_scans = [s for s in scans if str(s.get("created_at", ""))[:10] == day.isoformat()]
        series.append(
            {
                "date": day.isoformat(),
                "scans": len(day_scans),
                "threats": len([s for s in day_scans if s["decision"] in MALICIOUS_DECISIONS]),
                "blocked": len([s for s in day_scans if s["decision"] in {"block", "quarantine"}]),
                "avg_risk": round(sum(s["risk_score"] for s in day_scans) / len(day_scans), 1) if day_scans else 0.0,
            }
        )

    recent = [
        {
            "id": s["id"],
            "created_at": s["created_at"],
            "source_name": s["source_name"],
            "source_type": s["source_type"],
            "risk_score": s["risk_score"],
            "risk_band": s["risk_band"],
            "decision": s["decision"],
            "decision_label": s["decision_label"],
            "summary": s["summary"],
            "actor": s.get("actor"),
        }
        for s in scans[:8]
    ]

    return {
        "total_scans": total,
        "attacks_detected": len(malicious),
        "attacks_blocked": len(blocked),
        "safe_documents": len(safe),
        "critical_alerts": len(critical),
        "open_threats": len([t for t in threats if t.get("status") == "open"]),
        "detection_rate": detection_rate,
        "block_rate": block_rate,
        "average_risk_score": avg_risk,
        "firewall": {
            "actions_evaluated": len(actions),
            "actions_blocked": len([a for a in actions if a.get("status") in {"blocked", "denied"}]),
            "pending_approvals": len([a for a in approvals if a.get("status") == "pending"]),
            "approved": len([a for a in approvals if a.get("status") == "approved"]),
            "denied": len([a for a in approvals if a.get("status") == "denied"]),
        },
        "by_category": sorted(
            ({"category": k, "count": v} for k, v in by_category.items()),
            key=lambda x: -x["count"],
        ),
        "by_language": sorted(
            ({"language": k, "count": v} for k, v in by_language.items()),
            key=lambda x: -x["count"],
        ),
        "by_source": sorted(
            ({"source_type": k, "count": v} for k, v in by_source.items()),
            key=lambda x: -x["count"],
        ),
        "activity": series,
        "recent_activity": recent,
        "storage": store.health(),
    }


def analytics() -> dict:
    stats = dashboard_statistics()
    store = db.get_store()
    runs = store.find("test_runs", limit=1)
    latest_run = runs[0] if runs else None
    scans = store.find("scans", limit=2000)

    # Score distribution buckets (real data).
    buckets = [{"band": "low", "min": 0, "count": 0}, {"band": "medium", "min": 30, "count": 0},
               {"band": "high", "min": 60, "count": 0}, {"band": "critical", "min": 80, "count": 0}]
    for scan in scans:
        score = scan.get("risk_score", 0)
        for bucket in reversed(buckets):
            if score >= bucket["min"]:
                bucket["count"] += 1
                break

    return {
        "statistics": stats,
        "score_distribution": buckets,
        "latest_evaluation": latest_run,
        "detector": {
            "model": (scans[0]["model"] if scans else {"available": False}),
            "rules_version": "promptshield-rules-1.0",
        },
    }
