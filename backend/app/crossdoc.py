"""Cross-document attack analysis.

Documents are analysed independently first (see ``security.classifier``); this
module only looks at *relationships* between their suspicious fragments.

Design rules that avoid the "shared words ⇒ malicious" trap:

* similarity is computed **only over the suspicious spans** the detector found,
  never over whole documents (two invoices share boilerplate, that is not an
  attack);
* a pair is only flagged when it shows at least one *strong* signal — a shared
  unique indicator (email/domain/amount/account), a high phrase overlap on
  suspicious text, or two or more shared attack categories;
* common words are removed before comparison;
* a document's own risk score and decision are never rewritten by this module.
"""
from __future__ import annotations

import hashlib
import re
from itertools import combinations
from typing import Iterable

from .db import audit, get_store, new_id, utcnow

STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "your", "you", "are", "was", "were",
    "have", "has", "had", "will", "would", "should", "could", "must", "not", "all", "any",
    "please", "kindly", "also", "into", "then", "than", "them", "they", "their", "there",
    "here", "when", "what", "which", "who", "how", "our", "out", "get", "got", "can", "may",
    "his", "her", "its", "it", "is", "be", "to", "of", "in", "on", "at", "as", "by", "or",
    "if", "so", "we", "he", "she", "do", "does", "did", "been", "being", "about", "after",
    "before", "over", "under", "very", "just", "now", "new", "one", "two", "more", "most",
}

INDICATOR_PATTERNS = {
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"),
    "url": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|example|ru|cn|xyz|top|shop|info)\b", re.IGNORECASE),
    "amount": re.compile(r"(?:rs\.?|inr|\$|usd|€)\s?\d[\d,]*(?:\.\d{2})?", re.IGNORECASE),
    "account": re.compile(r"\b(?:acct|account|iban|upi)[\s:#-]*[A-Za-z0-9@._-]{6,}", re.IGNORECASE),
    "phone": re.compile(r"\b\+?\d{10,15}\b"),
    "code": re.compile(r"\b(?:[A-Z]{2,}-?\d{3,}|TXN\d+)\b"),
}

TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


def _norm_token(token: str) -> str:
    return token.lower()


def _content_tokens(text: str) -> list[str]:
    return [
        _norm_token(t)
        for t in TOKEN_RE.findall(text)
        if len(t) > 2 and _norm_token(t) not in STOPWORDS and not t.isdigit()
    ]


def _shingles(tokens: list[str], size: int = 4) -> set[str]:
    if len(tokens) < size:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i : i + size]) for i in range(len(tokens) - size + 1)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def _suspicious_text(scan: dict) -> str:
    analysis = scan.get("analysis") or {}
    parts = []
    for item in analysis.get("evidence", []):
        parts.append(str(item.get("matched_text", "")))
        parts.append(str(item.get("label", "")))
    if not parts:
        # No rule evidence: use preview so weak relationships are still visible.
        parts.append(str(scan.get("content_preview", ""))[:800])
    return " \n".join(parts)


def _indicators(text: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for name, pattern in INDICATOR_PATTERNS.items():
        values = {m.group(0).lower().strip(".,;)") for m in pattern.finditer(text)}
        if values:
            found[name] = values
    return found


def _document_profile(scan: dict) -> dict:
    analysis = scan.get("analysis") or {}
    suspicious = _suspicious_text(scan)
    tokens = _content_tokens(suspicious)
    evidence = analysis.get("evidence", [])
    unmitigated = [e for e in evidence if not e.get("mitigated")]
    return {
        "scan_id": scan.get("id"),
        "source_name": scan.get("source_name", "unknown"),
        "source_type": scan.get("source_type", "text"),
        "risk_score": float(analysis.get("risk_score", 0)),
        "decision": analysis.get("decision", "allow_untrusted"),
        "categories": set(analysis.get("threat_categories", [])),
        "rule_ids": {e["rule_id"] for e in unmitigated},
        "languages": set(analysis.get("languages_detected", [])),
        "tokens": tokens,
        "shingles": _shingles(tokens),
        "indicators": _indicators(suspicious),
    }


def _pair_relationship(a: dict, b: dict) -> dict:
    shared_rules = sorted(a["rule_ids"] & b["rule_ids"])
    shared_categories = sorted(a["categories"] & b["categories"])
    phrase_overlap = _jaccard(a["shingles"], b["shingles"])

    shared_indicators: dict[str, list[str]] = {}
    for kind in set(a["indicators"]) | set(b["indicators"]):
        common = a["indicators"].get(kind, set()) & b["indicators"].get(kind, set())
        if common:
            shared_indicators[kind] = sorted(common)[:6]

    # Strong-evidence gate: shared vocabulary alone never flags a campaign.
    strong = bool(shared_indicators) or phrase_overlap >= 0.25 or len(shared_rules) >= 2 or len(shared_categories) >= 2

    score = 0.0
    score += min(45.0, 15.0 * len(shared_categories))
    score += min(25.0, 10.0 * len(shared_rules))
    score += min(40.0, phrase_overlap * 100.0)
    score += min(45.0, 15.0 * sum(len(v) for v in shared_indicators.values()))
    if a["languages"] & b["languages"] and len(a["languages"] | b["languages"]) > 1:
        score += 5.0
    score = round(min(100.0, score if strong else min(score, 25.0)), 1)

    if strong and score >= 60:
        relationship = "coordinated_campaign"
    elif strong and score >= 35:
        relationship = "probable_coordination"
    elif score >= 20:
        relationship = "weak_similarity"
    else:
        relationship = "unrelated"

    explanation = []
    if shared_categories:
        explanation.append(f"shared attack categories: {', '.join(shared_categories)}")
    if shared_rules:
        explanation.append(f"{len(shared_rules)} shared detection rule(s)")
    if phrase_overlap >= 0.25:
        explanation.append(f"suspicious phrasing overlap {phrase_overlap:.0%}")
    if shared_indicators:
        flat = [f"{k}: {', '.join(v)}" for k, v in shared_indicators.items()]
        explanation.append("shared indicators (" + "; ".join(flat) + ")")
    if not strong:
        explanation.append("similarity is explained by common vocabulary, not a shared payload")

    return {
        "document_a": a["scan_id"],
        "document_b": b["scan_id"],
        "source_a": a["source_name"],
        "source_b": b["source_name"],
        "relationship": relationship,
        "score": score,
        "strong_evidence": strong,
        "shared_rules": shared_rules,
        "shared_categories": shared_categories,
        "phrase_overlap": round(phrase_overlap, 3),
        "shared_indicators": shared_indicators,
        "explanation": "; ".join(explanation),
    }


def _cluster(flagged: list[dict]) -> list[list[str]]:
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(x: str, y: str) -> None:
        parent[find(x)] = find(y)

    for rel in flagged:
        union(rel["document_a"], rel["document_b"])
    groups: dict[str, list[str]] = {}
    for node in list(parent):
        groups.setdefault(find(node), []).append(node)
    return [sorted(members) for members in groups.values() if len(members) > 1]


def analyze_batch(scans: list[dict], label: str, user: dict) -> dict:
    """Compare already-scanned documents and persist a campaign record."""
    if len(scans) < 2:
        raise ValueError("Cross-document analysis needs at least two documents.")

    profiles = [_document_profile(scan) for scan in scans]
    relationships = [
        _pair_relationship(a, b) for a, b in combinations(profiles, 2)
    ]
    flagged = [r for r in relationships if r["relationship"] in ("coordinated_campaign", "probable_coordination")]
    clusters = _cluster(flagged)

    by_id = {p["scan_id"]: p for p in profiles}
    cluster_reports = []
    for members in clusters:
        member_profiles = [by_id[m] for m in members]
        max_risk = max(p["risk_score"] for p in member_profiles)
        campaign_risk = round(min(100.0, max_risk + 8.0 * (len(members) - 1)), 1)
        categories = sorted({c for p in member_profiles for c in p["categories"]})
        cluster_reports.append(
            {
                "cluster_id": "clu-" + hashlib.sha1("|".join(sorted(members)).encode()).hexdigest()[:10],
                "documents": [
                    {
                        "scan_id": p["scan_id"],
                        "source_name": p["source_name"],
                        "risk_score": p["risk_score"],
                        "decision": p["decision"],
                        "categories": sorted(p["categories"]),
                    }
                    for p in member_profiles
                ],
                "categories": categories,
                "campaign_risk": campaign_risk,
                "campaign_band": "critical" if campaign_risk >= 80 else "high" if campaign_risk >= 60 else "medium",
                "requires_review": campaign_risk >= 60,
                "summary": (
                    f"{len(members)} documents show coordinated injection evidence across "
                    f"{len(categories)} categories. Distributed delivery suggests a single actor; "
                    "treat the set as one campaign rather than independent incidents."
                ),
            }
        )

    campaign_risk = max((c["campaign_risk"] for c in cluster_reports), default=0.0)
    requires_review = bool(cluster_reports) and campaign_risk >= 60
    shared_indicators: dict[str, set[str]] = {}
    for rel in flagged:
        for kind, values in rel["shared_indicators"].items():
            shared_indicators.setdefault(kind, set()).update(values)

    batch = {
        "id": new_id("bat"),
        "label": label or "Cross-document analysis",
        "document_count": len(scans),
        "documents": [
            {
                "scan_id": p["scan_id"],
                "source_name": p["source_name"],
                "source_type": p["source_type"],
                "risk_score": p["risk_score"],
                "decision": p["decision"],
                "categories": sorted(p["categories"]),
                "languages": sorted(p["languages"]),
            }
            for p in profiles
        ],
        "relationships": relationships,
        "clusters": cluster_reports,
        "campaign_risk": campaign_risk,
        "requires_review": requires_review,
        "shared_indicators": {k: sorted(v) for k, v in shared_indicators.items()},
        "summary": (
            f"{len(scans)} documents compared; {len(flagged)} relationship(s) flagged and "
            f"{len(cluster_reports)} coordinated cluster(s) identified."
            if flagged
            else f"{len(scans)} documents compared; no coordinated pattern found."
        ),
        "recommendation": (
            "Escalate the cluster to a security analyst: block all linked tool actions and trace the "
            "delivery channel shared by these documents."
            if requires_review
            else "Documents can be processed independently as untrusted content."
        ),
        "created_at": utcnow(),
        "created_by": user.get("email", "unknown"),
    }
    get_store().insert("batches", batch)
    audit(
        user,
        "analysis.cross_document",
        batch["summary"],
        {"batch_id": batch["id"], "campaign_risk": campaign_risk},
    )
    return batch
