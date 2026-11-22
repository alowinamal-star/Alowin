"""Hybrid detection engine.

Pipeline for a single document:

1. ``normalize``       – strip invisibles/homoglyphs, decode base64 & escapes,
                         produce extra views to scan.
2. rule scan           – multilingual semantic patterns over every view.
3. context analysis    – per-span quote/education/prohibition weighting.
4. statistical model   – hashed-feature logistic regression probability.
5. risk + decision     – blended score, band, decision, explanation.
6. sanitisation        – redact instruction spans, wrap content as untrusted.

Nothing here executes uploaded content; it is pure text analysis.
"""
from __future__ import annotations

import json
import math
import threading
from pathlib import Path
from typing import Any, Optional

from .. import config
from . import normalize as norm_mod
from . import risk
from .context import analyze_span, document_context
from .features import featurize
from .patterns import CATEGORY_LABELS, compiled_rules

MAX_EVIDENCE = 14
_MODEL_LOCK = threading.Lock()
_MODEL_CACHE: dict[str, Any] = {"path": None, "model": None, "mtime": None}


class LogisticModel:
    """Minimal inference-only logistic regression over hashed features."""

    def __init__(self, payload: dict):
        self.version = payload.get("version", "unknown")
        self.dim = int(payload.get("dim", 1 << 18))
        self.bias = float(payload.get("bias", 0.0))
        self.threshold = float(payload.get("threshold", 0.5))
        self.weights = {int(k): float(v) for k, v in payload.get("weights", {}).items()}
        self.named = {str(k): float(v) for k, v in payload.get("named", {}).items()}
        self.metrics = payload.get("metrics", {})
        self.trained_at = payload.get("trained_at")
        self.training_size = payload.get("training_size")
        self.feature_count = len(self.weights)

    def probability(self, hashed: dict[int, float], named: dict[str, float]) -> float:
        z = self.bias
        weights = self.weights
        for idx, value in hashed.items():
            weight = weights.get(idx)
            if weight:
                z += weight * value
        for key, value in named.items():
            weight = self.named.get(key)
            if weight:
                z += weight * value
        # Numerically stable sigmoid.
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        exp_z = math.exp(z)
        return exp_z / (1.0 + exp_z)

    def describe(self) -> dict:
        return {
            "version": self.version,
            "trained_at": self.trained_at,
            "training_size": self.training_size,
            "feature_count": self.feature_count,
            "threshold": self.threshold,
            "metrics": self.metrics,
            "named_features": sorted(self.named),
        }


def load_model(path: Optional[Path] = None) -> Optional[LogisticModel]:
    """Load (and cache) the trained model; ``None`` when it is not available."""
    path = Path(path or config.MODEL_PATH)
    with _MODEL_LOCK:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            _MODEL_CACHE.update({"path": str(path), "model": None, "mtime": None})
            return None
        if _MODEL_CACHE["path"] == str(path) and _MODEL_CACHE["mtime"] == mtime:
            return _MODEL_CACHE["model"]
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            model = LogisticModel(payload)
        except (OSError, ValueError):
            _MODEL_CACHE.update({"path": str(path), "model": None, "mtime": mtime})
            return None
        _MODEL_CACHE.update({"path": str(path), "model": model, "mtime": mtime})
        return model


def _collect_matches(view_label: str, text: str) -> list[dict]:
    """Run every rule over one text view and keep the best spans."""
    found: list[dict] = []
    for rule, patterns in compiled_rules():
        best: Optional[dict] = None
        occurrences = 0
        for pattern in patterns:
            for match in pattern.finditer(text):
                snippet = match.group(0)
                if not snippet.strip():
                    continue
                occurrences += 1
                start, end = match.start(), match.end()
                ctx = analyze_span(text, start, end)
                candidate = {
                    "rule_id": rule.id,
                    "category": rule.category,
                    "category_label": CATEGORY_LABELS.get(rule.category, rule.category),
                    "severity": rule.severity,
                    "weight": rule.weight,
                    "language": rule.language,
                    "label": rule.label,
                    "reason": rule.reason,
                    "matched_text": snippet[:400],
                    "start": start,
                    "end": end,
                    "view": view_label,
                    "context_factor": ctx["factor"],
                    "mitigated": ctx["mitigated"],
                    "context": ctx,
                }
                if best is None or candidate["context_factor"] > best["context_factor"]:
                    best = candidate
                if occurrences >= 6:
                    break
            if occurrences >= 6:
                break
        if best is not None:
            best["occurrences"] = occurrences
            found.append(best)
    return found


def _dedupe(matches: list[dict]) -> list[dict]:
    """Collapse duplicate spans coming from different views of the same text."""
    seen: dict[tuple[str, str], dict] = {}
    for match in matches:
        key = (match["rule_id"], match["matched_text"].strip().lower()[:80])
        existing = seen.get(key)
        if existing is None or match["context_factor"] > existing["context_factor"]:
            seen[key] = match
    ordered = sorted(
        seen.values(),
        key=lambda m: (-(m["weight"] * m["context_factor"]), m["start"]),
    )
    return ordered[:MAX_EVIDENCE]


class Detector:
    """Stateless analyser; safe to reuse across requests."""

    def __init__(self, model: Optional[LogisticModel] = None):
        self._model = model
        self._model_loaded = model is not None

    @property
    def model(self) -> Optional[LogisticModel]:
        if not self._model_loaded:
            self._model = load_model()
            self._model_loaded = True
        return self._model

    def analyze(
        self,
        text: str,
        *,
        source_name: str = "inline text",
        source_type: str = "text",
        scan_id: str = "pending",
        extra_signals: Optional[dict] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        extra_signals = dict(extra_signals or {})
        norm = norm_mod.normalize(text)
        languages = norm.signals.get("languages") or ["en"]

        matches: list[dict] = []
        for label, view_text in norm.all_views:
            if view_text and view_text.strip():
                matches.extend(_collect_matches(label, view_text))
        matches = _dedupe(matches)

        doc_ctx = document_context(norm.primary)
        hashed, named = featurize(norm.primary)
        model = self.model
        ml_probability = model.probability(hashed, named) if model else None

        components = risk.combine(
            matches, ml_probability, norm.signals, doc_ctx, extra_signals=extra_signals
        )
        decision = risk.decide(components["score"], components["categories"], extra_signals)
        sanitized = risk.sanitize(norm.primary, matches)
        envelope = risk.build_envelope(sanitized, source_name, scan_id, decision)

        evidence = []
        for match in matches:
            evidence.append(
                {
                    "rule_id": match["rule_id"],
                    "category": match["category"],
                    "category_label": match["category_label"],
                    "severity": match["severity"],
                    "label": match["label"],
                    "reason": match["reason"],
                    "matched_text": match["matched_text"],
                    "start": match["start"],
                    "end": match["end"],
                    "language": match["language"],
                    "view": match["view"],
                    "weight": round(match["weight"] * match["context_factor"], 2),
                    "context_factor": match["context_factor"],
                    "mitigated": match["mitigated"],
                    "context_notes": match["context"].get("notes", []),
                    "occurrences": match.get("occurrences", 1),
                }
            )

        return {
            "scan_id": scan_id,
            "source_name": source_name,
            "source_type": source_type,
            "languages_detected": languages,
            "risk_score": components["score"],
            "risk_band": components["band"],
            "decision": decision,
            "decision_label": risk.DECISION_LABELS[decision],
            "summary": risk.summarize(
                components["band"], decision, components["categories"], components["score"]
            ),
            "threat_categories": components["categories"],
            "category_labels": [CATEGORY_LABELS.get(c, c) for c in components["categories"]],
            "evidence": evidence,
            "reasoning": risk.build_reasoning(
                matches, components, doc_ctx, norm.signals
            ),
            "recommended_action": risk.recommended_action(decision, components["categories"]),
            "scores": {
                "rule_component": components["rule_component"],
                "ml_component": components["ml_component"],
                "obfuscation_component": components["obfuscation_component"],
                "document_factor": components["document_factor"],
                "blend": "0.62*rule + 0.38*model" if ml_probability is not None else "rule-only",
            },
            "model": {
                "available": model is not None,
                "version": getattr(model, "version", None),
                "probability": round(ml_probability, 4) if ml_probability is not None else None,
            },
            "obfuscation": {
                "zero_width_removed": norm.signals.get("zero_width_removed", 0),
                "homoglyphs_mapped": norm.signals.get("homoglyphs_mapped", 0),
                "unicode_escapes_decoded": norm.signals.get("unicode_escapes_decoded", 0),
                "html_entities_decoded": norm.signals.get("html_entities_decoded", 0),
                "leet_tokens": norm.signals.get("leet_tokens", 0),
                "encoded_payloads": norm.signals.get("encoded_payloads", 0),
                "views_scanned": [label for label, _ in norm.all_views],
            },
            "hidden_segments": extra_signals.get("hidden_segments", []),
            "document_context": doc_ctx,
            "metadata": metadata or {},
            "sanitized_content": sanitized,
            "untrusted_envelope": envelope,
            "untrusted_banner": risk.UNTRUSTED_BANNER,
            "text_preview": norm.primary[:600],
            "characters": len(norm.primary),
            "word_count": len(norm.primary.split()),
        }


_detector: Optional[Detector] = None


def get_detector() -> Detector:
    global _detector
    if _detector is None:
        _detector = Detector()
    return _detector


def analyze_text(text: str, **kwargs) -> dict:
    return get_detector().analyze(text, **kwargs)
