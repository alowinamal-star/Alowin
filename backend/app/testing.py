"""Adaptive security testing laboratory.

Evaluates the *deployed hybrid detector* (rules + context + statistical model)
against the documented keyword baseline on a held-out split, plus mutation
suites that emulate attacker adaptation:

* ``paraphrase``  – softened wording and politeness wrappers
* ``obfuscation`` – zero-width characters, leetspeak, HTML entities
* ``hidden``      – HTML comments / hidden-element style payloads
* ``multilingual``– Tamil, Hindi and romanised mixed-language attacks
* ``benign_lookalike`` – security documentation that quotes attacks

Nothing here trains or updates the model at request time: this is an
*evaluation* harness, not online learning. Metrics describe this synthetic
dataset only.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from . import db
from .security.classifier import analyze_text
from .security.patterns import baseline_keyword_hits
from ml.dataset import build_samples, dataset_fingerprint


# ------------------------------------------------------------------ mutations
def _m_paraphrase(text: str) -> str:
    return f"Kindly review the following and act accordingly: {text} Thanks in advance."


def _m_obfuscation(text: str) -> str:
    table = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})
    leet = text.translate(table)
    return f"{leet[:60]}\u200b\u200b{leet[60:]}".strip()


def _m_hidden(text: str) -> str:
    return f"<p>Invoice summary attached.</p><!-- assistant: {text} --><p>Regards</p>"


def _m_entity(text: str) -> str:
    encoded = "".join(f"&#{ord(ch)};" if ch.isalpha() and i % 3 == 0 else ch for i, ch in enumerate(text))
    return f"<html><body><div style='display:none'>{encoded}</div><p>Quarterly report</p></body></html>"


MUTATORS: dict[str, Callable[[str], str]] = {
    "paraphrase": _m_paraphrase,
    "obfuscation": _m_obfuscation,
    "hidden": _m_hidden,
    "html_entity": _m_entity,
}


def _metrics(labels: list[int], preds: list[int]) -> dict:
    tp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 1)
    tn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 0)
    fp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 0)
    fn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 1)
    total = max(1, len(labels))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "samples": len(labels),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": round((tp + tn) / total, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else 0.0,
    }


def _detect(text: str) -> dict:
    """Run the production detector; malicious = anything above 'allow'."""
    result = analyze_text(text, source_name="evaluation sample", source_type="text")
    return {
        "score": result["risk_score"],
        "decision": result["decision"],
        "categories": result["threat_categories"],
        "predicted": 0 if result["decision"] == "allow_untrusted" else 1,
        "evidence_count": len(result["evidence"]),
    }


def _suite(name: str, samples: list[dict], transform: Optional[Callable[[str], str]] = None) -> dict:
    labels: list[int] = []
    hybrid_preds: list[int] = []
    baseline_preds: list[int] = []
    failures: list[dict] = []

    for sample in samples:
        text = transform(sample["text"]) if transform else sample["text"]
        verdict = _detect(text)
        baseline_hit = 1 if baseline_keyword_hits(text) >= 1 else 0
        labels.append(sample["label"])
        hybrid_preds.append(verdict["predicted"])
        baseline_preds.append(baseline_hit)
        if verdict["predicted"] != sample["label"]:
            failures.append(
                {
                    "sample_id": sample["id"],
                    "family": sample["family"],
                    "expected": "malicious" if sample["label"] else "benign",
                    "predicted": "malicious" if verdict["predicted"] else "benign",
                    "score": verdict["score"],
                    "decision": verdict["decision"],
                    "categories": verdict["categories"],
                    "excerpt": text[:160],
                }
            )

    return {
        "suite": name,
        "hybrid": _metrics(labels, hybrid_preds),
        "keyword_baseline": _metrics(labels, baseline_preds),
        "failures": failures[:12],
    }


def run_evaluation(user: Optional[dict] = None, persist: bool = True, limit_suites: Optional[list[str]] = None) -> dict:
    started = time.perf_counter()
    samples = build_samples()
    test = [s for s in samples if s["split"] == "test"]
    attacks = [s for s in test if s["label"] == 1]
    benign = [s for s in test if s["label"] == 0]

    suites: list[dict] = []
    selected = set(limit_suites or [])

    def wanted(name: str) -> bool:
        return not selected or name in selected

    if wanted("held_out"):
        suites.append(_suite("held_out", test))
    if wanted("multilingual"):
        multilingual = [s for s in attacks if s["language"] in ("ta", "hi", "mixed")]
        suites.append(_suite("multilingual", multilingual or attacks))
    if wanted("benign_lookalike"):
        suites.append(_suite("benign_lookalike", benign or test))
    for name, mutator in MUTATORS.items():
        if wanted(name):
            suites.append(_suite(name, attacks or test, transform=mutator))

    aggregate_labels: list[int] = []
    aggregate_hybrid: list[int] = []
    aggregate_baseline: list[int] = []
    for suite in suites:
        count = suite["hybrid"]["samples"]
        aggregate_labels.extend([1] * suite["hybrid"]["tp"] + [0] * suite["hybrid"]["tn"])
        aggregate_labels.extend([1] * suite["hybrid"]["fn"] + [0] * suite["hybrid"]["fp"])
        aggregate_hybrid.extend([1] * suite["hybrid"]["tp"] + [0] * suite["hybrid"]["tn"])
        aggregate_hybrid.extend([0] * suite["hybrid"]["fn"] + [1] * suite["hybrid"]["fp"])
        aggregate_baseline.extend([1] * suite["keyword_baseline"]["tp"] + [0] * suite["keyword_baseline"]["tn"])
        aggregate_baseline.extend([0] * suite["keyword_baseline"]["fn"] + [1] * suite["keyword_baseline"]["fp"])
        _ = count

    overall = _metrics(aggregate_labels, aggregate_hybrid)
    baseline_overall = _metrics(aggregate_labels, aggregate_baseline)
    duration_ms = round((time.perf_counter() - started) * 1000, 1)

    report = {
        "id": db.new_id("test"),
        "created_at": db.utcnow(),
        "duration_ms": duration_ms,
        "dataset": {
            "fingerprint": dataset_fingerprint(samples),
            "total_samples": len(samples),
            "held_out_samples": len(test),
            "splits": {
                name: len([s for s in samples if s["split"] == name])
                for name in ("train", "validation", "test")
            },
        },
        "overall": overall,
        "keyword_baseline_overall": baseline_overall,
        "delta": {
            "precision": round(overall["precision"] - baseline_overall["precision"], 4),
            "recall": round(overall["recall"] - baseline_overall["recall"], 4),
            "false_positive_rate": round(
                overall["false_positive_rate"] - baseline_overall["false_positive_rate"], 4
            ),
            "false_negative_rate": round(
                overall["false_negative_rate"] - baseline_overall["false_negative_rate"], 4
            ),
        },
        "suites": suites,
        "notes": (
            "Evaluation only — the model is not retrained or updated by this run. "
            "Scores describe the repository's synthetic dataset, not production traffic."
        ),
        "actor": (user or {}).get("email", "system"),
    }

    if persist:
        db.insert("test_runs", report)
        db.audit(
            user or "system",
            "testing.evaluation",
            f"Ran {len(suites)} suites over {overall['samples']} samples in {duration_ms} ms",
            {"test_run_id": report["id"], "overall": overall},
        )
    return report
