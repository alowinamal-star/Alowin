"""Offline training for the PromptShield statistical classifier.

Pure-Python logistic regression on hashed features (no numpy/scikit-learn at
runtime, so the deployed image stays small). Run:

    python -m ml.train            # from backend/
    python -m ml.train --report   # include per-split metrics

The resulting ``ml/model.json`` is committed, and the training metrics stored
inside it are the only accuracy claims this project makes.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security.features import DIM, featurize  # noqa: E402
from app.security.patterns import baseline_keyword_hits  # noqa: E402
from ml.dataset import build_samples, dataset_fingerprint  # noqa: E402

MODEL_VERSION = "promptshield-hashed-lr-1.0"
EPOCHS = 60
LEARNING_RATE = 0.35
L2 = 2e-4
SEED = 20240517


def _train(
    rows: list[tuple[dict[int, float], dict[str, float], int]],
    epochs: int = EPOCHS,
    lr: float = LEARNING_RATE,
) -> tuple[float, dict[int, float], dict[str, float]]:
    rng = random.Random(SEED)
    weights: dict[int, float] = {}
    named_weights: dict[str, float] = {key: 0.0 for key in rows[0][1]} if rows else {}
    bias = 0.0
    order = list(range(len(rows)))
    for epoch in range(epochs):
        rng.shuffle(order)
        rate = lr / (1.0 + epoch * 0.05)
        for idx in order:
            hashed, named, label = rows[idx]
            z = bias + sum(weights.get(k, 0.0) * v for k, v in hashed.items())
            z += sum(named_weights.get(k, 0.0) * v for k, v in named.items())
            prob = 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))
            error = prob - label
            for key, value in hashed.items():
                grad = error * value + L2 * weights.get(key, 0.0)
                weights[key] = weights.get(key, 0.0) - rate * grad
            for key, value in named.items():
                grad = error * value + L2 * named_weights.get(key, 0.0)
                named_weights[key] = named_weights.get(key, 0.0) - rate * grad
            bias -= rate * error
    return bias, weights, named_weights


def _probability(hashed, named, bias, weights, named_weights) -> float:
    z = bias + sum(weights.get(k, 0.0) * v for k, v in hashed.items())
    z += sum(named_weights.get(k, 0.0) * v for k, v in named.items())
    return 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))


def _metrics(preds: list[int], labels: list[int]) -> dict:
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


def _tune_threshold(rows, labels, bias, weights, named_weights) -> tuple[float, dict]:
    probs = [_probability(h, n, bias, weights, named_weights) for h, n, _ in rows]
    best = (0.5, -1.0, {})
    for step in range(20, 81):
        threshold = step / 100
        preds = [1 if p >= threshold else 0 for p in probs]
        metrics = _metrics(preds, labels)
        if metrics["f1"] > best[1]:
            best = (threshold, metrics["f1"], metrics)
    return best[0], best[2]


def train_and_save(model_path: Path | None = None, report: bool = False) -> dict:
    samples = build_samples()
    splits = {"train": [], "validation": [], "test": []}
    for sample in samples:
        splits[sample["split"]].append(sample)

    def rows_for(items):
        rows = []
        for item in items:
            hashed, named = featurize(item["text"])
            rows.append((hashed, named, item["label"]))
        return rows

    train_rows = rows_for(splits["train"])
    val_rows = rows_for(splits["validation"])
    test_rows = rows_for(splits["test"])
    val_labels = [item["label"] for item in splits["validation"]]
    test_labels = [item["label"] for item in splits["test"]]

    bias, weights, named_weights = _train(train_rows)
    threshold, val_metrics = _tune_threshold(val_rows, val_labels, bias, weights, named_weights)

    test_probs = [_probability(h, n, bias, weights, named_weights) for h, n, _ in test_rows]
    test_preds = [1 if p >= threshold else 0 for p in test_probs]
    test_metrics = _metrics(test_preds, test_labels)

    train_probs = [_probability(h, n, bias, weights, named_weights) for h, n, _ in train_rows]
    train_preds = [1 if p >= threshold else 0 for p in train_probs]
    train_metrics = _metrics(train_preds, [row[2] for row in train_rows])

    # Documented keyword baseline on the same held-out split.
    baseline_preds = [1 if baseline_keyword_hits(item["text"]) >= 1 else 0 for item in splits["test"]]
    baseline_metrics = _metrics(baseline_preds, test_labels)

    # Per-language / per-slice breakdown of the held-out split.
    slices: dict[str, dict] = {}
    for item, pred in zip(splits["test"], test_preds):
        key = item["language"] if item["label"] == 1 else f"benign:{item['category']}"
        bucket = slices.setdefault(key, {"preds": [], "labels": []})
        bucket["preds"].append(pred)
        bucket["labels"].append(item["label"])
    slice_metrics = {k: _metrics(v["preds"], v["labels"]) for k, v in slices.items()}

    trimmed_weights = {str(k): round(v, 5) for k, v in weights.items() if abs(v) > 1e-4}
    payload = {
        "version": MODEL_VERSION,
        "dim": DIM,
        "bias": round(bias, 6),
        "threshold": round(threshold, 3),
        "weights": trimmed_weights,
        "named": {k: round(v, 5) for k, v in named_weights.items()},
        "metrics": {
            "train": train_metrics,
            "validation": val_metrics,
            "test": test_metrics,
            "keyword_baseline_test": baseline_metrics,
            "slices_test": slice_metrics,
            "split_sizes": {k: len(v) for k, v in splits.items()},
        },
        "training_size": len(train_rows),
        "feature_count": len(trimmed_weights),
        "dataset_fingerprint": dataset_fingerprint(samples),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "notes": (
            "Hashed-feature logistic regression trained offline on the repo dataset. "
            "Metrics describe this synthetic, hand-authored dataset only; they are not a "
            "claim about production accuracy."
        ),
    }

    target = Path(model_path or (Path(__file__).resolve().parent / "model.json"))
    target.write_text(json.dumps(payload, indent=1), encoding="utf-8")

    if report:
        print(json.dumps(payload["metrics"], indent=2))
        print(f"\nSaved {target} ({target.stat().st_size / 1024:.0f} KB, {len(trimmed_weights)} weights)")
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the PromptShield classifier")
    parser.add_argument("--report", action="store_true", help="print evaluation metrics")
    args = parser.parse_args()
    train_and_save(report=True if args.report else True)
