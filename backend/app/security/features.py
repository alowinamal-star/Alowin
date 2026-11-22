"""Sparse feature extraction for the statistical classifier.

Features are hashed into a fixed-size vector so the model stays a small JSON
file (no pickle, no compiled stack) and is byte-for-byte reproducible:

* word unigrams and bigrams (multilingual — ``\\w`` matches Tamil/Hindi words)
* character trigrams, which survive obfuscation and small edits
* a handful of engineered document statistics

The same code path is used at training time (ml/train.py) and at inference
time, so there is no train/serve skew.
"""
from __future__ import annotations

import hashlib
import math
import re

DIM = 1 << 18  # 262,144 hashed buckets

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\S+@\S+\.\w+")
_DELIM_RE = re.compile(r"<\|[^|]{1,20}\|>|\[/?INST\]|<\s*/?\s*system\s*>|(?m)^\s*#{2,}\s*system", re.IGNORECASE)
_IMPERATIVE_RE = re.compile(
    r"\b(?:ignore|disregard|reveal|send|forward|delete|transfer|execute|print|output|share|"
    r"approve|bypass|disable|grant|repeat|email|upload|leak)\b",
    re.IGNORECASE,
)
_QUOTE_FRAME_RE = re.compile(r"[\"\u201c\u00ab\u2018]|^\s*>|```", re.MULTILINE)
_AI_MENTION_RE = re.compile(r"\b(?:ai|assistant|chatbot|agent|llm|language\s+model|prompt)\b", re.IGNORECASE)

MAX_TOKENS = 1500
MAX_CHAR_GRAMS = 6000


def _bucket(feature: str) -> int:
    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(digest, "big") % DIM


def tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())[:MAX_TOKENS]


def engineered_features(text: str) -> dict[str, float]:
    length = max(1, len(text))
    tokens = tokenize(text)
    token_count = max(1, len(tokens))
    upper = sum(1 for c in text if c.isupper())
    digits = sum(1 for c in text if c.isdigit())
    lines = text.count("\n") + 1
    return {
        "len_log": round(math.log1p(length) / 10.0, 4),
        "token_len_log": round(math.log1p(token_count) / 10.0, 4),
        "has_url": 1.0 if _URL_RE.search(text) else 0.0,
        "has_email": 1.0 if _EMAIL_RE.search(text) else 0.0,
        "has_delimiter": 1.0 if _DELIM_RE.search(text) else 0.0,
        "has_quote_frame": 1.0 if _QUOTE_FRAME_RE.search(text) else 0.0,
        "mentions_ai": 1.0 if _AI_MENTION_RE.search(text) else 0.0,
        "imperative_ratio": round(len(_IMPERATIVE_RE.findall(text)) / token_count, 4),
        "uppercase_ratio": round(upper / length, 4),
        "digit_ratio": round(digits / length, 4),
        "line_density": round(lines / length * 100, 4),
    }


def featurize(text: str) -> tuple[dict[int, float], dict[str, float]]:
    """Return (hashed sparse features, engineered named features)."""
    tokens = tokenize(text)
    hashed: dict[int, float] = {}

    def add(key: str, value: float = 1.0) -> None:
        idx = _bucket(key)
        hashed[idx] = hashed.get(idx, 0.0) + value

    for tok in tokens:
        add("w:" + tok)
    for first, second in zip(tokens, tokens[1:]):
        add(f"b:{first}_{second}", 0.8)

    # Character trigrams over a whitespace-collapsed view: robust to spacing,
    # punctuation and light obfuscation.
    collapsed = re.sub(r"\s+", " ", text.lower())[:8000]
    for i in range(0, max(0, len(collapsed) - 2), 1):
        gram = collapsed[i : i + 3]
        if gram.strip():
            add("c:" + gram, 0.35)
        if len(hashed) > MAX_CHAR_GRAMS:
            break

    # L2-normalise so document length does not dominate the dot product.
    norm = math.sqrt(sum(v * v for v in hashed.values())) or 1.0
    return {k: v / norm for k, v in hashed.items()}, engineered_features(text)
