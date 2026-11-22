"""Obfuscation-resistant text normalisation and language detection.

Attackers hide instructions behind invisible characters, homoglyphs, HTML
entities, unicode escapes, base64 blobs and leetspeak. PromptShield analyses a
*primary* normalised view of the document plus additional *variant* views so a
concealed payload is still inspected, while every variant keeps a record of
what transformation produced it (surfaced as an obfuscation signal).
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = "\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\ufeff\u180e\u00ad"

# Cyrillic / Greek characters that render like Latin letters.
_HOMOGLYPHS = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "α": "a", "ν": "v", "τ": "t", "ρ": "p", "κ": "k", "ι": "i", "ε": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}

_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"}

_UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

SCRIPT_RANGES = {
    "ta": [(0x0B80, 0x0BFF)],
    "hi": [(0x0900, 0x097F)],
    "ar": [(0x0600, 0x06FF)],
    "ru": [(0x0400, 0x04FF)],
    "zh": [(0x4E00, 0x9FFF)],
    "ja": [(0x3040, 0x30FF)],
    "ko": [(0xAC00, 0xD7AF)],
}

SCRIPT_LABELS = {
    "en": "English",
    "ta": "Tamil",
    "hi": "Hindi",
    "ar": "Arabic",
    "ru": "Cyrillic",
    "zh": "Chinese",
    "ja": "Japanese",
    "ko": "Korean",
    "mixed": "Mixed-language",
}


@dataclass
class NormalizedText:
    """A normalised view of the submitted content."""

    primary: str
    variants: list[tuple[str, str]] = field(default_factory=list)  # (label, text)
    signals: dict = field(default_factory=dict)

    @property
    def all_views(self) -> list[tuple[str, str]]:
        return [("primary", self.primary), *self.variants]


def _is_script_char(ch: str, ranges: list[tuple[int, int]]) -> bool:
    code = ord(ch)
    return any(low <= code <= high for low, high in ranges)


def detect_languages(text: str) -> list[str]:
    """Return language/script hints, e.g. ``['en', 'ta', 'mixed']``."""
    if not text:
        return ["en"]
    counts: dict[str, int] = {}
    latin = 0
    total = 0
    for ch in text:
        if not ch.isalpha():
            continue
        total += 1
        if "a" <= ch.lower() <= "z":
            latin += 1
            continue
        for lang, ranges in SCRIPT_RANGES.items():
            if _is_script_char(ch, ranges):
                counts[lang] = counts.get(lang, 0) + 1
                break
    detected: list[str] = []
    if latin and total:
        # Romanised text is treated as English unless it is a minority script.
        if latin / total >= 0.25:
            detected.append("en")
    for lang, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        if total and count / total >= 0.10:
            detected.append(lang)
    if not detected:
        detected = ["en"]
    if len(detected) > 1:
        detected.append("mixed")
    return detected


def _strip_invisibles(text: str) -> tuple[str, int]:
    removed = sum(1 for ch in text if ch in ZERO_WIDTH)
    if not removed:
        return text, 0
    return "".join(ch for ch in text if ch not in ZERO_WIDTH), removed


def _dehomoglyph(text: str) -> tuple[str, int]:
    mapped = 0
    out = []
    for ch in text:
        replacement = _HOMOGLYPHS.get(ch)
        if replacement is not None:
            mapped += 1
            out.append(replacement)
        else:
            out.append(ch)
    return "".join(out), mapped


def _decode_unicode_escapes(text: str) -> tuple[str, int]:
    matches = _UNICODE_ESCAPE.findall(text)
    if not matches:
        return text, 0
    decoded_total = 0

    def _replace(match: re.Match) -> str:
        nonlocal decoded_total
        raw = match.group(0)
        try:
            decoded = raw.encode().decode("unicode_escape")
        except Exception:
            return raw
        if not decoded.strip():
            return raw
        decoded_total += 1
        return decoded

    return _UNICODE_ESCAPE.sub(_replace, text), decoded_total


def _leet_view(text: str) -> tuple[str, int]:
    """Map digit-for-letter substitutions only inside mixed alphanumeric words."""
    changed = 0
    out = []
    for token in re.split(r"(\s+)", text):
        if not token or token.isspace():
            out.append(token)
            continue
        has_alpha = any(c.isalpha() for c in token)
        has_leet = any(c in _LEET for c in token)
        if has_alpha and has_leet and any(c.isdigit() for c in token):
            new_token = "".join(_LEET.get(c, c) for c in token)
            if new_token != token:
                changed += 1
                out.append(new_token)
                continue
        out.append(token)
    return "".join(out), changed


def _base64_payloads(text: str) -> list[str]:
    payloads: list[str] = []
    for match in _B64_BLOB.finditer(text):
        blob = match.group(0)
        try:
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(decoded.strip()) < 8:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c.isspace())
        if printable / max(1, len(decoded)) < 0.85:
            continue
        payloads.append(decoded.strip())
    return payloads[:5]


def normalize(text: str) -> NormalizedText:
    """Produce the primary view, decoded variants and obfuscation signals."""
    original = text or ""
    working, zero_width = _strip_invisibles(original)
    # NFKC folds full-width / stylised characters into canonical forms.
    working = unicodedata.normalize("NFKC", working)
    working = working.replace("\r\n", "\n").replace("\r", "\n")
    working, homoglyphs = _dehomoglyph(working)
    working, escaped = _decode_unicode_escapes(working)
    # HTML entities are common in scraped web content.
    unescaped = html.unescape(working)
    entity_count = 0
    if unescaped != working:
        entity_count = max(0, working.count("&") - unescaped.count("&"))
        working = unescaped

    variants: list[tuple[str, str]] = []
    leet_text, leet_tokens = _leet_view(working)
    if leet_tokens:
        variants.append(("leet", leet_text))
    b64 = _base64_payloads(working)
    for idx, payload in enumerate(b64):
        variants.append((f"base64-{idx + 1}", payload))

    signals = {
        "zero_width_removed": zero_width,
        "homoglyphs_mapped": homoglyphs,
        "unicode_escapes_decoded": escaped,
        "html_entities_decoded": entity_count,
        "leet_tokens": leet_tokens,
        "encoded_payloads": len(b64),
        "decoded_payloads": b64,
        "languages": detect_languages(working),
    }
    return NormalizedText(primary=working, variants=variants, signals=signals)


def obfuscation_score(signals: dict) -> float:
    """0-1 aggregate of how much hiding technique was applied."""
    score = 0.0
    if signals.get("zero_width_removed", 0) >= 3:
        score += 0.30
    elif signals.get("zero_width_removed", 0) > 0:
        score += 0.12
    if signals.get("homoglyphs_mapped", 0) >= 4:
        score += 0.25
    if signals.get("unicode_escapes_decoded", 0) > 0:
        score += 0.20
    if signals.get("encoded_payloads", 0) > 0:
        score += 0.30
    if signals.get("leet_tokens", 0) >= 2:
        score += 0.15
    return min(1.0, round(score, 3))
