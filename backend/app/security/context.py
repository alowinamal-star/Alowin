"""Context-aware analysis.

The hard part of prompt-injection detection is not finding the phrase
"ignore previous instructions" — it is knowing whether the document is
*issuing* that instruction to an AI or merely *quoting* it (a security report,
an awareness-training slide, a quoted email thread).

This module computes, per matched span:

* ``in_quote``        – the span sits inside quotation marks, a blockquote or a
                        code block;
* ``educational``     – the surrounding text frames it as an example,
                        research, detection rule or mitigation advice;
* ``prohibition``     – the surrounding text forbids the action ("never do X");
* ``addressed_to_model`` – the span talks about the assistant's own
                        instructions/permissions rather than to a human.

Those flags scale the rule weight so a documented attack example is reported as
informational evidence instead of a critical incident.
"""
from __future__ import annotations

import re

QUOTE_PAIRS = (('"', '"'), ("'", "'"), ("\u201c", "\u201d"), ("\u00ab", "\u00bb"), ("\u2018", "\u2019"))

EDUCATIONAL_CUES = re.compile(
    r"("
    r"for\s+example|for\s+instance|e\.g\.|such\s+as|sample\s+(?:payload|attack|prompt)|"
    r"attackers?\s+(?:may|might|could|often|typically)|example\s+of\s+an?\s+(?:attack|injection)|"
    r"this\s+(?:report|document|paper|section|chapter|training)|"
    r"we\s+(?:analyse|analyze|describe|discuss|demonstrate|simulate)|"
    r"case\s+study|awareness\s+training|security\s+(?:research|training|review)|"
    r"malicious\s+prompt\s+(?:such\s+as|like)|"
    r"detect(?:ion|ed|s)?\s+(?:rule|pattern|these|this)|"
    r"mitigat(?:e|ion)|countermeasure|red\s*team|penetration\s+test|"
    r"do\s+not\s+(?:follow|comply|execute)|never\s+(?:follow|comply|execute|obey)"
    r")",
    re.IGNORECASE,
)

PROHIBITION_CUES = re.compile(
    r"(?:never|must\s+not|mustn't|should\s+not|shouldn't|do\s+not|don'?t|refuse\s+to|"
    r"is\s+not\s+allowed|are\s+not\s+allowed|prohibited|block(?:ed)?\s+(?:this|any)|flag\s+(?:this|any))",
    re.IGNORECASE,
)

MODEL_ADDRESS_CUES = re.compile(
    r"(?:you\s+are\s+an?\s+(?:ai|assistant|model)|your\s+(?:system\s+)?instructions|"
    r"your\s+(?:rules|guidelines|permissions|tools)|as\s+an?\s+(?:ai|assistant|agent)|"
    r"the\s+(?:ai|assistant|agent|model)\s+(?:must|should|will|shall))",
    re.IGNORECASE,
)

REPORT_FRAMING = re.compile(
    r"(?:prompt\s+injection|threat\s+model|security\s+(?:report|assessment|policy)|"
    r"detection\s+(?:engine|rule|rate)|mitigation|vulnerability|exploit(?:s|ed)?|"
    r"OWASP|LLM0\d|red\s*team)",
    re.IGNORECASE,
)

HUMAN_RECIPIENT = re.compile(
    r"(?:dear\s+(?:team|all|colleagues|sir|madam)|hi\s+(?:team|all)|"
    r"best\s+regards|kind\s+regards|thanks,|sincerely)",
    re.IGNORECASE,
)

IMPERATIVE_AT_MODEL = re.compile(
    r"(?:\b(?:ignore|disregard|reveal|send|forward|delete|transfer|execute|print|output|"
    r"email|share|approve|bypass|disable|grant|repeat)\b)",
    re.IGNORECASE,
)

_WINDOW_BEFORE = 420
_WINDOW_AFTER = 180


def _inside_quote(text: str, start: int, end: int) -> bool:
    window_start = max(0, start - 300)
    prefix = text[window_start:start]
    suffix = text[end : end + 300]
    for opener, closer in QUOTE_PAIRS:
        if opener == closer:
            if prefix.count(opener) % 2 == 1 and closer in suffix:
                return True
        else:
            unmatched = prefix.count(opener) - prefix.count(closer)
            if unmatched > 0 and closer in suffix:
                return True
    # Markdown blockquote or fenced/indented code block.
    line_start = text.rfind("\n", 0, start) + 1
    line_prefix = text[line_start:start]
    if line_prefix.lstrip().startswith(">"):
        return True
    if line_prefix.startswith("    ") or line_prefix.startswith("\t"):
        return True
    if text.count("```", 0, start) % 2 == 1:
        return True
    return False


def analyze_span(text: str, start: int, end: int) -> dict:
    """Context classification for one matched span."""
    before = text[max(0, start - _WINDOW_BEFORE) : start]
    after = text[end : end + _WINDOW_AFTER]
    sentence_window = before[-260:] + text[start:end] + after[:120]

    in_quote = _inside_quote(text, start, end)
    educational = bool(EDUCATIONAL_CUES.search(before[-300:]))
    prohibition = bool(PROHIBITION_CUES.search(before[-160:]))
    addressed_to_model = bool(MODEL_ADDRESS_CUES.search(sentence_window)) or bool(
        re.search(r"\b(?:you|your)\b", text[max(0, start - 120) : end + 80], re.IGNORECASE)
    )

    factor = 1.0
    notes: list[str] = []
    if in_quote:
        factor *= 0.55
        notes.append("evidence sits inside quoted or formatted text")
    if educational:
        factor *= 0.50
        notes.append("surrounding text frames it as an example/analysis")
    if prohibition:
        factor *= 0.70
        notes.append("surrounding text forbids the action")
    if addressed_to_model:
        factor *= 1.20
        notes.append("wording targets the assistant's own instructions or tools")
    if not (in_quote or educational) and IMPERATIVE_AT_MODEL.search(sentence_window):
        factor *= 1.10

    factor = max(0.10, min(1.6, factor))
    return {
        "in_quote": in_quote,
        "educational": educational,
        "prohibition": prohibition,
        "addressed_to_model": addressed_to_model,
        "factor": round(factor, 3),
        "mitigated": factor < 0.5,
        "notes": notes,
    }


def document_context(text: str) -> dict:
    """Document-level framing used to dampen or amplify the final score."""
    length = max(1, len(text))
    quote_chars = sum(text.count(q) for pair in QUOTE_PAIRS for q in pair)
    educational_hits = len(EDUCATIONAL_CUES.findall(text))
    report_hits = len(REPORT_FRAMING.findall(text))
    human_framing = bool(HUMAN_RECIPIENT.search(text))
    mentions_model = bool(MODEL_ADDRESS_CUES.search(text))

    quote_density = round(min(1.0, quote_chars / (length / 120)), 3)
    educational_density = round(educational_hits / (length / 1000), 3) if length > 200 else 0.0

    # A document is treated as "analysis/documentation" only when it is framed
    # as security material *and* quotes or discusses the technique.
    analytical = report_hits > 0 and (quote_density > 0.15 or educational_hits > 0)
    return {
        "quote_density": quote_density,
        "educational_density": educational_density,
        "report_framing": report_hits > 0,
        "educational_framing": educational_hits > 0,
        "analytical_document": analytical,
        "human_addressing": human_framing,
        "mentions_model": mentions_model,
    }


def document_factor(doc_ctx: dict) -> float:
    """Multiplier applied once at document level (kept gentle and explainable)."""
    factor = 1.0
    if doc_ctx.get("analytical_document"):
        factor *= 0.72
    if doc_ctx.get("human_addressing") and not doc_ctx.get("mentions_model"):
        factor *= 0.95
    return round(factor, 3)
