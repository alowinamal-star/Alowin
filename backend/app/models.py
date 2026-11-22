"""PromptShield AI — API schemas (Pydantic v2)."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

Decision = Literal[
    "allow_untrusted",
    "flag_for_review",
    "quarantine",
    "block",
    "require_human_approval",
]

ActionType = Literal[
    "send_email",
    "share_file",
    "execute_command",
    "transfer_funds",
    "read_secret",
    "http_request",
    "delete_records",
]


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=1, max_length=200)


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    name: str = Field(default="", max_length=120)
    password: str = Field(min_length=8, max_length=200)
    role: Literal["admin", "analyst", "viewer"] = "analyst"


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    capabilities: list[str] = []
    created_at: Optional[str] = None


class LoginResponse(BaseModel):
    token: str
    expires_in: int
    user: UserOut


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
class TextScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=200_000)
    source_name: str = Field(default="pasted-text.txt", max_length=200)
    declared_type: Literal["text", "html", "email", "pdf", "url"] = "text"
    notes: str = Field(default="", max_length=500)

    @field_validator("content")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("content must not be blank")
        return value


class EmailScanRequest(BaseModel):
    raw_email: str = Field(min_length=1, max_length=200_000, description="Raw RFC 822 email or plain body text")
    source_name: str = Field(default="message.eml", max_length=200)


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2000)

    @field_validator("url")
    @classmethod
    def _scheme(cls, value: str) -> str:
        lowered = value.strip().lower()
        if not (lowered.startswith("http://") or lowered.startswith("https://")):
            raise ValueError("Only http:// and https:// URLs may be scanned")
        return value.strip()


class MultiDocumentRequest(BaseModel):
    scan_ids: list[str] = Field(min_length=2, max_length=12)
    label: str = Field(default="", max_length=160)


class EvidenceOut(BaseModel):
    rule_id: str
    category: str
    category_label: str
    severity: str
    label: str
    reason: str
    matched_text: str
    start: int
    end: int
    language: str
    view: str
    weight: float
    context_factor: float
    mitigated: bool = False
    context_notes: list[str] = Field(default_factory=list)
    occurrences: int = 1


class AnalysisOut(BaseModel):
    risk_score: float
    risk_band: str
    decision: Decision
    decision_label: str
    threat_categories: list[str]
    category_labels: list[str]
    evidence: list[EvidenceOut]
    scores: dict[str, Any]
    model: dict[str, Any]
    reasoning: list[str]
    recommended_action: str
    summary: str
    languages_detected: list[str]
    obfuscation: dict[str, Any]
    hidden_segments: list[str] = Field(default_factory=list)
    document_context: dict[str, Any]
    sanitized_content: str
    untrusted_envelope: str
    untrusted_banner: str
    text_preview: str
    characters: int
    word_count: int


class ScanOut(BaseModel):
    id: str
    source_name: str
    source_type: str
    source_origin: str
    content_length: int
    content_preview: str
    metadata: dict[str, Any]
    analysis: AnalysisOut
    ai_processing: Optional[dict[str, Any]] = None
    created_at: str
    created_by: str
    batch_id: Optional[str] = None
    status: str = "analysed"


# --------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------
class FirewallActionRequest(BaseModel):
    action_type: ActionType
    origin: Literal["user", "agent", "external_content"] = "agent"
    user_role: Literal["admin", "analyst", "viewer"] = "analyst"
    source_scan_ids: list[str] = Field(default_factory=list, max_length=12)
    parameters: dict[str, Any] = Field(default_factory=dict)
    intent: str = Field(default="", max_length=500)


class FirewallRuleResult(BaseModel):
    rule: str
    status: Literal["pass", "warn", "require_approval", "block"]
    detail: str


class FirewallDecision(BaseModel):
    decision: Literal["allow", "require_human_approval", "block"]
    risk_level: Literal["low", "medium", "high", "critical"]
    reasons: list[str]
    rule_results: list[FirewallRuleResult]
    approval_id: Optional[str] = None
    action_id: str
    sanitized_parameters: dict[str, Any]
    explanation: str
    created_at: str


class ApprovalRequest(BaseModel):
    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=500)


# --------------------------------------------------------------------------
# Testing laboratory
# --------------------------------------------------------------------------
class TestingRunRequest(BaseModel):
    subsets: list[str] = Field(default_factory=lambda: ["all"], max_length=8)
    mutate: bool = True
    compare_baseline: bool = True


class TestingRunOut(BaseModel):
    run_id: str
    created_at: str
    created_by: str
    dataset: dict[str, Any]
    overall: dict[str, Any]
    baseline: Optional[dict[str, Any]] = None
    per_subset: list[dict[str, Any]]
    mutations: list[dict[str, Any]]
    confusion_matrix: dict[str, int]
    threshold: float
    notes: list[str]
