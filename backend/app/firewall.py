"""Smart Action Firewall.

An independent security layer between the AI assistant and its tools. It never
trusts the model's own judgement: every proposed action is validated against
user role, action type, destination, data classification and the risk of the
content that motivated it.

Key principle: **external content can never grant itself permissions**. Any
privileged action whose origin is retrieved content is denied, regardless of
how convincing the text is.

Approvals are persisted, so a human decision is recorded and auditable. Actions
are dispatched through a narrow executor that only sends mail when SMTP is
explicitly configured; otherwise it reports ``delivery: not_configured`` rather
than pretending to have sent anything.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from . import config
from .db import audit, get_store, new_id, utcnow

PRIVILEGED_ACTIONS = {
    "send_email",
    "share_file",
    "execute_command",
    "transfer_payment",
    "update_record",
    "delete_record",
}
READ_ACTIONS = {"read_document", "summarize_document", "search_knowledge_base"}

ROLE_ALLOWED_ACTIONS = {
    "admin": PRIVILEGED_ACTIONS | READ_ACTIONS | {"approve_request"},
    "analyst": READ_ACTIONS | {"send_email", "share_file", "update_record", "delete_record"},
    "viewer": READ_ACTIONS,
}

SENSITIVE_CLASSIFICATIONS = {"confidential", "secret", "pii", "financial", "credentials"}

DANGEROUS_COMMAND = re.compile(
    r"(rm\s+-rf|mkfs|dd\s+if=|:\(\)\{|curl[^\n]*\|\s*(?:ba)?sh|wget[^\n]*\|\s*(?:ba)?sh|"
    r"chmod\s+777|chown\s+root|shutdown|reboot|useradd|passwd\s|sudo\s|nc\s+-e|"
    r"eval\s*\(|os\.system|subprocess\.|/etc/shadow|\.ssh/)",
    re.IGNORECASE,
)

SECRET_KEY_PATTERN = re.compile(r"(password|passwd|secret|token|api[_-]?key|credential|ssn|card|cvv|private)", re.IGNORECASE)

DEFAULT_POLICY = {
    "require_approval_for": ["send_email", "share_file", "transfer_payment", "update_record", "delete_record"],
    "block_external_content_actions": True,
    "email_domain_allowlist": list(config.EMAIL_ALLOWLIST),
    "transfer_approval_threshold": config.TRANSFER_APPROVAL_THRESHOLD,
    "transfer_hard_limit": config.TRANSFER_HARD_LIMIT,
    "quarantine_blocks_tools": True,
    "blocked_action_types": [],
    "require_approval_when_source_risk_above": 60,
}


def load_policy() -> dict:
    """Stored policy merged over defaults (admin-editable)."""
    policy = dict(DEFAULT_POLICY)
    stored = get_store().find("settings", lambda d: d.get("key") == "firewall", limit=1)
    if stored:
        override = stored[0].get("value") or {}
        for key, value in override.items():
            if key in policy:
                policy[key] = value
    return policy


def save_policy(updates: dict, actor: dict) -> dict:
    store = get_store()
    current = load_policy()
    for key, value in updates.items():
        if key in DEFAULT_POLICY and value is not None:
            current[key] = value
    existing = store.find("settings", lambda d: d.get("key") == "firewall", limit=1)
    if existing:
        store.update("settings", existing[0]["id"], {"value": current, "updated_at": utcnow()})
    else:
        store.insert("settings", {"id": new_id("set"), "key": "firewall", "value": current, "updated_at": utcnow()})
    audit(actor, "firewall.policy_updated", "Firewall policy updated", {"policy": current})
    return current


def _redact(parameters: dict) -> dict:
    redacted: dict[str, Any] = {}
    for key, value in (parameters or {}).items():
        if SECRET_KEY_PATTERN.search(str(key)) and isinstance(value, str) and value:
            redacted[key] = f"***redacted ({len(value)} chars)***"
        elif isinstance(value, dict):
            redacted[key] = _redact(value)
        else:
            redacted[key] = value
    return redacted


def _result(rule: str, status: str, detail: str) -> dict:
    return {"rule": rule, "status": status, "detail": detail}


def _domain(address: str) -> str:
    match = re.search(r"@([\w.\-]+)", address or "")
    return match.group(1).lower() if match else ""


def validate_action(payload: dict, user: dict, source_scans: Optional[list[dict]] = None) -> dict:
    """Validate a proposed tool call. Returns a ``FirewallDecision`` shaped dict."""
    policy = load_policy()
    source_scans = source_scans or []
    action_type = payload.get("action_type", "read_document")
    origin = payload.get("origin", "agent")
    role = payload.get("user_role") or user.get("role", "viewer")
    params = payload.get("parameters") or {}
    intent = payload.get("intent", "")

    results: list[dict] = []
    reasons: list[str] = []
    decision = "allow"
    risk_level = "low"

    def escalate(level: str) -> None:
        nonlocal decision, risk_level
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if level == "block":
            decision = "block"
        elif level == "require_approval" and decision != "block":
            decision = "require_human_approval"
        risk_map = {"block": "critical", "require_approval": "high", "warn": "medium", "pass": "low"}
        candidate = risk_map.get(level, "low")
        if order[candidate] > order[risk_level]:
            risk_level = candidate

    # 1. Role-based permission -------------------------------------------------
    allowed = ROLE_ALLOWED_ACTIONS.get(role, READ_ACTIONS)
    if action_type in allowed:
        results.append(_result("rbac.role_permission", "pass", f"Role '{role}' may request '{action_type}'."))
    else:
        results.append(
            _result("rbac.role_permission", "block", f"Role '{role}' is not permitted to perform '{action_type}'.")
        )
        reasons.append(f"Role '{role}' lacks permission for {action_type}.")
        escalate("block")

    # 2. Explicitly blocked action types --------------------------------------
    if action_type in (policy.get("blocked_action_types") or []):
        results.append(_result("policy.blocked_action", "block", f"'{action_type}' is disabled by policy."))
        reasons.append(f"'{action_type}' is blocked by firewall policy.")
        escalate("block")
    else:
        results.append(_result("policy.blocked_action", "pass", "Action type is enabled."))

    # 3. External content must never grant permissions ------------------------
    if origin == "external_content" and action_type in PRIVILEGED_ACTIONS:
        if policy.get("block_external_content_actions", True):
            results.append(
                _result(
                    "origin.external_content_privilege",
                    "block",
                    "Privileged action requested by retrieved content; untrusted text cannot authorise tool use.",
                )
            )
            reasons.append(
                "Origin is external content: retrieved documents cannot grant tool permissions, so the action is denied."
            )
            escalate("block")
        else:
            results.append(
                _result("origin.external_content_privilege", "require_approval", "External origin requires human approval.")
            )
            escalate("require_approval")
    elif origin == "external_content":
        results.append(
            _result("origin.external_content_privilege", "warn", "Read-only action from external content, allowed as untrusted.")
        )
        escalate("warn")
    else:
        results.append(_result("origin.external_content_privilege", "pass", f"Origin '{origin}' may request actions."))

    # 4. Risk of the content that motivated the action -----------------------
    max_risk = max((float((s.get("analysis") or {}).get("risk_score", 0)) for s in source_scans), default=0.0)
    quarantined = [
        s.get("id", "?")
        for s in source_scans
        if (s.get("analysis") or {}).get("decision") in ("quarantine", "block")
    ]
    if quarantined and policy.get("quarantine_blocks_tools", True):
        results.append(
            _result("source.quarantined_content", "block", f"Linked content is quarantined/blocked: {', '.join(quarantined)}.")
        )
        reasons.append("The action cites content that is quarantined or blocked.")
        escalate("block")
    elif max_risk >= float(policy.get("require_approval_when_source_risk_above", 60)):
        results.append(
            _result("source.risk_threshold", "require_approval", f"Linked content risk is {max_risk:.0f}/100.")
        )
        reasons.append(f"Content that motivated this action scored {max_risk:.0f}/100.")
        escalate("require_approval")
    else:
        results.append(_result("source.risk_threshold", "pass", f"Linked content risk {max_risk:.0f}/100 within tolerance."))

    # 5. Destination / recipient checks --------------------------------------
    recipient = str(params.get("recipient") or params.get("to") or params.get("destination") or "")
    if action_type == "send_email" and recipient:
        domain = _domain(recipient)
        allowlist = [d.lower() for d in policy.get("email_domain_allowlist", [])]
        if not domain:
            results.append(_result("destination.recipient", "block", "Recipient address is not a valid mailbox."))
            reasons.append("Recipient address is invalid.")
            escalate("block")
        elif allowlist and domain in allowlist:
            results.append(_result("destination.recipient", "pass", f"Recipient domain '{domain}' is allow-listed."))
        else:
            results.append(
                _result("destination.recipient", "require_approval", f"Recipient domain '{domain}' is external.")
            )
            reasons.append(f"Recipient domain '{domain}' is outside the trusted allow-list.")
            escalate("require_approval")

    # 6. Sensitive data access ------------------------------------------------
    classification = str(params.get("data_classification") or "").lower()
    content_sensitive = bool(re.search(r"(confidential|secret|password|api[_-]?key)", intent, re.IGNORECASE))
    if classification in SENSITIVE_CLASSIFICATIONS or content_sensitive:
        results.append(
            _result(
                "data.classification",
                "require_approval",
                f"Data classification '{classification or 'inferred confidential'}' requires human approval.",
            )
        )
        reasons.append("Action touches confidential or sensitive data.")
        escalate("require_approval")
        if action_type == "send_email" and recipient and _domain(recipient) not in [
            d.lower() for d in policy.get("email_domain_allowlist", [])
        ]:
            results.append(
                _result("data.external_disclosure", "block", "Confidential data destined for an external domain.")
            )
            reasons.append("Confidential data would leave the organisation boundary.")
            escalate("block")
    else:
        results.append(_result("data.classification", "pass", "No sensitive data classification on the action."))

    # 7. Payment limits -------------------------------------------------------
    if action_type == "transfer_payment":
        try:
            amount = float(params.get("amount", 0))
        except (TypeError, ValueError):
            amount = 0.0
        if amount > float(policy.get("transfer_hard_limit", config.TRANSFER_HARD_LIMIT)):
            results.append(_result("payment.hard_limit", "block", f"Amount {amount:.2f} exceeds the hard limit."))
            reasons.append(f"Payment amount exceeds the hard limit of {policy.get('transfer_hard_limit')}.")
            escalate("block")
        elif amount > float(policy.get("transfer_approval_threshold", config.TRANSFER_APPROVAL_THRESHOLD)):
            results.append(
                _result("payment.approval_threshold", "require_approval", f"Amount {amount:.2f} needs approval.")
            )
            reasons.append("Payment amount exceeds the approval threshold.")
            escalate("require_approval")
        else:
            results.append(_result("payment.approval_threshold", "pass", f"Amount {amount:.2f} within limits."))

    # 8. Command execution ----------------------------------------------------
    if action_type == "execute_command":
        command = str(params.get("command", ""))
        if not command.strip():
            results.append(_result("execution.command", "block", "Empty command."))
            escalate("block")
        elif DANGEROUS_COMMAND.search(command):
            results.append(_result("execution.command", "block", "Command matches a destructive pattern."))
            reasons.append("Command contains destructive shell constructs.")
            escalate("block")
        else:
            results.append(
                _result("execution.command", "require_approval", "Shell execution always requires human approval.")
            )
            escalate("require_approval")

    # 9. Approval-required action types --------------------------------------
    if action_type in (policy.get("require_approval_for") or []):
        results.append(_result("policy.requires_approval", "require_approval", f"'{action_type}' requires approval."))
        if decision == "allow":
            reasons.append(f"Policy requires human approval for '{action_type}'.")
        escalate("require_approval")
    else:
        results.append(_result("policy.requires_approval", "pass", "No blanket approval requirement."))

    action_id = new_id("act")
    approval_id: Optional[str] = None
    if decision == "require_human_approval":
        approval_id = new_id("apr")
        get_store().insert(
            "approvals",
            {
                "id": approval_id,
                "action_id": action_id,
                "status": "pending",
                "action_type": action_type,
                "origin": origin,
                "user_role": role,
                "requested_by": user.get("email", "unknown"),
                "source_scan_ids": payload.get("source_scan_ids", []),
                "parameters": _redact(params),
                "intent": intent[:500],
                "reasons": reasons,
                "risk_level": risk_level,
                "created_at": utcnow(),
                "decided_at": None,
                "decided_by": None,
                "decision_note": "",
            },
        )
        audit(user, "firewall.approval_requested", f"{action_type} from {origin}", {"approval_id": approval_id})

    explanation_bits = [f"Action '{action_type}' from origin '{origin}' as role '{role}'."]
    if decision == "allow":
        explanation_bits.append("All firewall rules passed; the action may be dispatched.")
    elif decision == "require_human_approval":
        explanation_bits.append("Held for human approval: " + "; ".join(reasons or ["policy requires approval"]))
    else:
        explanation_bits.append("Denied: " + "; ".join(reasons or ["policy violation"]))

    record = {
        "id": action_id,
        "action_type": action_type,
        "origin": origin,
        "user_role": role,
        "requested_by": user.get("email", "unknown"),
        "source_scan_ids": payload.get("source_scan_ids", []),
        "decision": decision,
        "risk_level": risk_level,
        "reasons": reasons,
        "rule_results": results,
        "approval_id": approval_id,
        "sanitized_parameters": _redact(params),
        "explanation": " ".join(explanation_bits),
        "created_at": utcnow(),
    }
    get_store().insert("firewall_actions", record)
    audit(
        user,
        "firewall.action_evaluated",
        f"{action_type} -> {decision}",
        {"action_id": action_id, "risk_level": risk_level},
    )
    return record


def decide_approval(approval_id: str, approve: bool, user: dict, note: str = "") -> dict:
    """Record a human decision on a pending action."""
    store = get_store()
    approval = store.get("approvals", approval_id)
    if not approval:
        raise KeyError("Approval not found.")
    if approval.get("status") != "pending":
        raise ValueError(f"Approval already {approval.get('status')}.")
    if user.get("role") not in ("admin", "analyst"):
        raise PermissionError("Only admins and analysts can decide approvals.")
    if approve and approval.get("risk_level") == "critical":
        raise PermissionError("Critical-risk actions cannot be approved; they must be redesigned.")

    status = "approved" if approve else "denied"
    updated = store.update(
        "approvals",
        approval_id,
        {
            "status": status,
            "decided_at": utcnow(),
            "decided_by": user.get("email", "unknown"),
            "decision_note": note[:500],
        },
    )
    audit(
        user,
        f"firewall.approval_{status}",
        f"Approval {approval_id} {status}",
        {"action_id": approval.get("action_id"), "note": note[:200]},
    )
    return updated or {}


def list_approvals(status: Optional[str] = None, limit: int = 50) -> list[dict]:
    return get_store().find(
        "approvals",
        (lambda d: d.get("status") == status) if status else None,
        limit=limit,
    )


def list_actions(limit: int = 50) -> list[dict]:
    return get_store().find("firewall_actions", None, limit=limit)
