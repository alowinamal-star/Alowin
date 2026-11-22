"""Firewall endpoints: action validation, approvals, policy, audit trail."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import auth, db, firewall, service
from ..models import ApprovalRequest, FirewallActionRequest

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


@router.post("/validate-action")
def validate_action(
    payload: FirewallActionRequest, user: dict = Depends(auth.require("firewall"))
) -> dict:
    """Independently validate a proposed AI tool call before execution.

    The caller's claimed role in the payload is advisory only: the firewall
    evaluates the action against the *authenticated* user's role.
    """
    request_payload = payload.model_dump()
    source_scans = [scan for scan in (service.get_scan(i) for i in payload.source_scan_ids) if scan]
    decision = firewall.validate_action(request_payload, user, source_scans)
    db.audit(
        user,
        "firewall.evaluated",
        f"{payload.action_type} from {payload.origin} -> {decision.get('decision')}",
        {"action_id": decision.get("action_id"), "risk_level": decision.get("risk_level")},
    )
    return decision


@router.get("/actions")
def list_actions(limit: int = Query(50, ge=1, le=200), user: dict = Depends(auth.require("read"))) -> dict:
    return {"actions": service.list_actions(limit=limit)}


@router.get("/approvals")
def list_approvals(
    approval_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(auth.require("read")),
) -> dict:
    return {"approvals": service.list_approvals(status=approval_status, limit=limit)}


@router.post("/approvals/{approval_id}/decision")
def decide_approval(
    approval_id: str, payload: ApprovalRequest, user: dict = Depends(auth.require("approve"))
) -> dict:
    """Approve or reject a pending high-risk action. Requires the ``approve`` capability."""
    approval = service.get_approval(approval_id)
    if not approval:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval request not found.")
    if approval.get("status") != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Approval already {approval.get('status')}.")
    if approval.get("requested_by") == user.get("email") and user.get("role") != "admin":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Four-eyes control: the requester cannot approve their own action.",
        )
    result = service.decide_approval(approval_id, payload.decision, user, payload.note)
    db.audit(
        user,
        "firewall.approval_decision",
        f"{payload.decision} for action {approval.get('action_id')}",
        {"approval_id": approval_id, "note": payload.note},
    )
    return result


@router.get("/policy")
def get_policy(user: dict = Depends(auth.require("read"))) -> dict:
    return firewall.load_policy()


@router.put("/policy")
def update_policy(updates: dict, user: dict = Depends(auth.require("settings"))) -> dict:
    policy = firewall.save_policy(updates, user)
    db.audit(user, "firewall.policy_updated", "Firewall policy updated", {"keys": sorted(updates.keys())})
    return policy
