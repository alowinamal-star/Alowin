"""First-boot demo seeding.

Every seeded record is produced by the real pipeline (extraction → detection →
scoring → decision → firewall). Nothing here hardcodes a result: the dashboard
numbers are simply the outcome of scanning the bundled sample documents.
"""
from __future__ import annotations

import logging

from . import auth, config, db, extract, firewall, samples, service
from .security.classifier import analyze_text

log = logging.getLogger("promptshield.seed")


def seed_demo_scans() -> None:
    if not config.SEED_DEMO_SCANS:
        return
    store = db.get_store()
    if store.count("scans") > 0:
        return

    admin = auth.find_user_by_email(config.SEED_ADMIN_EMAIL) or {
        "id": "system",
        "email": "system@promptshield.ai",
        "role": "admin",
    }
    analyst = auth.find_user_by_email("analyst@promptshield.ai") or admin

    created: list[dict] = []
    for sample in samples.SAMPLES:
        extraction = None
        text = sample["content"]
        hidden: list[str] = []
        if sample["kind"] in {"html", "email"}:
            try:
                extraction = extract.extract_bytes(sample["source_name"], sample["content"].encode("utf-8"))
                text = extraction["text"]
                hidden = extraction.get("hidden_segments", [])
            except extract.ExtractionError:
                log.warning("Sample %s could not be extracted; using raw text", sample["id"])

        scan_id = db.new_id("scan")
        analysis = analyze_text(
            text,
            source_name=sample["source_name"],
            source_type=sample["kind"],
            scan_id=scan_id,
            extra_signals={"hidden_segments": hidden},
            metadata={"scenario": sample["scenario"], "demo": True, "sample_id": sample["id"]},
        )
        analysis["scan_id"] = scan_id
        created.append(service.record_scan(analysis, admin, extraction))

    # Demonstrate the firewall on real decisions derived from the seeded scans.
    email_scan = next((s for s in created if s["source_type"] == "email"), None)
    if email_scan:
        firewall.validate_action(
            {
                "action_type": "send_email",
                "origin": "external_content",
                "user_role": "analyst",
                "source_scan_ids": [email_scan["id"]],
                "parameters": {
                    "to": "exfil-collector@external-collect.example",
                    "subject": "Confidential export",
                    "body": "Customer database export requested by the email.",
                    "data_classification": "confidential",
                },
                "intent": "Exfiltrate customer data to an external address named in the document.",
            },
            admin,
            [email_scan],
        )

    # A legitimate-but-sensitive action that must be held for human approval.
    firewall.validate_action(
        {
            "action_type": "send_email",
            "origin": "user",
            "user_role": "analyst",
            "source_scan_ids": [],
            "parameters": {
                "to": "client-contact@partner-org.example",
                "subject": "Quarterly pricing summary",
                "body": "Pricing summary as requested by the account manager.",
                "data_classification": "confidential",
            },
            "intent": "Send the approved pricing summary to the customer contact.",
        },
        analyst,
        [],
    )

    log.info("Seeded %d demonstration scans and 2 firewall evaluations", len(created))
