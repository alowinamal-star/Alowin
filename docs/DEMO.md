# Hackathon demonstration workflow — PromptShield AI

Five scenarios, in the order that tells the story best. Everything below runs on
real backend detection; nothing is scripted in the UI. The demo database is
seeded with example scans (`SEED_DEMO_SCANS=1`) so charts are populated on first
load, and the **Testing Laboratory** produces its own fresh evaluation runs.

Sign in at `/login`. Seeded accounts (override with `SEED_ADMIN_*` / `SEED_DEMO_*`):

| Role     | Email                     | Password      |
| -------- | ------------------------- | ------------- |
| Admin    | `admin@promptshield.ai`   | `Admin@12345` |
| Analyst  | see `GET /api/auth/demo-accounts` | `Demo@12345` |
| Viewer   | see `GET /api/auth/demo-accounts` | `Demo@12345` |

---

## Scenario A — Safe PDF / document (allow as untrusted content)

1. Go to **Document Scanner** → *Paste* tab → open **Demo samples** → pick
   `q3-operations-review.txt` (or upload your own business report as PDF/TXT/HTML).
2. Click **Scan**.

Expected: risk lands in the **Low** band (0–29), decision **Allow as untrusted
content**, no evidence spans, and the untrusted-envelope preview shows the text
fenced off from system instructions. The dashboard's *Safe documents* counter
increments.

Talking point: a benign document is still never *trusted* — it is delivered to
the AI stage as delimited data.

## Scenario B — Malicious email (detect, isolate, block)

1. Go to **Email Scanner**, use sample `invoice-reminder.eml` (an email that
   tells the assistant to ignore its rules and send confidential data out).
2. Click **Scan**, then open the result in **Threat Analysis**.

Expected: **Critical** risk, decision **Block**, evidence spans listing
*Instruction addressed to the AI*, *Data exfiltration*, *Instruction override*,
plus a recommended action and the source document name. In
**Firewall & Actions**, simulate the follow-on tool call (send email to an
external domain) — the firewall denies it independently of the model.

## Scenario C — Multilingual attack (Tamil / mixed)

1. **Document Scanner** → sample `vendor-note-ta.txt` (Tamil instruction), or
   paste your own mixed English + Tamil instruction.
2. Scan, then check **Security Analytics** → *Language coverage* shows `Ta` and
   `Mixed` counts.

Expected: **High** risk, **Quarantine**, with the suspicious Tamil span quoted
back in the evidence list. Talking point: detection is not a keyword list — the
engine combines multilingual instruction patterns, imperative/context signals
and a statistical classifier.

## Scenario D — Cross-document attack

1. Open **Cross-Document**, select the two campaign samples
   (`campaign-invoice-01.txt`, `campaign-vendor-02.txt`) or upload several
   documents at once.
2. Click **Analyse documents**.

Expected: each document is scored independently first, then the correlation
pass reports a shared instruction family / coordinated intent and raises the
review recommendation. Documents that merely share vocabulary are **not**
auto-flagged — the correlation requires overlapping *instruction* signals.

## Scenario E — Unsafe tool call (firewall denies)

1. Go to **Firewall & Actions** → *Validate an AI tool call*.
2. Choose `send_email` with a recipient outside the allowlist and body text
   containing confidential material (or pick `transfer_funds` above the hard
   limit).

Expected: decision **Block** with per-check results (recipient policy, sensitive
data, linked-content risk, amount limits). A sensitive-but-allowed action
returns **Require human approval** and appears in the approvals queue, where an
admin can approve or reject it — recorded in the audit log.

3. Then try `transfer_funds` between the approval threshold and the hard limit:
   the action is **held for approval**, proving the firewall does not simply
   allow-or-deny.

---

## Scenario F (optional) — Adaptive Testing Laboratory

**Testing Laboratory** → **Run evaluation**. The run executes the detector over
the repository dataset and reports precision, recall, F1, false-positive rate
and false-negative rate per split, compared against the keyword baseline, with
per-language and per-slice breakdowns. Runs are stored and listed with their
dataset fingerprint.

Be honest here: the dataset is small and hand-authored, so the reported numbers
describe that dataset only — see README "Evaluation honesty".

---

## Closing line

External content → extraction → contextual detection → risk scoring →
isolation/decision → AI processing as untrusted data → independent action
validation → monitoring. The product's core claim is the last step: content can
be *read*, but it can never *act*.
