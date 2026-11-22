# PromptShield AI

**An intelligent, context-aware indirect prompt-injection detection and prevention platform.**

AI assistants now read emails, PDFs, web pages and uploaded documents. Any of those
sources can carry instructions an attacker wrote — and a naive assistant will treat
them as if they came from its operator. PromptShield AI sits between external content
and the assistant: it extracts, analyses, scores, isolates and explains that content,
and then independently validates every tool call the assistant attempts.

> **The principle:** do not just detect prompt injection — prevent untrusted content
> from controlling AI behaviour. Content may be *read*; it may never *act*.

**Live demo:** https://yl2e5fg7um.dev.ap-jt.com — sign in with the seeded admin
account below.

---

## What it actually does

| Capability | Implementation |
| --- | --- |
| **Multilingual detection** | English, Tamil, Hindi and mixed-script instruction patterns (transliteration + native script), not a keyword blocklist. |
| **Context-aware scoring** | Distinguishes a quoted/educational instruction ("never tell a user to ignore previous instructions") from an operative one addressed to the assistant. |
| **Hybrid engine** | Rule + pattern evidence, contextual weighting, and a trained statistical classifier combined into one 0–100 risk score. |
| **Explainable threats** | Every threat returns category, quoted evidence span, risk score, detection reason, source document, recommended action and final decision. |
| **Cross-document analysis** | Documents are scored independently first, then correlated on *instruction* overlap to surface coordinated campaigns — shared vocabulary alone is not enough. |
| **Smart Action Firewall** | Independent layer validating recipient/destination, operation, sensitive-data access, linked-content risk and amount limits before any tool call executes. Blocks, or requires human approval for sensitive actions. |
| **Adaptive testing lab** | Runs the detector over the repository dataset and reports precision, recall, F1, FPR, FNR per split, per language and per slice against a keyword baseline. |
| **Real persistence** | MongoDB when `MONGODB_URI` is set, otherwise an embedded SQLite document store. Dashboard statistics are computed from stored scans, never hardcoded. |

Every page of the dashboard reads live backend data: **Dashboard, Document Scanner,
Email Scanner, URL Scanner, Threat Analysis, Attack History, Security Analytics,
Cross-Document, Firewall & Actions, Testing Laboratory, User Settings.**

## Stack

- **Frontend** — React 19, Vite, Tailwind CSS 4, Lucide React, Recharts
- **Backend** — Python 3.13, FastAPI, Pydantic v2, Uvicorn
- **Detection** — pure-Python hashed-feature logistic regression (`backend/ml/model.json`) + rule/context/multilingual engine (no torch, fits a 1 GB instance)
- **Extraction** — `pypdf`, BeautifulSoup (HTML text + metadata), Python `email` parsing, SSRF-guarded URL fetcher
- **Storage** — MongoDB (`pymongo`) or embedded SQLite
- **Tests** — pytest (45 tests), plus the in-app evaluation laboratory

## Quickstart

### Backend + frontend (development)

```bash
# 1. Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000     # API + docs at http://127.0.0.1:8000/api/docs

# 2. Frontend (second terminal) — proxies /api to :8000
cd frontend
npm install
npm run dev                                    # http://127.0.0.1:5173
```

### Single process (production mode)

```bash
cd frontend && npm run build
cd ../backend
FRONTEND_DIST=../frontend/dist uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The FastAPI process then serves the API under `/api/*` and the built SPA on every
other path, including client-side routes such as `/threats`.

### Docker

```bash
docker build -t promptshield .
docker run -p 8000:8000 promptshield        # non-root, Alpine, multi-stage
```

The image builds the SPA with Node and runs FastAPI with Uvicorn on `$PORT` (8000).

### Seeded accounts

| Role | Email | Password |
| --- | --- | --- |
| Admin | `admin@promptshield.ai` | `Admin@12345` |
| Analyst / Viewer | `GET /api/auth/demo-accounts` | `Demo@12345` |

Override with `SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD`, `SEED_DEMO_PASSWORD`, or set
`SEED_DEMO_USERS=0` to disable demo accounts. **Change the admin password before any
real deployment.** See `.env.example` for every supported variable.

## Tests

```bash
cd backend && python -m pytest -q            # 45 tests: detection, firewall, API, extraction
cd frontend && npm run build                 # production build must succeed
```

### Dependency locking

`backend/requirements.lock` is the fully resolved set (direct + transitive versions)
that the container installs and that dependency scanning can resolve completely;
`frontend/package-lock.json` does the same for npm. Regenerate the Python lock after
changing `requirements.txt`:

```bash
cd backend
python3 -m venv /tmp/lockenv && /tmp/lockenv/bin/pip install -r requirements.txt
/tmp/lockenv/bin/pip freeze | sort > requirements.lock
```

Coverage includes: benign-vs-malicious detection, multilingual and mixed-language
samples, hidden HTML-comment injection, quoted-vs-operative instruction context,
PDF/email/URL extraction, SSRF refusal, RBAC and auth failures, firewall blocking
and approval flows, dashboard statistics, and the evaluation laboratory.

## Dataset and model — honest numbers

The repository ships a small, hand-authored, synthetic dataset
(`backend/ml/dataset.py`, 132 samples: 72 malicious / 60 benign, deterministic
split 98 train / 14 validation / 20 test, fingerprint `53e23a4a26261d73`) and a
pure-Python hashed-feature logistic-regression classifier trained offline by
`backend/ml/train.py` (`python -m ml.train`).

Measured on the held-out test split of that dataset:

| Detector | Accuracy | Precision | Recall | FPR | FNR |
| --- | --- | --- | --- | --- | --- |
| Keyword baseline | 0.95 | 1.00 | 0.917 | 0.00 | 0.083 |
| Trained LR classifier | 0.75 | 0.706 | 1.00 | 0.625 | 0.00 |

Read that honestly: on 20 test samples the simple baseline scored *higher* than the
trained classifier, which traded precision for recall. These numbers describe this
tiny synthetic dataset only — they are **not** a claim about production accuracy,
and the product does not rely on the classifier alone. The shipped detection path
is the hybrid engine (rule + contextual + multilingual + statistical), and the
Testing Laboratory exists so the numbers can be re-measured as the dataset grows.

No adaptive/online learning is claimed: there is no automatic model-update
pipeline. Re-training is a deliberate, offline, reproducible step.

## Security controls

- Every uploaded document is untrusted input: type sniffing, size limits
  (`MAX_UPLOAD_BYTES`), text limits (`MAX_TEXT_CHARS`), no script execution, HTML
  reduced to text.
- URL scanning is SSRF-guarded: only `http`/`https`, private/loopback/link-local
  addresses refused (`ALLOW_PRIVATE_URL_FETCH=0`), bounded redirects, timeout and
  byte cap.
- Authentication (signed bearer tokens, persisted signing key) and role-based
  access (admin / analyst / viewer); admin-only policy and approval actions.
- Per-route rate limiting, audit log of security-relevant actions, sanitised error
  responses (no stack traces to clients).
- Secrets come from the environment only; no API key is ever exposed to the
  frontend bundle.
- The AI stage is optional. Without `LLM_API_KEY` + `LLM_BASE_URL` no content
  leaves the process; when configured, content is passed as an untrusted,
  delimited envelope, never as instructions.
- The firewall is independent of the model: a compromised or manipulated model
  still cannot send mail outside the allowlist or move money past the hard limit.

## Risk scoring

Application-specific heuristic, 0–100: **0–29 low, 30–59 medium, 60–79 high,
80–100 critical**. Decisions: allow as untrusted content, flag for review,
quarantine, block, require human approval. This is not a universal or certified
security standard — it drives this platform's decisions only.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system diagram, module map, data flow, storage schema
- [`docs/API.md`](docs/API.md) — REST reference with examples (live OpenAPI at `/api/docs`)
- [`docs/DEMO.md`](docs/DEMO.md) — five-scenario hackathon walkthrough
- `.env.example` — configuration reference

## Project layout

```
backend/
  app/            FastAPI app: routers, service layer, detection engine, firewall, storage
  ml/             dataset.py (synthetic samples + splits), train.py, model.json (artifact)
  tests/          pytest suite (detection, firewall, API)
frontend/
  src/pages/      11 authenticated pages + login
  src/components/ ScanResult, Layout, ui primitives
docs/             ARCHITECTURE.md, API.md, DEMO.md
Dockerfile        multi-stage: Node SPA build → Python runtime serving API + SPA
```

## Known limitations

- The dataset is small and synthetic; real-world precision/recall will differ.
- The classifier is a lightweight hashed LR model, not a transformer — a deliberate
  choice for a 1 GB / 1 vCPU instance, documented rather than hidden.
- URL scanning fetches public pages only; authenticated or JS-rendered pages are
  out of scope.
- Rate limiting and audit storage are in-process; a multi-replica deployment needs
  a shared store.
- Single-app hosting on the Free plan is 1 GB RAM / 1 vCPU — fine for a prototype
  demo, not a sizing claim for production traffic.
