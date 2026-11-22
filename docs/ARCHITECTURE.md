# System architecture — PromptShield AI

## 1. End-to-end pipeline

```
                        ┌──────────────────────────────────────────────┐
                        │  Browser (React 19 + Vite + Tailwind)        │
                        │  login · scanners · threats · firewall · lab │
                        └───────────────┬──────────────────────────────┘
                                        │ HTTPS, Bearer token
                                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ FastAPI process (Uvicorn, one port)                                       │
│                                                                           │
│  routers/          auth · scan · firewall · dashboard · testing · system   │
│      │                                                                    │
│      ▼                                                                    │
│  service.py  ── orchestration, RBAC checks, audit records                 │
│      │                                                                    │
│      ├──► extract.py   bytes/URL → text + metadata                        │
│      │      PDF (pypdf) · HTML (BeautifulSoup) · RFC822 (email) · URL      │
│      │      SSRF guard: scheme, DNS resolution, private-IP refusal        │
│      │                                                                    │
│      ├──► security/engine.py  hybrid detection                            │
│      │      ├── rules.py          instruction-override / exfiltration /   │
│      │      │                     policy-bypass / tool-abuse patterns     │
│      │      ├── multilingual.py   English · Tamil · Hindi · mixed script  │
│      │      ├── context.py        quoted-vs-operative, addressee, intent  │
│      │      ├── ml.py             hashed-feature LR (ml/model.json)       │
│      │      └── risk.py           weighted score 0-100 → band + decision  │
│      │                                                                    │
│      ├──► crossdoc.py  independent scores → instruction-overlap correlation│
│      ├──► firewall.py  independent tool-call validation + approvals       │
│      ├──► ai.py        untrusted envelope → optional external LLM         │
│      └──► db.py        MongoStore (MONGODB_URI) | SqliteStore (default)   │
└───────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
                    MongoDB (when configured) or embedded SQLite
```

The SPA is served by the same process: `main.py` mounts `/assets` and falls back to
`index.html` for client routes, so production is a single container and a single port.

## 2. Content flow (the security contract)

1. **Ingest** — upload / paste / email / URL. Type sniffing plus hard limits on bytes
   and characters. Uploaded content is never executed.
2. **Extract** — text plus metadata (PDF info, HTML title/links, email headers), with
   source name preserved and document boundaries kept.
3. **Detect** — rule evidence spans, multilingual patterns, contextual weighting and
   the statistical classifier are combined; each contributes an explainable reason.
4. **Score** — weighted 0–100 heuristic → band (low/medium/high/critical) and a
   decision (allow as untrusted content · flag for review · quarantine · block ·
   require human approval).
5. **Isolate** — quarantined/blocked content is stored with its evidence but is not
   forwarded to the AI stage.
6. **AI stage** — permitted content is wrapped in an explicit untrusted envelope with
   a boundary the model is told to treat as data, never as instructions. Without
   `LLM_API_KEY`/`LLM_BASE_URL` no content leaves the process.
7. **Tool-call validation** — `firewall.py` re-checks the *action* independently:
   recipient/destination allowlist, sensitive-data access, linked-content risk,
   operation risk, amount thresholds. Model output is not trusted.
8. **Monitor** — every scan, decision, firewall verdict and approval is persisted and
   surfaced on the dashboard, history and audit views.

## 3. Module map

| Path | Responsibility |
| --- | --- |
| `backend/app/main.py` | App factory, lifespan (schema + user seeding + demo scans), SPA serving |
| `backend/app/config.py` | Env-driven settings; single source of truth for limits and paths |
| `backend/app/models.py` | Pydantic request/response contracts (validation, literal enums) |
| `backend/app/auth.py` | Password hashing, signed bearer tokens, role checks, seeded users |
| `backend/app/routers/*.py` | Thin HTTP layer: validation, status codes, RBAC dependencies |
| `backend/app/service.py` | Orchestration of scan → detect → store → dashboard aggregation |
| `backend/app/extract.py` | PDF/HTML/email/URL extraction and the SSRF guard |
| `backend/app/security/*` | Detection engine: rules, multilingual, context, ML, risk, cross-doc |
| `backend/app/firewall.py` | Independent action validation, approval queue, policy |
| `backend/app/ai.py` | Untrusted-envelope construction + optional external model call |
| `backend/app/db.py` | Storage abstraction: `MongoStore` / `SqliteStore`, collections, indexes |
| `backend/ml/dataset.py` | Hand-authored samples, deterministic splits, fingerprint |
| `backend/ml/train.py` | Offline training → `model.json` (reproducible, no auto-update) |

## 4. Data model (collections)

- **users** — id, name, email, password hash, role (`admin`/`analyst`/`viewer`), timestamps
- **scans** — id, user, source name/kind, extracted text, language signals, risk score,
  band, decision, evidence spans, engine contributions, untrusted envelope, created_at
- **threats** — derived view over scans that carry malicious decisions, with status
  (open / reviewed / dismissed) and reviewer notes
- **firewall_actions** — requested tool call, per-check results, verdict, linked scan ids
- **approvals** — action id, reason, status (pending/approved/rejected), decider, note
- **cross_document_runs** — scan ids, per-document verdicts, correlation findings
- **test_runs** — split metrics, baseline comparison, slice breakdown, dataset fingerprint
- **audit_log** — actor, action, target, outcome, timestamp
- **settings** — firewall policy document and the persisted token signing key

SQLite uses one document table with JSON payloads and indexed columns; MongoDB uses the
same shape as native collections. `db.get_store()` picks the backend at startup.

## 5. Trust boundaries

| Boundary | Control |
| --- | --- |
| Browser → API | Bearer token, CORS allowlist, per-route rate limits, RBAC |
| Uploaded file → parser | Type/size limits, no execution, text-only extraction |
| URL → network | http/https only, public-IP enforcement, redirect/timeout/byte caps |
| Content → AI stage | Untrusted envelope; content cannot grant itself permissions |
| AI output → tools | Independent firewall verdict; human approval for sensitive actions |
| API → storage | Parameterised queries / typed documents; secrets from env only |

## 6. Design decisions and their trade-offs

- **Hashed-feature logistic regression instead of a transformer** — keeps the image
  within a 1 GB / 1 vCPU instance and makes training reproducible offline. Trade-off:
  weaker generalisation, so the classifier is one signal among several rather than the
  sole decision-maker.
- **Hybrid rule + context engine as the primary path** — explainable evidence for every
  verdict; trade-off: patterns need maintenance as attack styles evolve.
- **SQLite fallback** — the prototype runs with zero external services; production
  should set `MONGODB_URI`.
- **Single process serving API + SPA** — one container, one port, no CORS in production.
