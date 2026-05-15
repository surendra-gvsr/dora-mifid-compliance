# 🔏 DORA & MiFID II Compliance-as-Code

> An agentic RAG system that maps ICT security controls to EU financial regulations in real time — complete with gap analysis, compliance scoring, and tamper-proof forensic audit trails.

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## What It Does

Financial firms under **DORA** and **MiFID II** must prove their IT security controls meet specific regulatory articles. Manual mapping takes weeks and produces stale Word documents.

This system replaces that process with an AI agent that:

1. **Reasons step-by-step** (ReAct loop) over your ICT controls database
2. **Retrieves regulatory requirements** via an MCP tool registry
3. **Blocks PII in-flight** before it ever reaches the LLM
4. **Produces a signed forensic receipt** for every analysis — auditor-ready

---

## Architecture

```
User Query
    │
    ▼
ComplianceAgent (ReAct Loop, max 6 steps)
    │
    ├── THINK  → LLM produces {thought, action, action_input}
    │
    ├── ACT    → MCPToolRegistry.call_tool(action, **kwargs)
    │               ├── get_dora_article(article_id)
    │               ├── get_mifid_article(article_id)
    │               └── query_controls_db(article_id, type, status)
    │
    ├── GUARD  → PIIGuard.enforce_kill_switch(tool_result, clearance)
    │               ├── ANALYST         → BLOCK if any PII found
    │               ├── COMPLIANCE_OFFICER → anonymise MEDIUM/LOW
    │               └── DPO             → anonymise all levels
    │
    └── OBSERVE → safe result appended to LLM context window

    ▼
ForensicSnapshot (SHA-256 signed, immutable)
    └── Stored in DB → retrievable by snapshot_id
```

### Key Components

| Component | File | Purpose |
|---|---|---|
| **ReAct Agent** | `compliance/compliance_agent.py` | Multi-step Reason+Act orchestration |
| **MCP Registry** | `compliance/mcp_server.py` | Tool registry (MCP protocol pattern) |
| **PII Kill-Switch** | `compliance/pii_guard.py` | In-flight PII detection & enforcement |
| **Forensic Snapshot** | `compliance/forensic.py` | SHA-256 signed audit trail |
| **Regulatory KB** | `compliance/regulatory_kb.py` | DORA + MiFID II article knowledge base |
| **ICT Controls DB** | `compliance/controls_db.py` | 10 mock ICT security controls |
| **REST API** | `compliance/routes.py` | 4 FastAPI endpoints |

---

## ICT Controls Mapped

| ID | Control | DORA | MiFID II | Status |
|---|---|---|---|---|
| ICT-001 | Incident Classification & Reporting | Art.17 | Art.16 | ✅ Implemented |
| ICT-002 | Third-Party ICT Risk Assessment | Art.7 | Art.16 | ⚠️ Partial |
| ICT-003 | ICT Risk Management Framework | Art.5 | Art.16 | ✅ Implemented |
| ICT-004 | ICT Systems Resilience & Availability | Art.6 | — | ⚠️ Partial |
| ICT-005 | Data Protection & Encryption | Art.9 | Art.16 | ✅ Implemented |
| ICT-006 | Business Continuity & DR | Art.11 | Art.16 | ❌ Gap |
| ICT-007 | Network Segmentation & Access Control | Art.9 | Art.16 | ✅ Implemented |
| ICT-008 | Vulnerability Management | Art.6, Art.9 | Art.16 | ⚠️ Partial |
| ICT-009 | ICT Audit Logging & Monitoring | Art.5, Art.17 | Art.16 | ✅ Implemented |
| ICT-010 | Concentration Risk — Critical 3rd Parties | Art.7 | Art.16 | ❌ Gap |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/compliance/analyze` | Run agentic compliance analysis |
| `GET` | `/api/compliance/snapshot/{id}` | Retrieve forensic snapshot |
| `GET` | `/api/compliance/controls` | List ICT controls (filterable) |
| `POST` | `/api/compliance/pii-scan` | Demo PII Kill-Switch |
| `POST` | `/api/auth/register` | Create account |
| `POST` | `/api/auth/login` | Login → JWT token |

Full interactive docs at `/docs` (Swagger UI).

---

## Quick Start

### Prerequisites
- Python 3.11+
- A free [Google Gemini API key](https://aistudio.google.com/app/apikey) *(or set `MOCK_LLM=true` for zero-API demo)*

### Install & Run

```bash
git clone https://github.com/surendra-gvsr/dora-mifid-compliance.git
cd dora-mifid-compliance

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt

cp .env.example .env
# Edit .env: add GEMINI_API_KEY=... (or set MOCK_LLM=true)

uvicorn main:app --reload --port 8000
```

Open **http://localhost:8000** — the dashboard loads instantly.

### Zero-API Demo Mode

Add `MOCK_LLM=true` to `.env` to run the full ReAct loop with pre-scripted responses. No API key, no internet required.

---

## Demo Flow

```bash
# 1. Register
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"user_id":"demo@firm.com","password":"Demo@1234"}'

# 2. Login → copy token
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo@firm.com","password":"Demo@1234"}'

# 3. PII Kill-Switch — try with ANALYST (blocked) and DPO (anonymised)
curl -X POST http://localhost:8000/api/compliance/pii-scan \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"text":"Contact j.smith@firm.com IBAN GB29NWBK60161331926819","clearance_level":"ANALYST"}'

# 4. Full compliance analysis
curl -X POST http://localhost:8000/api/compliance/analyze \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"Map ICT controls to DORA Art.9 and identify gaps","regulation":"DORA","clearance_level":"COMPLIANCE_OFFICER"}'
```

---

## PII Clearance Matrix

| Clearance | HIGH risk (IBAN, account, national ID) | MEDIUM risk (email, phone) | LOW risk (names) |
|---|---|---|---|
| `ANALYST` | 🚫 Blocked | 🚫 Blocked | 🚫 Blocked |
| `COMPLIANCE_OFFICER` | 🚫 Blocked | ✅ Anonymised | ✅ Anonymised |
| `DPO` | ✅ Anonymised | ✅ Anonymised | ✅ Anonymised |

---

## Forensic Snapshot

Every analysis produces an immutable SHA-256 signed record:

```json
{
  "snapshot_id": "a3f2c1d0-...",
  "timestamp": "2026-01-15T10:30:00Z",
  "query": "Map ICT controls to DORA Art.9",
  "compliance_score": 72.5,
  "matched_controls": [...],
  "gap_analysis": [...],
  "agent_steps": [...],
  "auditor_signature": "e3b0c44298fc1c149af...",
  "integrity_verified": true
}
```

Tampering with any field breaks the signature → `integrity_verified: false`.

---

## Tech Stack

- **FastAPI** — async REST API
- **SQLAlchemy** — ORM (SQLite for dev, PostgreSQL for prod)
- **PyJWT** — authentication
- **MCP pattern** — in-process tool registry (no extra server)
- **Regex + heuristic NER** — PII detection (stdlib only, no heavy NLP deps)
- **hashlib SHA-256** — forensic signing

---

## Deployment

Configured for [Vercel](https://vercel.com) via `vercel.json`.

```bash
vercel --prod
```

Set these environment variables in Vercel dashboard:
- `GEMINI_API_KEY` (or `XAI_API_KEY` / `OPENAI_API_KEY`)
- `LLM_PROVIDER` = `GEMINI`
- `JWT_SECRET` = (random string)
- `PASSWORD_SALT` = (random string)
- `MOCK_LLM` = `true` (for demo deployment without LLM costs)

---

## Regulations Covered

**DORA** (EU 2022/2554) — Digital Operational Resilience Act  
Articles: 5, 6, 7, 9, 11, 17

**MiFID II** (2014/65/EU) — Markets in Financial Instruments Directive  
Article: 16 (Organisational Requirements)

---

## License

MIT — see [LICENSE](LICENSE)
