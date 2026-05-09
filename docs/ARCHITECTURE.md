# QuantHunt — Architecture Summary

This document maps the core modules, API surface, data flows, and where algorithms live.

Overview
- Backend: `backend/` — FastAPI app (`backend/main.py`) exposing REST endpoints, mounting frontend at `/static`.
- Frontend: `frontend/app.jsx`, `frontend/config.js` — React single-file app calling the backend API.
- Scanner: `backend/scanner/` — modular scanning engine (discovery, TLS inspector, PQC scoring, pipeline orchestration).
- Quick engine: `backend/quanthunt_engine.py` — pure-algorithmic asyncio engine (standalone). Exposed at `POST /api/scan/quick-engine`.

Key flows
- Create scan: Frontend `POST /api/scan` -> `backend/main.py:create_scan()` -> creates DB scan row and dispatches pipeline via Celery or thread -> `backend/scanner.pipeline.run_scan_pipeline`.
- Poll results: Frontend `GET /api/scan/{id}` and related endpoints -> `backend/main.py` routes -> DB-backed payloads prepared by `backend/crud.py`.
- Quick engine: Frontend or operator can call `POST /api/scan/quick-engine` with a `ScanRequest` body to run `run_quanthunt_scan()` directly and return the engine JSON.

Important modules
- `backend/scanner/asset_discovery.py` — discovery & brute-force
- `backend/scanner/tls_inspector.py` — TLS handshake parsing, SAN/cipher extraction
- `backend/scanner/pqc_engine.py` — HNDL/PQC scoring
- `backend/scanner/pipeline.py` — orchestration, retries, backoff
- `backend/quanthunt_engine.py` — new pure-engine: orchestrator, crawler, mutator, resolver, TLS prober
- `backend/main.py` — FastAPI routes and dispatch logic
- `backend/crud.py` + `backend/db.py` — persistence & payload formatting

Notes & recommendations
- The quick-engine endpoint intentionally returns the engine output directly and does not persist to the DB. Use it for validation, comparisons, or as a fallback/testing tool.
- For production, prefer Postgres over SQLite when using Celery or multiple worker processes.
- Ensure `requirements.txt` includes `aiohttp`, `aiodns`, and `cryptography` if the engine is used in production.

Contact
For changes that alter scanning behavior or DB schema, update `backend/ARCHITECTURE.md` and run the test suite.
