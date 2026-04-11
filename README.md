# QuantumShield MVP

FastAPI + scanner engine + glass/clay dashboard for HNDL-focused PQC posture assessment.

## What Was Updated (April 2026)

This repository now includes a production-grade asset discovery and TLS probing refresh focused on coverage and scoring transparency:

- Deep asset discovery pipeline with CT scraping + async DNS brute-force and deduplication.
- Multi-resolver discovery support (system resolvers + custom resolvers + optional union behavior).
- Granular TLS probing with enforced SNI in handshake path.
- Adaptive retry strategy for unknown TLS assets:
  - pass 1: timeout ~4.5s, concurrency 50
  - pass 2 (unknown only): longer timeout, lower concurrency, backoff/jitter
- Service-aware reachability checks beyond 443:
  - 25, 465, 587, 993, 995, 8443, 9443
  - assets can now be classified as service-reachable even when 443 TLS profile is unavailable
- Report bucket model for transparent scoring:
  - `passive_discovered` (CT/passive inventory, including dead)
  - `live_dns` (resolvable/live DNS)
  - `live_tls_measured` (TLS profile fully captured)
- Frontend scan summary cards now surface these three buckets plus a non-443 service-reachable badge so judges can immediately distinguish discovery coverage from TLS measurement coverage.

### Wordlist Seeding Helpers

To improve discovery recall for enterprise/private naming patterns, two helper scripts are included:

- `scripts/seed_wordlists_from_db_catalog.py`
  - seeds tokens from private SQLite host catalogs into scanner wordlists.
- `scripts/import_inventory_to_wordlists.py`
  - imports host tokens from JSON/CSV/TXT inventories and appends missing labels.

Target-specific and parent-domain lists are under `backend/scanner/wordlists/`.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Open: `http://localhost:8000`

## Deployment

This repo is configured for:

- Backend deployment via generic deploy hook (GitHub Actions)

### Current Deployment Workflow

- `.github/workflows/backend-deploy.yml`

The workflow enforces backend regression tests (`tests.test_offline_and_scoring`) before deployment.

### Backend

Backend workflow triggers your provider deploy hook and probes health on:

- `${BACKEND_ORIGIN}/api/scans`

Optional keepalive workflow:

- `.github/workflows/backend-keepalive.yml` (scheduled ping every 10 minutes)

Required GitHub secrets for backend workflow:

- `BACKEND_DEPLOY_HOOK_URL`
- `BACKEND_ORIGIN`

### One-time GitHub Secrets Setup (Backend)

Configure backend deployment secrets:

```powershell
"<backend-deploy-hook-url>" | gh secret set BACKEND_DEPLOY_HOOK_URL
"https://<your-backend-host>" | gh secret set BACKEND_ORIGIN
```

### Database

Backend DB URLs are configured from environment variables:

- `DATABASE_URL` (general model)
- `BANKING_DATABASE_URL` (banking model, optional override)

MongoDB mirror (optional, recommended for cloud backup/history):

- `MONGODB_URI` (Atlas/cluster connection string)
- `MONGODB_DB` (default: `quanthunt`)
- `MONGODB_COLLECTION` (default: `scan_snapshots`)

When MongoDB is enabled, completed scans are mirrored into Mongo while SQLite remains the primary runtime store.
Check status at:

- `GET /api/persistence-status`

If not set, the app falls back to local SQLite files for both models.

## Frontend to Hosted Backend (Vercel)

The frontend supports runtime API base configuration via `frontend/config.js`:

```js
window.QUANTHUNT_CONFIG = Object.freeze({ API_BASE: "https://<your-backend-origin>" });
```

For your Vercel frontend (`https://quanthunt-seven.vercel.app/`), set `API_BASE` to the deployed backend origin.

Notes:

- Keep backend CORS strict using `CORS_ALLOW_ORIGINS`, including your Vercel origin.
- If `API_BASE` is empty, frontend falls back to same-origin/local behavior.

## Deep Clean Smoke Test (One Command)

Runs a clean temporary server process and executes scripted end-to-end checks for:
- standalone scan completion
- fleet scan completion
- network/VPN status endpoint

```powershell
scripts\deep-clean.cmd
```

Optional flags:

```powershell
scripts\deep-clean.cmd --scan-timeout 300 --port 8014
```

## Optional Production Mode (Celery + Redis)

```powershell
$env:USE_CELERY="true"
$env:REDIS_URL="redis://localhost:6379/0"
celery -A backend.tasks worker --loglevel=info
uvicorn backend.main:app --reload --port 8000
```

## Optional Claude Integration

```powershell
$env:ANTHROPIC_API_KEY="your_key"
$env:ANTHROPIC_MODEL="claude-3-5-sonnet-latest"
```

If `ANTHROPIC_API_KEY` is not set, deterministic fallback recommendations are used.

## Optional QuantHunt (OpenAI)

```powershell
$env:OPENAI_API_KEY="your_openai_api_key"
$env:OPENAI_MODEL="gpt-4.1-mini"
```

QuantHunt endpoint: `POST /api/quanthunt/chat`

## Included Features

- Asset discovery via `crt.sh` + DNS brute-force
- TLS handshake inspection (version/cipher/certificate metadata)
- API endpoint checks (common ports, JWT alg parsing, security headers)
- PQC/HNDL score engine with weighted formula
- CycloneDX 1.6 style CBOM export
- SQL-backed persistence tables: scans, assets, crypto_findings, recommendations, cbom_exports
- Optional Celery + Redis queue execution
- Server-side PDF report export (`/api/scan/{scan_id}/report.pdf`)
- Optional Claude-generated recommendations
- QuantHunt chat assistant tab powered by OpenAI API key (server-side)
- Chart.js radar and leaderboard visuals
- Dashboard tabs: Scanner, Asset Map, Crypto Analysis, CBOM, Roadmap, Docs
