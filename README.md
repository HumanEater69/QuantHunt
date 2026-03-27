# QuantumShield MVP

FastAPI + scanner engine + glass/clay neon dashboard for HNDL-focused PQC posture assessment.

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
- Frontend deployment on Vercel (GitHub Actions)

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

### Database (Neon)

Backend DB URLs are configured from environment variables in this order:

- `DATABASE_URL` (preferred)
- `BANKING_DATABASE_URL` (optional override for banking model)
- `NEON_DATABASE_URL` (shared fallback for both models)

Set a Neon Postgres connection string in `NEON_DATABASE_URL` (or `DATABASE_URL`).

If you are using Neon REST API separately, keep it in your own env var (for example `NEON_REST_API_URL`) and API key env var in your backend host.

Example Neon REST endpoint provided:

- `https://ep-withered-feather-a8q01x6f.apirest.eastus2.azure.neon.tech/neondb/rest/v1`

### Frontend (Vercel)

Frontend workflow:

- `.github/workflows/frontend-vercel.yml`

Required GitHub secrets:

- `VERCEL_TOKEN`
- `VERCEL_ORG_ID`
- `VERCEL_PROJECT_ID`

Set them from your local machine after linking the Vercel project:

```powershell
vercel link frontend
Get-Content frontend\.vercel\project.json
# Copy orgId and projectId values, then set secrets:
"<vercel-token>" | gh secret set VERCEL_TOKEN
"<vercel-org-id>" | gh secret set VERCEL_ORG_ID
"<vercel-project-id>" | gh secret set VERCEL_PROJECT_ID
```

Frontend API calls use `/api/*`, and `frontend/vercel.json` rewrites those requests to your backend host.

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
