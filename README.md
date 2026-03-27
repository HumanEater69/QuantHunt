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

## Deployment (Railway Backend)

This repo is configured for Railway backend deployment using GitHub Actions.

- Backend deploy target: Railway service via native trigger/fallback deploy hook

### Current Deployment Workflow

- `.github/workflows/backend-deploy.yml`

The workflow enforces backend regression tests (`tests.test_offline_and_scoring`) before deployment.

### Backend

Backend workflow triggers a provider deploy hook and probes health on:

- `${BACKEND_ORIGIN}/api/scans`

Optional keepalive workflow:

- `.github/workflows/backend-keepalive.yml` (scheduled ping every 10 minutes)

Required GitHub secrets for backend workflow:

- `BACKEND_DEPLOY_HOOK_URL`
- `BACKEND_ORIGIN`

Recommended backend target for current FastAPI codebase:

- Railway FastAPI service: `https://quanthunt-fullstack-production.up.railway.app`

### One-time GitHub Secrets Setup (Backend)

Configure backend deployment secrets:

```powershell
"<backend-deploy-hook-url>" | gh secret set BACKEND_DEPLOY_HOOK_URL
"https://quanthunt-fullstack-production.up.railway.app" | gh secret set BACKEND_ORIGIN
```

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
