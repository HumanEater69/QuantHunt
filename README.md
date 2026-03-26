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

## Deployment Revamp (Netlify + Backend Hook)

This repo is now configured for Netlify frontend deployment and a free backend host via deploy hook.

- Frontend deploy target: Netlify (`https://quanthunt.netlify.app`)
- Backend deploy target: provider deploy hook

### Current Deployment Workflows

- `.github/workflows/frontend-netlify.yml`
- `.github/workflows/backend-deploy.yml`

Both workflows enforce backend regression tests (`tests.test_offline_and_scoring`) before deployment.

### Frontend (Netlify)

The frontend is deployed from the `frontend/` directory using Netlify CLI.

Required GitHub secrets for frontend workflow:

- `NETLIFY_AUTH_TOKEN`
- `NETLIFY_SITE_ID`
- `NETLIFY_SITE_URL`

### Backend (Free Candidate)

Backend workflow triggers a provider deploy hook and probes health on:

- `${BACKEND_ORIGIN}/api/scans`

Optional keepalive workflow:

- `.github/workflows/backend-keepalive.yml` (scheduled ping every 10 minutes)

Required GitHub secrets for backend workflow:

- `BACKEND_DEPLOY_HOOK_URL`
- `BACKEND_ORIGIN`

Recommended backend candidate for current FastAPI codebase:

- Any free host with deploy webhook support (for example Netlify build hook, Koyeb, Render)

Decision for this repo:

- Use Netlify for frontend/custom domain delivery
- Use backend deploy hook + `BACKEND_ORIGIN` probe to keep the backend platform interchangeable

### One-time GitHub Secrets Setup

You can configure required secrets in one command:

```powershell
scripts\setup_github_secrets_netlify_backend.ps1 \
	-Repo "HumanEater69/QuantHunt" \
	-NetlifyAuthToken "<netlify-auth-token>" \
	-NetlifySiteId "<netlify-site-id>" \
	-NetlifySiteUrl "https://quanthunt.netlify.app" \
	-BackendDeployHookUrl "<backend-deploy-hook-url>" \
	-BackendOrigin "https://quanthunt.netlify.app"
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
