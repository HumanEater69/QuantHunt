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

## Deploy Backend To Microsoft Azure (App Service)

Use Azure App Service (Linux, Python 3.11) for the backend.

```powershell
az group create --name rg-quanthunt --location centralindia
az appservice plan create --name asp-quanthunt --resource-group rg-quanthunt --sku B1 --is-linux
az webapp create --name quanthunt-backend --resource-group rg-quanthunt --plan asp-quanthunt --runtime "PYTHON|3.11"
az webapp config set --name quanthunt-backend --resource-group rg-quanthunt --startup-file "uvicorn backend.main:app --host 0.0.0.0 --port 8000"
az webapp config appsettings set --name quanthunt-backend --resource-group rg-quanthunt --settings SCM_DO_BUILD_DURING_DEPLOYMENT=true CORS_ALLOW_ORIGINS=https://quanthunt.netlify.app
az webapp up --name quanthunt-backend --resource-group rg-quanthunt --runtime "PYTHON|3.11"
```

After deploy, this repo's `netlify.toml` already routes `/api/*` to:

- `${API_ORIGIN}/api/:splat`

Set `API_ORIGIN` in Netlify (Site settings -> Environment variables), for example:

- `API_ORIGIN=https://quanthunt-backend.azurewebsites.net`

### Azure Production Environment Template

Use `.env.azure.production.template` as the baseline for Azure App Service application settings.
It includes recommended scan tuning defaults for deep and shallow scans.

## Auto Apply Changes To Live Domain

This repo now includes GitHub Actions live deployment workflow:

- `.github/workflows/live-deploy.yml`

It auto-deploys on every push to `master` or `main`:

- Frontend -> Netlify production
- Backend -> Azure Web App

### One-time GitHub Secrets Setup

Add these repository secrets in GitHub -> Settings -> Secrets and variables -> Actions:

- `NETLIFY_AUTH_TOKEN`
- `NETLIFY_SITE_ID`
- `API_ORIGIN` (example: `https://quanthunt-backend.azurewebsites.net`)
- `AZURE_WEBAPP_NAME` (example: `quanthunt-backend`)
- `AZURE_WEBAPP_PUBLISH_PROFILE` (download from Azure Web App -> Get publish profile)

After secrets are set, every push updates the live website automatically.

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
