# QuantHunt Deployment: Vercel + Render + Supabase

## Target Layout

- Vercel serves the static QuantHunt frontend from `frontend/`.
- Render runs the FastAPI backend with long-lived scan execution.
- Supabase PostgreSQL stores scan state, findings, assets, logs, CBOMs, and chain blocks through SQLAlchemy.
- Optional: Render worker `backend.supabase_worker` consumes `scan_jobs` rows for a pure Supabase queue flow.

## Supabase

1. Create a Supabase project.
2. Copy the Postgres connection string from Project Settings -> Database.
3. Use the pooler URL on Render, with `sslmode=require`.
4. If you want the optional queue worker, run `supabase/schema.sql` in the Supabase SQL editor.

The FastAPI service creates the core QuantHunt SQLAlchemy tables on startup. The `supabase/schema.sql` file is only for the optional `scan_jobs` table worker.

## Render API

Create the service from `render.yaml` or manually:

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

Set these Render environment variables:

```bash
DATABASE_URL=postgresql://...supabase.../postgres?sslmode=require
BANKING_DATABASE_URL=postgresql://...supabase.../postgres?sslmode=require
CORS_ALLOW_ORIGINS=https://YOUR-VERCEL-APP.vercel.app,http://localhost:5177,http://127.0.0.1:5177
USE_CELERY=false
SINGLE_FORCE_RUNNING_ON_SUBMIT=true
FLEET_FORCE_RUNNING_ON_SUBMIT=true
FLEET_FORCE_ASYNCIO_DISPATCH=true
VPN_ENFORCE_BLOCK=false
```

After deploy, verify:

```bash
curl https://YOUR-RENDER-SERVICE.onrender.com/health
```

Expected:

```json
{"status":"ok","backend":"connected"}
```

## Optional Render Worker

Use this only if you want Supabase table rows to trigger scans independently of the FastAPI `/api/scan` endpoint.

- Start command: `python -m backend.supabase_worker`

Required env:

```bash
SUPABASE_URL=https://YOUR_PROJECT_REF.supabase.co
SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY
QUANTHUNT_WORKER_POLL_SECONDS=8
```

Insert a job:

```sql
insert into public.scan_jobs (target_domain) values ('example.com');
```

The worker claims the row, sets `status='running'`, writes JSON into `results`, then sets `status='completed'`.

## Vercel Frontend

Recommended Vercel project settings:

- Root directory: `frontend`
- Framework preset: Other
- Build command: leave empty
- Output directory: `.`

Update `frontend/vercel.json` before deploy.

Replace:

Replace `https://YOUR-RENDER-SERVICE.onrender.com` with your real Render backend URL.

The frontend can call the backend in two ways:

- Same-origin `/api/*` through the Vercel rewrite in `frontend/vercel.json`
- Or directly via `window.QUANTHUNT_CONFIG.API_BASE` in `frontend/config.js` if you intentionally set it to the Render URL

## Strict Separation

- Vercel never runs Python scan code.
- Render owns `backend.main:app` and optional `backend.supabase_worker`.
- Supabase stores durable state.
- The browser polls Render/Supabase-backed state and receives completed scan results after the worker/API finishes.
