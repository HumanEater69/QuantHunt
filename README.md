# QuantHunt🛡️

**Post-Quantum Cryptography (PQC) Posture Assessment Platform**

A production-grade FastAPI + React dashboard for enterprise-scale cryptographic readiness auditing with advanced asset discovery, TLS fingerprinting, and HNDL (Harvest Now, Decrypt Later) risk scoring.

---

## 📋 Overview

QuantHunt is a comprehensive security platform designed to assess organizational readiness for quantum-safe cryptography adoption. It combines deep asset discovery, TLS inspection, and AI-driven recommendations to identify cryptographic vulnerabilities and provide actionable remediation pathways.

### 🎯 Core Capabilities

- **Deep Asset Discovery**: Certificate Transparency (CT) scraping + async DNS brute-force with deduplication
- **Multi-Resolver DNS Support**: System resolvers, custom resolvers, optional union behavior
- **TLS Profiling**: Granular handshake inspection with enforced SNI, version/cipher/certificate extraction
- **Service-Aware Probing**: Beyond port 443 (25, 465, 587, 993, 995, 8443, 9443)
- **Adaptive Retry Strategy**: Intelligent timeout escalation and backoff/jitter for unknown TLS assets
- **PQC/HNDL Scoring Engine**: Weighted cryptographic posture classification with threshold-based readiness labels
- **CycloneDX 1.6 CBOM Export**: Standards-compliant cryptographic bill of materials
- **AI-Driven Recommendations**: Claude/OpenAI-powered remediation suggestions
- **Server-Side PDF Reporting**: Automated report generation with certificate of readiness
- **Dual-Model Scanning**: General + banking-specific threat profiles
- **Blockchain Audit Trail**: SHA-256 PoW chain blocks for immutable scan provenance

---

## 🏗️ Architecture

### Backend Stack
- **Framework**: FastAPI 0.116+ with async/await throughout
- **Database**: SQLAlchemy 2.0+ (PostgreSQL recommended, SQLite fallback)
- **Task Queue**: Celery 5.5+ with Redis backend (optional, for async scans)
- **Report Generation**: ReportLab 4.4+ for PDF exports
- **HTTP Client**: httpx 0.28+ for async asset probing

### Frontend Stack
- **Framework**: React 18+ (single-file JSX)
- **Charting**: Chart.js + Recharts for radar/leaderboard visuals
- **Styling**: CSS glassmorphism + liquid glass effects
- **API Integration**: Fetch-based client with smart origin detection

### Scanner Modules
| Module | Purpose | Lines |
|--------|---------|-------|
| `asset_discovery.py` | CT scraping, DNS brute-force, deduplication | 1116 |
| `tls_inspector.py` | TLS handshake, SNI validation, cipher extraction | 765 |
| `pqc_engine.py` | HNDL scoring, PQC classification, label generation | 356 |
| `cbom_generator.py` | CycloneDX 1.6 SBOM serialization | 304 |
| `pipeline.py` | 9-stage orchestration, progress tracking, error recovery | 755 |
| `ai_recommender.py` | Claude API integration for intelligent remediation | 112 |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip or uv
- (Optional) Redis for Celery
- (Optional) PostgreSQL for production

### Local Development

```bash
# Clone and setup
git clone https://github.com/your-org/quanthunt.git
cd quanthunt

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run backend (dev mode)
uvicorn backend.main:app --reload --port 8000

# Open dashboard
# Navigate to: http://localhost:8000
```

**Expected Output**:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete
```

### Docker Deployment

```dockerfile
# See included Dockerfile for containerized deployment
docker build -t quantumshield:latest .
docker run -p 8000:8000 -e DATABASE_URL="postgresql://..." quanthunt:latest
```

---

## 📡 API Endpoints

### Scan Management

#### `POST /api/scans`
Initiate a single domain scan.

**Request**:
```json
{
  "domain": "example.com",
  "deep_scan": true,
  "scan_model": "general",
  "dns_resolvers": ["8.8.8.8", "1.1.1.1"]
}
```

**Response** (202 Accepted):
```json
{
  "scan_id": "scan_abc123...",
  "domain": "example.com",
  "status": "running",
  "progress": 0
}
```

#### `POST /api/batch-scans`
Batch scan multiple domains.

**Request**:
```json
{
  "domains": ["example.com", "test.org", "acme.net"],
  "deep_scan": true,
  "scan_model": "general"
}
```

**Response** (202 Accepted):
```json
{
  "batch_id": "batch_xyz789...",
  "scan_ids": ["scan_abc123...", "scan_def456...", "scan_ghi789..."],
  "total": 3,
  "status": "queued"
}
```

#### `GET /api/scans/{scan_id}`
Fetch scan details and live progress.

**Response**:
```json
{
  "scan_id": "scan_abc123...",
  "domain": "example.com",
  "status": "completed",
  "progress": 100,
  "assets_discovered": 47,
  "assets_with_tls": 42,
  "pqc_readiness": "HYBRID_READY",
  "hndl_score": 820,
  "error": null
}
```

#### `GET /api/scan/{scan_id}/report.pdf`
Download PDF report with certificate of readiness.

### Asset & Crypto Analysis

#### `GET /api/scans/{scan_id}/assets`
List all discovered assets for a scan.

**Response**:
```json
{
  "assets": [
    {
      "host": "api.example.com",
      "ip": "192.0.2.1",
      "port": 443,
      "discovery_method": "ct",
      "tls_version": "1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "certificate": {
        "subject": "*.example.com",
        "issuer": "Let's Encrypt Authority X3",
        "not_before": "2025-01-15",
        "not_after": "2025-04-15",
        "key_size": 2048,
        "signature_algo": "sha256WithRSAEncryption"
      },
      "crypto_status": "ACCEPTABLE"
    }
  ]
}
```

#### `GET /api/scans/{scan_id}/findings`
Cryptographic findings and violations.

**Response**:
```json
{
  "findings": [
    {
      "finding_type": "weak_key_exchange",
      "severity": "CRITICAL",
      "asset_count": 3,
      "description": "ECDHE-RSA with 256-bit curve detected",
      "remediation": "Migrate to post-quantum algorithms"
    }
  ]
}
```

#### `GET /api/scans/{scan_id}/cbom`
CycloneDX 1.6 CBOM export (JSON).

### Analytics & Leaderboard

#### `GET /api/leaderboard`
Global or filtered leaderboard of scan readiness scores.

**Query Params**:
- `limit`: Top N scans (default: 10)
- `scan_model`: Filter by "general" or "banking"
- `sort_by`: "hndl_score" (default) or "assets_discovered"

**Response**:
```json
{
  "leaderboard": [
    {
      "rank": 1,
      "domain": "bank-alpha.bank.in",
      "hndl_score": 950,
      "pqc_readiness": "FULLY_QUANTUM_SAFE",
      "assets": 120,
      "scanned_at": "2025-04-10T14:22:00Z"
    }
  ]
}
```

### Configuration & Monitoring

#### `GET /api/health`
Service health and readiness probe.

#### `GET /api/status/vpn`
VPN/Network reachability summary.

#### `POST /api/models/set`
Switch active scan model at runtime.

**Request**:
```json
{
  "scan_model": "banking"
}
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/quantumshield
BANKING_DATABASE_URL=postgresql://user:pass@localhost/quantumshield_banking

# Task Queue (Optional)
USE_CELERY=true
REDIS_URL=redis://localhost:6379/0

# API Keys (Optional)
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-3-5-sonnet-latest
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4.1-mini

# CORS
CORS_ALLOW_ORIGINS=http://localhost:8000,https://dashboard.example.com
ALLOW_INSECURE_CORS=false

# Scan Tuning
SCAN_DISCOVERY_TIMEOUT_SEC=45.0
SCAN_DISCOVERY_TIMEOUT_SEC_DEEP=120.0
SCAN_CONCURRENCY=50

# Feature Flags
REUSE_COMPLETED_SCANS=false
```

### Secrets Setup (GitHub Actions)

```bash
gh secret set BACKEND_DEPLOY_HOOK_URL -b "<railway|vercel|custom-webhook-url>"
gh secret set BACKEND_ORIGIN -b "https://quantumshield-api.example.com"
```

---

## 🧪 Testing & QA

### Unit & Integration Tests

```bash
# Run all tests
pytest

# Run specific module tests
pytest tests/test_offline_and_scoring.py -v
pytest tests/test_kb_expansion.py -v

# With coverage
pytest --cov=backend
```

### Smoke Test (One-Command End-to-End)

```bash
# Windows PowerShell
scripts\deep-clean.cmd --scan-timeout 300 --port 8014

# Linux/macOS
bash scripts/deep-clean.sh --scan-timeout 300 --port 8014
```

This launches a temporary server, runs a fleet scan, and validates:
- Standalone scan completion
- Fleet scan orchestration
- Network/VPN status probes

### Live Demo Validation

```bash
# Start dev server
uvicorn backend.main:app --reload --port 8000

# Example: Scan a public domain
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com","deep_scan":false}'

# Poll progress
curl http://localhost:8000/api/scans/scan_<id>

# Get findings when complete
curl http://localhost:8000/api/scans/scan_<id>/findings
```

---

## 📊 Data Models

### Scan Lifecycle

```
queued → running → processing_results → completed/failed
  ↓                                        ↓
 logs                              findings, recommendations
 assets                            cbom_exports, chain_blocks
```

### Asset Classification

| Bucket | Definition |
|--------|-----------|
| **passive_discovered** | From CT/passive inventory (may include dead hosts) |
| **live_dns** | Resolvable via DNS (TTL > 0) |
| **live_tls_measured** | TLS profile fully captured (cipher/version/cert) |
| **service_reachable_non_443** | Responsive on secondary ports (25, 465, 587, etc.) |

### HNDL Score Formula

```
HNDL Score = Sum of weighted findings:
  - CRITICAL:   100 points × severity_factor
  - WARNING:    50 points × severity_factor
  - ACCEPTABLE: 20 points × severity_factor
  - SAFE:       0 points

Readiness Label:
  [850-1000): FULLY_QUANTUM_SAFE
  [700-850):  HYBRID_READY
  [500-700):  MIGRATION_IN_PROGRESS
  [0-500):    VULNERABLE_TO_HARVEST_NOW_DECRYPT_LATER
```

---

## 🔐 Security Considerations

### Scan Isolation
- Each scan executes in isolated DB transaction
- Scan IDs are cryptographically random (UUID4 + SHA256)
- Cross-domain interference safeguards in batch scans

### TLS Validation
- Enforced SNI in handshake (prevents hostname spoofing)
- Certificate chain validation
- Pinning support for known CA roots

### Rate Limiting (Recommended)
- Deploy with reverse proxy (nginx, Cloudflare) for rate limiting
- Recommended: 10 scans/min per API key
- 100 domains max per batch scan

### Data Retention
- Scan records: Configurable (default 90 days)
- PDF reports: Encrypted on-disk or cloud storage
- Chat history: Purged after session termination

---

## 📈 Deployment & CI/CD

### GitHub Actions Workflow

```yaml
# .github/workflows/backend-deploy.yml
- Runs regression tests before deployment
- Validates PQC scoring consistency
- Probes health endpoint: ${BACKEND_ORIGIN}/api/scans
- Auto-deploys on main branch push
```

### Optional: Keepalive Ping

```yaml
# .github/workflows/backend-keepalive.yml
Scheduled every 10 minutes to prevent cold sleep on Heroku/Railway
```

### Production Checklist

- [ ] Set `CORS_ALLOW_ORIGINS` to your domain only
- [ ] Configure `DATABASE_URL` (PostgreSQL recommended)
- [ ] Set `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` if using AI
- [ ] Enable GitHub Actions secrets
- [ ] Deploy `.github/workflows/backend-deploy.yml`
- [ ] Test health endpoint: `curl https://<your-domain>/api/scans`
- [ ] Monitor error logs and scan queue depth

---

## 🛠️ Helper Scripts

### Wordlist Seeding

For enterprise/private naming patterns, seed wordlists with custom tokens:

#### From Database Catalog
```bash
python scripts/seed_wordlists_from_db_catalog.py \
  --db-path /path/to/inventory.db \
  --wordlist backend/scanner/wordlists/custom.txt
```

#### From JSON/CSV Inventory
```bash
python scripts/import_inventory_to_wordlists.py \
  --input assets.json \
  --output backend/scanner/wordlists/imported.txt \
  --format json
```

### PQC Simulator

Test scoring logic with mock TLS profiles:

```bash
python scripts/pqc_simulator.py \
  --cipher "TLS_AES_256_GCM_SHA384" \
  --tls-version "1.3" \
  --key-size 256 \
  --host "example.com" \
  --model "general"
```

---

## 📚 Documentation

### Key Files
- **Frontend**: `frontend/app.jsx` (~12,400 LOC) — React dashboard with tabs: Scanner, Asset Map, Crypto Analysis, CBOM, Roadmap, Docs
- **Backend**: `backend/main.py` (~3,400 LOC) — FastAPI routes and scan orchestration
- **Scanner**: `backend/scanner/` — Modular PQC assessment pipeline
- **Tests**: `tests/test_offline_and_scoring.py` — Comprehensive offline test suite



## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-enhancement`
3. Commit changes with clear messages
4. Run tests: `pytest`
5. Submit pull request with description

### Development Guidelines
- Follow PEP 8 for Python; ESLint for JavaScript
- Add unit tests for new scanner modules
- Update docs for API changes
- Use type hints (Python 3.10+ syntax)

---

## 📄 License

This project is proprietary and confidential. Unauthorized copying or redistribution is prohibited.

For licensing inquiries, contact: [your-email@org.com]

---

## 🔮 Roadmap

- [ ] GraphQL API layer
- [ ] Multi-tenant SaaS dashboard
- [ ] Integration with SIEM platforms (Splunk, Elastic)
- [ ] ML-powered anomaly detection for scan patterns
- [ ] Post-quantum algorithm library expansion
- [ ] Mobile app for scan monitoring

---

## Authors

   Akul Attre | Saksham Shreyans

   
**Last Updated**: April 2026  
**Version**: 1.0.0 (MVP)  
**Status**: Production Ready ✅
