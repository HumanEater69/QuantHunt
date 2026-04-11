🚀 Quanthunt — Quantum-Proof Systems Scanner

Quanthunt is an advanced cybersecurity platform designed to analyze public-facing systems and evaluate their readiness for the post-quantum era. It scans digital assets, generates Crypto Bill of Materials (CBOM), and provides actionable insights for Post-Quantum Cryptography (PQC) migration.

🌐 Overview

With the rise of quantum computing, traditional cryptographic systems are at risk from Harvest Now, Decrypt Later (HNDL) attacks.

Quanthunt helps organizations:

Discover cryptographic assets
Analyze vulnerabilities
Assess quantum risk
Generate CBOM reports
Recommend PQC migration strategies
🧠 Key Features
🔍 Asset Discovery
Identifies domains, APIs, endpoints, and exposed services
Supports targeted and wordlist-based scanning
🔐 Cryptographic Analysis
TLS inspection (versions, cipher suites, key exchange)
Certificate analysis
Weak/legacy crypto detection
🧾 CBOM Generation
Generates machine-readable reports:
JSON
Logs
Scan summaries
CERT-In aligned structure
⚛️ PQC Readiness Engine
Labels systems:
❌ Not Quantum Safe
⚠️ PQC Ready
✅ Fully Quantum Safe
🤖 AI-Based Recommendations
Suggests migration strategies
Context-aware remediation guidance
📊 Dashboard & Reporting
Visual insights (frontend)
Exportable reports
Audit-ready artifacts
⚙️ Async Scanning
Powered by Celery + Redis
Scalable background task execution
🏗️ Project Structure
quanthunt/
│
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── models.py            # Data models
│   ├── db.py                # Database config
│   ├── tasks.py             # Celery async jobs
│   ├── reporting.py         # Report generation
│   ├── pqc_utils.py         # PQC logic
│   │
│   └── scanner/
│       ├── pipeline.py      # Scan orchestration
│       ├── tls_inspector.py # TLS analysis
│       ├── cbom_generator.py
│       ├── pqc_engine.py
│       ├── asset_discovery.py
│       ├── api_analyzer.py
│       └── ai_recommender.py
│
├── frontend/
│   ├── app.jsx              # React frontend
│   ├── index.html
│   └── styles.css
│
├── artifacts/               # Scan outputs & CBOM reports
├── .github/workflows/       # CI/CD pipelines
└── README.md
⚙️ Tech Stack
Backend
FastAPI
Celery + Redis
SQLite (can be upgraded)
HTTPX
ReportLab
Frontend
React (Vite-based setup)
DevOps
GitHub Actions (CI/CD)
Railway / Netlify deployment-ready
🚀 Getting Started
1️⃣ Clone the Repository
git clone https://github.com/your-username/quanthunt.git
cd quanthunt
2️⃣ Setup Backend
cd backend
pip install -r requirements.txt

Run FastAPI server:

uvicorn main:app --reload
3️⃣ Start Celery Worker
celery -A celery_app.celery worker --loglevel=info
4️⃣ Setup Frontend
cd frontend
npm install
npm run dev
📡 How It Works
Input target domain / system
Asset discovery begins
TLS & crypto inspection runs
CBOM is generated
PQC engine evaluates risk
AI recommends migration steps
Reports are exported
📁 Sample Outputs

Located in /artifacts/:

scan.json
cbom.json
logs.json
🔐 Use Cases
Banking & Financial Systems
Government Infrastructure
Public APIs
Enterprise Security Audits
⚠️ Limitations
Focused on public-facing assets
PQC recommendations are evolving with NIST standards
Requires tuning for large-scale enterprise deployments
🧠 Future Enhancements
🔗 Blockchain-based audit logs
🧬 Full NIST PQC integration
🧠 Advanced AI risk scoring
☁️ Cloud-native distributed scanning
🤝 Contributing

Contributions are welcome!

fork → clone → branch → commit → PR
📜 License

MIT License (or specify your preferred license)

🏆 Hackathon Context

Built for:
PSB Cybersecurity Hackathon 2026

Theme:

Quantum-Safe Cryptographic Transition & CBOM Generation

👨‍💻 Authors

Akul Attre | Saksham Shreyans

💡 Tagline

"Secure today. Quantum-proof tomorrow."
