from __future__ import annotations

from pathlib import Path
from textwrap import wrap

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


OUT_PATH = Path("runlogs") / "quanthunt_prototype_20_page_report.pdf"


def draw_header(c: canvas.Canvas, page_no: int, title: str) -> None:
    w, h = A4
    c.setFillColor(colors.HexColor("#f2f6fb"))
    c.rect(0, h - 78, w, 78, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#c3d3e6"))
    c.line(30, h - 78, w - 30, h - 78)
    c.setFillColor(colors.HexColor("#2e5d8a"))
    c.setFont("Helvetica-Bold", 15)
    c.drawString(36, h - 45, "Quanthunt Prototype Dossier")
    c.setFillColor(colors.HexColor("#5c7897"))
    c.setFont("Helvetica", 10)
    c.drawString(36, h - 62, title)
    c.setFillColor(colors.HexColor("#2e5d8a"))
    c.setFont("Helvetica-Bold", 10)
    c.drawRightString(w - 36, h - 50, f"Page {page_no} of 20")


def draw_footer(c: canvas.Canvas) -> None:
    w, _ = A4
    c.setStrokeColor(colors.HexColor("#c3d3e6"))
    c.line(30, 38, w - 30, 38)
    c.setFillColor(colors.HexColor("#6a7f95"))
    c.setFont("Helvetica", 9)
    c.drawString(36, 24, "Confidential prototype summary for demonstration and technical review.")


def draw_paragraph(c: canvas.Canvas, text: str, x: float, y: float, width: int = 94, line_h: int = 14) -> float:
    c.setFillColor(colors.HexColor("#23384f"))
    c.setFont("Helvetica", 11)
    for line in wrap(text, width):
        c.drawString(x, y, line)
        y -= line_h
    return y


def draw_bullets(c: canvas.Canvas, items: list[str], x: float, y: float, width: int = 88, line_h: int = 14) -> float:
    c.setFillColor(colors.HexColor("#23384f"))
    c.setFont("Helvetica", 11)
    for item in items:
        lines = wrap(item, width)
        if not lines:
            continue
        c.drawString(x, y, f"- {lines[0]}")
        y -= line_h
        for cont in lines[1:]:
            c.drawString(x + 12, y, cont)
            y -= line_h
        y -= 4
    return y


def draw_section_box(c: canvas.Canvas, x: float, y: float, w: float, h: float, title: str) -> None:
    c.setFillColor(colors.HexColor("#f6f9fd"))
    c.roundRect(x, y - h, w, h, 12, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#c8d8ea"))
    c.roundRect(x, y - h, w, h, 12, fill=0, stroke=1)
    c.setFillColor(colors.HexColor("#2e5d8a"))
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x + 12, y - 20, title)


PAGES: list[dict[str, object]] = [
    {
        "title": "Executive Summary",
        "intro": "Quanthunt is a cybersecurity prototype for bank-domain risk visibility, with a scan-to-insight workflow that identifies cryptographic posture issues, scores risk, and proposes remediation guidance through an interactive UI.",
        "bullets": [
            "Core value: move from raw scan logs to actionable remediation and governance decisions.",
            "Scope: asset discovery, TLS and API checks, PQC-oriented findings, leaderboard and roadmap views.",
            "Deployment shape: FastAPI backend, SQL persistence, React frontend, optional Celery integration.",
            "Status: working prototype with stable backend tests and production-style report export support.",
        ],
    },
    {
        "title": "Problem Statement",
        "intro": "Security teams need a unified way to assess domain-level risk in banking environments where legacy crypto, endpoint exposure, and weak governance controls can accumulate silently over time.",
        "bullets": [
            "Fragmented tooling often hides cross-domain risk patterns.",
            "Decision makers need a score and explanation, not only raw technical findings.",
            "Operational teams need remediation sequencing that maps to real-world rollout phases.",
            "Prototype focus: shorten the path from scan event to mitigation action.",
        ],
    },
    {
        "title": "System Architecture",
        "intro": "The architecture is built around a backend scan pipeline, persistent data model, and a dashboard that transforms backend outputs into ranked, comparable, and explainable intelligence.",
        "bullets": [
            "Backend API: scan lifecycle, findings retrieval, leaderboard feeds, report generation.",
            "Scanner modules: discovery, TLS inspector, API analyzer, recommendations engine.",
            "Persistence: scan and finding records suitable for trend and governance views.",
            "Frontend tabs: scanner, crypto posture, asset map, roadmap, leaderboard, docs.",
        ],
    },
    {
        "title": "Backend API Layer",
        "intro": "The FastAPI layer orchestrates scan requests and serves structured data that powers all interactive views and downloadable artifacts.",
        "bullets": [
            "Endpoints provide scan status, findings, historical summaries, and ranking data.",
            "VPN guard behavior is retained from baseline hardening requirements.",
            "PDF report and certificate generation are exposed through API download routes.",
            "Error behavior and response payloads are designed for frontend clarity.",
        ],
    },
    {
        "title": "Scanner and Discovery",
        "intro": "Scanner execution performs multi-step evidence collection and normalizes asset-level signals into domain-level risk outputs.",
        "bullets": [
            "Asset discovery covers DNS and network-facing indicators.",
            "TLS checks capture protocol, cipher, and certificate profile signals.",
            "API checks inspect endpoint behavior and selected security metadata.",
            "Pipeline improvements include concurrency tuning and timeout controls.",
        ],
    },
    {
        "title": "Scoring and Interpretation",
        "intro": "Risk scoring is presented as a 0-100 scale where lower values indicate safer posture. Complementary security score views use inverse representation for intuitive ranking.",
        "bullets": [
            "Score bands: safer, watchlist, and high-risk priority ranges.",
            "Leaderboard and per-bank insights convert numbers into practical decisions.",
            "Problem statements and recommendations are generated from score context.",
            "Comparative analytics support domain-to-domain prioritization.",
        ],
    },
    {
        "title": "Data Model and Persistence",
        "intro": "Persistent records enable historical analysis, trend views, and evidence-backed reporting over repeated scans.",
        "bullets": [
            "Scan records include status, progress, and domain identifiers.",
            "Asset and finding records preserve technical detail behind score outcomes.",
            "Recommendation records map to roadmap phase and action planning.",
            "CBOM exports provide standardized component-level context for crypto posture.",
        ],
    },
    {
        "title": "Frontend Experience",
        "intro": "The dashboard is built for decision flow: scan command, posture visualization, prioritized insights, and actionable next steps in one interface.",
        "bullets": [
            "Liquid-glass and claymorphism aesthetic supports premium prototype presentation.",
            "Interactive podium and ranking views surface top-safe and top-risk domains.",
            "Mobile adjustments improve readability and touch behavior on compact screens.",
            "Assistant panel supports quick analytical prompts with context injection.",
        ],
    },
    {
        "title": "Tab Walkthrough: Scanner",
        "intro": "Scanner tab initiates and monitors scan execution, including logs, progress overlays, and artifact download actions.",
        "bullets": [
            "Supports single-domain and batch scan launch flows.",
            "Displays real-time progress and operational telemetry logs.",
            "Allows report and readiness certificate download after completion.",
            "Provides formula breakdown panel for traceable score composition.",
        ],
    },
    {
        "title": "Tab Walkthrough: Crypto and Assets",
        "intro": "Crypto and asset tabs expose technical context behind domain risk through component-level and host-level inspection summaries.",
        "bullets": [
            "Crypto posture uses radar and fallback visualization paths.",
            "Asset map highlights host labels and detected VPN signal tags.",
            "Rows and lists are deduplicated by latest domain evidence.",
            "Tables preserve detailed references for analyst follow-up.",
        ],
    },
    {
        "title": "Tab Walkthrough: Roadmap",
        "intro": "Roadmap translates findings into phased action groups so execution can be sequenced according to urgency, hardening depth, and governance maturity.",
        "bullets": [
            "Phase 1: immediate stabilization tasks.",
            "Phase 2: protocol and platform hardening.",
            "Phase 3: modernization toward PQC readiness.",
            "Phase 4: governance and continuous control validation.",
        ],
    },
    {
        "title": "Tab Walkthrough: Leaderboard",
        "intro": "Leaderboard compares domain posture and now includes a bank/domain selector that returns focused analysis, problems, and recommendations per selected entity.",
        "bullets": [
            "Trend chart supports both Recharts and visual fallback path.",
            "Selector dropdown uses gold claymorphism for visual emphasis.",
            "Per-bank cards provide concise narrative suitable for executive review.",
            "All-domain intelligence remains available without duplicate entries.",
        ],
    },
    {
        "title": "AI Assistant and Guidance",
        "intro": "The assistant panel offers context-aware support for quick analysis, prediction prompts, and recommendation synthesis from current leaderboard context.",
        "bullets": [
            "Supports preset prompt library and freeform questions.",
            "Context source can use backend or deterministic fallback baseline.",
            "Focus modes help narrow assistant output toward analysis or solutions.",
            "Design aligns with glassmorphism to match dashboard identity.",
        ],
    },
    {
        "title": "Design Language and Branding",
        "intro": "The prototype uses a distinctive visual system combining glass, clay, and metallic accents to communicate premium reliability while preserving information density.",
        "bullets": [
            "Bolder Quanthunt wordmark in sidebar brand area.",
            "Animated claymorphism logo for visual signature.",
            "Gold, silver, bronze interactive podium treatment.",
            "Color and typography tuned for desktop and mobile readability.",
        ],
    },
    {
        "title": "Security and Controls",
        "intro": "Security posture is represented both technically and operationally, pairing low-level evidence with policy-facing messages that teams can execute.",
        "bullets": [
            "Risk signals include TLS, certificate, endpoint, and exposure indicators.",
            "VPN blocking behavior enforced in backend access guard path.",
            "Roadmap guidance reduces ambiguity in mitigation sequencing.",
            "Per-domain score explanations improve decision confidence.",
        ],
    },
    {
        "title": "Performance and Reliability",
        "intro": "Recent optimization passes improved scanner throughput and responsiveness while preserving output consistency.",
        "bullets": [
            "Concurrency tuning in scan pipeline reduced total scan turnaround.",
            "Timeout controls for API and AI recommendation path improved stability.",
            "Performance logging outputs discovery and total scan timings.",
            "Fallback paths ensure UI usability even when external libs are unavailable.",
        ],
    },
    {
        "title": "Testing and Validation",
        "intro": "Validation combines code diagnostics, runtime tests, and artifact checks to reduce regression risk before demonstrations.",
        "bullets": [
            "Python tests passing: 15 passed in scoped test run.",
            "Compile checks succeed across backend and test modules.",
            "Frontend warnings are primarily style-policy diagnostics on inline styles.",
            "Known deprecation warning: FastAPI startup event hook migration pending.",
        ],
    },
    {
        "title": "Demo Narrative",
        "intro": "A recommended demonstration flow highlights business value first, then technical depth, then operational next steps.",
        "bullets": [
            "Start with scanner launch and live progress overlay.",
            "Show leaderboard and per-bank selector-driven intelligence.",
            "Open roadmap to communicate phased mitigation strategy.",
            "Export report artifact to prove audit-ready documentation.",
        ],
    },
    {
        "title": "Operational Readiness",
        "intro": "Prototype deployment can run locally for demos and can be extended to queue-backed execution patterns for heavier scan workloads.",
        "bullets": [
            "Local run path uses FastAPI and venv dependencies.",
            "Optional Celery and Redis support asynchronous execution model.",
            "Environment-based toggles support external model integrations.",
            "Versioned static assets reduce stale cache behavior after UI updates.",
        ],
    },
    {
        "title": "Roadmap to Production",
        "intro": "The prototype has a clear path toward production readiness with security hardening, observability, and governance automation as next milestones.",
        "bullets": [
            "Migrate deprecated startup hook to lifespan handlers.",
            "Externalize inline styles into structured CSS modules.",
            "Add CI test gate and artifact publishing workflow.",
            "Expand policy mappings and control coverage catalog.",
        ],
    },
    {
        "title": "Conclusion",
        "intro": "Quanthunt demonstrates a complete prototype loop from scan execution to executive-ready intelligence. It is positioned as a practical security decision platform with immediate demo value and clear expansion paths.",
        "bullets": [
            "Prototype is functional, tested, and presentation-ready.",
            "Per-bank selector improves stakeholder-specific review.",
            "Report generation supports compliance and governance narratives.",
            "Next phase can focus on production hardening and CI operationalization.",
        ],
    },
]


def build_pdf() -> Path:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(OUT_PATH), pagesize=A4)
    w, h = A4

    for idx, page in enumerate(PAGES, start=1):
        draw_header(c, idx, str(page["title"]))
        draw_footer(c)

        draw_section_box(c, 34, h - 98, w - 68, h - 156, str(page["title"]))

        y = h - 138
        y = draw_paragraph(c, str(page["intro"]), 52, y, width=96, line_h=15)
        y -= 8
        draw_bullets(c, list(page["bullets"]), 52, y, width=92, line_h=15)

        c.showPage()

    c.save()
    return OUT_PATH


if __name__ == "__main__":
    out = build_pdf()
    print(f"PDF generated: {out}")
    print("Total pages: 20")
