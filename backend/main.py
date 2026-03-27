from __future__ import annotations

import asyncio
import csv
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select

from .crud import (
    append_chain_block,
    assemble_scan_payload,
    create_scan as create_scan_record,
    findings_payload,
    leaderboard_payload,
    scan_detail_payload,
    scans_list_payload,
)
from .db import (
    DEFAULT_SCAN_MODEL,
    SCAN_MODELS,
    get_all_engines,
    get_session,
    normalize_scan_model,
    reset_active_scan_model,
    set_active_scan_model,
)
from .models import (
    BatchProgressRequest,
    BatchScanRequest,
    NetworkHintsRequest,
    PqcFleetExportRequest,
    QuantHuntChatRequest,
    PdfGenerateRequest,
    PqcSimRequest,
    ScanRequest,
)
from .reporting import build_quantum_certificate, build_scan_pdf, readiness_label
from .scanner import run_scan_pipeline
from .tasks import run_scan_task
from .tables import Asset, Base, CbomExport, ChainBlock, Scan


def _cors_origins_from_env() -> list[str]:
    default_origins = ["http://127.0.0.1:8000", "http://localhost:8000"]
    raw = os.getenv("CORS_ALLOW_ORIGINS", ",".join(default_origins)).strip()
    allow_insecure = os.getenv("ALLOW_INSECURE_CORS", "false").lower() == "true"
    if raw == "*" and allow_insecure:
        return ["*"]
    origins = [o.strip() for o in raw.split(",") if o.strip() and o.strip() != "*"]
    return origins or default_origins


app = FastAPI(title="QUANTHUNT API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins_from_env(),
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
USE_CELERY = os.getenv("USE_CELERY", "false").lower() == "true"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
REUSE_COMPLETED_SCANS = os.getenv("REUSE_COMPLETED_SCANS", "false").lower() == "true"
VPN_BLOCK_ENABLED = os.getenv("VPN_BLOCK_ENABLED", "true").lower() == "true"
VPN_BLOCK_ON_PROXY = os.getenv("VPN_BLOCK_ON_PROXY", "true").lower() == "true"
VPN_BLOCK_ON_HOSTING = os.getenv("VPN_BLOCK_ON_HOSTING", "true").lower() == "true"
VPN_ENFORCE_BLOCK = os.getenv("VPN_ENFORCE_BLOCK", "false").lower() == "true"
VPN_CHECK_TIMEOUT_SEC = float(os.getenv("VPN_CHECK_TIMEOUT_SEC", "2.5"))
VPN_CACHE_TTL_SEC = float(os.getenv("VPN_CACHE_TTL_SEC", "300"))
VPN_GEO_ENDPOINT = os.getenv("VPN_GEO_ENDPOINT", "http://ip-api.com/json")
VPN_TRUST_X_FORWARDED_FOR = (
    os.getenv("VPN_TRUST_X_FORWARDED_FOR", "true").lower() == "true"
)
VPN_SCORE_THRESHOLD = int(os.getenv("VPN_SCORE_THRESHOLD", "70"))
VPN_TLD_BLOCKLIST = {
    t.strip().lower().lstrip(".")
    for t in os.getenv("VPN_TLD_BLOCKLIST", "vpn,proxy").split(",")
    if t.strip()
}
VPN_REVERSE_KEYWORDS = {
    t.strip().lower()
    for t in os.getenv(
        "VPN_REVERSE_KEYWORDS",
        "vpn,proxy,tunnel,wireguard,openvpn,nord,surfshark,expressvpn,mullvad,proton",
    ).split(",")
    if t.strip()
}
VPN_NETWORK_KEYWORDS = {
    t.strip().lower()
    for t in os.getenv(
        "VPN_NETWORK_KEYWORDS",
        "vpn,proxy,anonymous,datacenter,colo,hosting,m247,ovh,choopa,vultr,digitalocean,linode,hetzner,leaseweb",
    ).split(",")
    if t.strip()
}
_VPN_CACHE: dict[str, tuple[float, bool, str]] = {}
FLEET_MAX_DOMAINS = 350
FLEET_BACKEND_INSTANT_THRESHOLD = 5


def _profile_domain_latency(domain: str) -> dict:
    out = {
        "status": "failed",
        "rtt_ms": 0.0,
        "classical_tls_ms": 0.0,
        "error": None,
    }
    try:
        start_tcp = time.time()
        sock = socket.create_connection((domain, 443), timeout=5)
        out["rtt_ms"] = round((time.time() - start_tcp) * 1000, 2)

        context = ssl.create_default_context()
        start_tls = time.time()
        ssock = context.wrap_socket(sock, server_hostname=domain)
        out["classical_tls_ms"] = round((time.time() - start_tls) * 1000, 2)
        ssock.close()

        out["status"] = "success"
    except Exception as exc:
        out["error"] = str(exc)
    return out


def _simulate_pqc_latency(
    rtt_ms: float,
    payload_size: int,
    loss_rate: float,
    min_rto: float = 200.0,
    mss: int = 1460,
    iw: int = 10,
    crypto_ms: float = 5.0,
) -> dict:
    n_seg = max(1, math.ceil(payload_size / mss))
    flights = 0 if n_seg <= iw else math.ceil(math.log2((n_seg / iw) + 1))
    t_prop = rtt_ms * (2 + flights)
    p_success = (1 - loss_rate) ** n_seg
    if p_success <= 0:
        p_success = 0.0001
    rto = max(min_rto, 3 * rtt_ms)
    t_loss = ((1 - p_success) / p_success) * rto
    total_ttfb = t_prop + t_loss + crypto_ms
    return {
        "payload_size": payload_size,
        "segments": n_seg,
        "extra_flights": flights,
        "t_prop_ms": round(t_prop, 2),
        "p_success": round(p_success, 6),
        "rto_ms": round(rto, 2),
        "t_loss_ms": round(t_loss, 2),
        "crypto_ms": round(crypto_ms, 2),
        "total_latency_ms": round(total_ttfb, 2),
    }


def _certificate_eligibility(scan: dict) -> tuple[bool, list[str], float]:
    findings = scan.get("findings") or []
    if not findings:
        return False, ["No findings were produced for this scan."], 100.0

    scores = [float(f.get("hndl_risk_score", 0)) for f in findings]
    avg_risk = sum(scores) / max(len(scores), 1)
    reasons: list[str] = []

    # Tightened bar: require stronger aggregate posture.
    if avg_risk > 60:
        reasons.append(
            f"Average HNDL risk {avg_risk:.2f} exceeds certification threshold (<= 60)."
        )

    unknown_tls_assets = []
    for f in findings:
        tls = f.get("tls") or {}
        tls_version = str(tls.get("tls_version") or "").strip().lower()
        scan_error = str(tls.get("scan_error") or "").strip()
        if tls_version in {"", "unknown", "none"} or scan_error:
            unknown_tls_assets.append(str(f.get("asset") or "unknown"))
    if unknown_tls_assets:
        reasons.append(
            f"TLS handshake/version could not be validated for {len(unknown_tls_assets)} asset(s): "
            + ", ".join(unknown_tls_assets[:8])
            + (" ..." if len(unknown_tls_assets) > 8 else "")
        )

    critical_assets = []
    warning_assets = []
    for f in findings:
        statuses = [
            str(f.get("key_exchange_status") or ""),
            str(f.get("auth_status") or ""),
            str(f.get("tls_status") or ""),
            str(f.get("cert_algo_status") or ""),
            str(f.get("symmetric_status") or ""),
        ]
        if any(s.upper() == "CRITICAL" for s in statuses):
            critical_assets.append(str(f.get("asset") or "unknown"))
        if any(s.upper() == "WARNING" for s in statuses):
            warning_assets.append(str(f.get("asset") or "unknown"))
    if critical_assets:
        reasons.append(
            f"Critical cryptographic posture detected on {len(critical_assets)} asset(s): "
            + ", ".join(critical_assets[:8])
            + (" ..." if len(critical_assets) > 8 else "")
        )

    # Additional strictness: too many transitional warnings cannot be certified.
    warning_ratio = len(set(warning_assets)) / max(len(findings), 1)
    if warning_ratio > 0.35:
        reasons.append(
            f"Warning-level posture remains high ({warning_ratio * 100:.1f}% of assets; allowed <= 35.0%)."
        )

    cbom = scan.get("cbom") or {}
    components = cbom.get("components") if isinstance(cbom, dict) else []
    pqc_signals = 0
    if isinstance(components, list):
        for comp in components:
            props = {str(p.get("name")): str(p.get("value")) for p in (comp.get("properties") or [])}
            if (
                props.get("nist-fips-203-signal-detected", "false").lower() == "true"
                or props.get("nist-fips-204-signal-detected", "false").lower() == "true"
                or props.get("nist-fips-205-signal-detected", "false").lower() == "true"
            ):
                pqc_signals += 1
    if pqc_signals == 0:
        reasons.append(
            "No NIST PQC signal (FIPS 203/204/205) detected in observed TLS/certificate metadata."
        )

    return len(reasons) == 0, reasons, round(avg_risk, 2)


def _normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d


def _is_valid_scan_domain(domain: str) -> bool:
    if not domain or "." not in domain:
        return False

    if any(
        c in domain
        for c in [
            "!",
            "$",
            "%",
            "^",
            "*",
            "(",
            ")",
            "+",
            "=",
            "[",
            "]",
            "{",
            "}",
            "|",
            "\\",
            ";",
            "'",
            '"',
            "<",
            ">",
            "?",
            "/",
            ",",
        ]
    ):
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False

    return bool(DOMAIN_RE.match(domain))


def _assert_scan_model(scan_model: str | None) -> str:
    raw = str(scan_model or "").strip().lower()
    if raw not in SCAN_MODELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan_model. Expected one of: {', '.join(SCAN_MODELS)}",
        )
    return normalize_scan_model(raw)


def _domain_forces_banking(domain: str | None) -> bool:
    host = str(domain or "").strip().strip(".").lower()
    return host == "bank.in" or host.endswith(".bank.in")


def _effective_scan_model_for_domain(domain: str, requested_scan_model: str) -> str:
    if _domain_forces_banking(domain):
        return "banking"
    return "general"


def _find_scan_model_for_scan_id(scan_id: str) -> str | None:
    for model in SCAN_MODELS:
        token = set_active_scan_model(model)
        try:
            with get_session() as session:
                if session.get(Scan, scan_id) is not None:
                    return model
        finally:
            reset_active_scan_model(token)
    return None


def _latest_reusable_scan(session, domain: str) -> Scan | None:
    completed = (
        session.execute(
            select(Scan)
            .where(Scan.domain == domain, Scan.status == "completed")
            .order_by(desc(Scan.completed_at), desc(Scan.created_at))
        )
        .scalars()
        .first()
    )
    if completed:
        return completed
    in_flight = (
        session.execute(
            select(Scan)
            .where(Scan.domain == domain, Scan.status.in_(["running", "queued"]))
            .order_by(desc(Scan.created_at))
        )
        .scalars()
        .first()
    )
    if in_flight:
        return in_flight
    return None


def _extract_tld(hostname: str | None) -> str:
    host = str(hostname or "").strip().strip(".").lower()
    if not host or "." not in host:
        return ""
    return host.rsplit(".", 1)[-1]


def _vpn_block_reasons(
    proxy: bool, hosting: bool, reverse_host: str | None
) -> list[str]:
    reasons: list[str] = []
    if VPN_BLOCK_ON_PROXY and proxy:
        reasons.append("proxy/vpn network")
    if VPN_BLOCK_ON_HOSTING and hosting:
        reasons.append("hosting relay network")
    reverse_tld = _extract_tld(reverse_host)
    if reverse_tld and reverse_tld in VPN_TLD_BLOCKLIST:
        reasons.append(f"reverse DNS TLD .{reverse_tld}")
    return reasons


def _contains_keyword(text: str | None, keywords: set[str]) -> str:
    value = (text or "").strip().lower()
    if not value:
        return ""
    for kw in keywords:
        if kw in value:
            return kw
    return ""


def _vpn_signal_score(data: dict) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    proxy = bool(data.get("proxy"))
    hosting = bool(data.get("hosting"))
    mobile = bool(data.get("mobile"))
    reverse_host = str(data.get("reverse") or "").strip().lower()

    if proxy:
        score += 90
        reasons.append("provider flagged proxy/vpn")
    if hosting:
        score += 80
        reasons.append("provider flagged hosting/datacenter")
    if mobile:
        score -= 20

    reverse_tld = _extract_tld(reverse_host)
    if reverse_tld and reverse_tld in VPN_TLD_BLOCKLIST:
        score += 35
        reasons.append(f"reverse DNS uses blocked TLD .{reverse_tld}")

    reverse_kw = _contains_keyword(reverse_host, VPN_REVERSE_KEYWORDS)
    if reverse_kw:
        score += 35
        reasons.append(f"reverse DNS contains '{reverse_kw}'")

    asn_text = " ".join(
        [
            str(data.get("as") or ""),
            str(data.get("asname") or ""),
            str(data.get("org") or ""),
            str(data.get("isp") or ""),
        ]
    ).strip()
    network_kw = _contains_keyword(asn_text, VPN_NETWORK_KEYWORDS)
    if network_kw:
        score += 30
        reasons.append(f"network signature contains '{network_kw}'")

    score = max(0, min(score, 100))
    return score, reasons


def _client_ip_from_request(request: Request) -> str:
    if VPN_TRUST_X_FORWARDED_FOR:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            first = xff.split(",", 1)[0].strip()
            if first:
                return first
    return (request.client.host if request.client else "").strip()


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        obj.is_private
        or obj.is_loopback
        or obj.is_reserved
        or obj.is_link_local
        or obj.is_multicast
    )


async def _check_vpn_block(ip: str) -> tuple[bool, str]:
    now = time.monotonic()
    cached = _VPN_CACHE.get(ip)
    if cached and now < cached[0]:
        return cached[1], cached[2]

    blocked = False
    reason = ""
    try:
        url = f"{VPN_GEO_ENDPOINT.rstrip('/')}/{ip}"
        params = {
            "fields": "status,message,query,proxy,hosting,mobile,reverse,as,asname,org,isp"
        }
        timeout = httpx.Timeout(VPN_CHECK_TIMEOUT_SEC)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params)
            if resp.is_success:
                data = resp.json()
                reasons = _vpn_block_reasons(
                    bool(data.get("proxy")),
                    bool(data.get("hosting")),
                    data.get("reverse"),
                )
                score, score_reasons = _vpn_signal_score(data)
                all_reasons = list(dict.fromkeys([*reasons, *score_reasons]))
                blocked = VPN_ENFORCE_BLOCK and (
                    bool(reasons) or score >= VPN_SCORE_THRESHOLD
                )
                reason = ", ".join(all_reasons) if all_reasons else ""
    except Exception:
        blocked = False
        reason = ""

    _VPN_CACHE[ip] = (now + VPN_CACHE_TTL_SEC, blocked, reason)
    return blocked, reason


async def _check_vpn_status(ip: str) -> dict[str, object]:
    blocked, reason = await _check_vpn_block(ip)
    detected = bool(reason)

    score = 0

    if "provider flagged proxy/vpn" in reason:
        score += 90
    if "provider flagged hosting/datacenter" in reason:
        score += 80
    if "reverse DNS uses blocked TLD" in reason:
        score += 35
    if "reverse DNS contains" in reason:
        score += 35
    if "network signature contains" in reason:
        score += 30
    score = max(0, min(score, 100))

    return {
        "ip": ip,
        "vpn_detected": detected,
        "blocked": blocked,
        "permissible": detected and not blocked,
        "reason": reason,
        "score": score,
    }


def _infer_network_type(
    connection_type: str | None,
    effective_type: str | None,
    downlink_mbps: float | None,
    rtt_ms: float | None,
    user_agent: str | None,
) -> tuple[str, str]:
    ctype = str(connection_type or "").strip().lower()
    etype = str(effective_type or "").strip().lower()
    ua = str(user_agent or "").strip().lower()

    if ctype in {"ethernet"}:
        return "ethernet", "high"
    if ctype in {"wifi", "wlan"}:
        return "wifi", "high"
    if ctype in {"cellular", "mobile"}:
        if "5g" in etype:
            return "5g", "medium"
        if "4g" in etype:
            return "4g", "medium"
        if "3g" in etype:
            return "3g", "medium"
        return "mobile", "medium"

    if "5g" in etype:
        return "5g", "medium"
    if "4g" in etype:
        return "4g", "medium"
    if "3g" in etype or "2g" in etype:
        return "mobile", "medium"

    if downlink_mbps is not None and rtt_ms is not None:
        if downlink_mbps >= 80 and rtt_ms <= 25:
            return "ethernet/wifi", "low"
        if downlink_mbps >= 20 and rtt_ms <= 50:
            return "wifi/4g", "low"
        if downlink_mbps < 15 and rtt_ms >= 60:
            return "mobile/edge", "low"

    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "mobile", "low"
    return "unknown", "low"


def _network_signal_payload(
    ip: str,
    status: dict[str, object],
    connection_type: str | None,
    effective_type: str | None,
    downlink_mbps: float | None,
    rtt_ms: float | None,
    user_agent: str | None,
) -> dict[str, object]:
    network_type, confidence = _infer_network_type(
        connection_type,
        effective_type,
        downlink_mbps,
        rtt_ms,
        user_agent,
    )
    return {
        **status,
        "network": {
            "type": network_type,
            "confidence": confidence,
            "ip": ip,
            "connection_type": connection_type or "",
            "effective_type": effective_type or "",
            "downlink_mbps": downlink_mbps,
            "rtt_ms": rtt_ms,
        },
    }


def _sync_asset_labels_for_scan(session, scan_id: str) -> list[Asset]:
    assets = (
        session.execute(select(Asset).where(Asset.scan_id == scan_id)).scalars().all()
    )
    for asset in assets:
        expected = readiness_label(float(asset.risk_score or 0))
        if asset.label != expected:
            asset.label = expected
    return assets


def _ensure_chain_block_for_completed_scan(session, scan: Scan) -> None:
    if scan.status != "completed":
        return
    assets = _sync_asset_labels_for_scan(session, scan.scan_id)
    existing = session.execute(
        select(ChainBlock.id).where(ChainBlock.scan_id == scan.scan_id)
    ).first()
    if existing:
        return
    avg_risk = round(sum(a.risk_score for a in assets) / max(len(assets), 1), 2)
    labels = sorted({a.label for a in assets if a.label})
    cbom = (
        session.execute(
            select(CbomExport)
            .where(CbomExport.scan_id == scan.scan_id)
            .order_by(desc(CbomExport.id))
        )
        .scalars()
        .first()
    )
    append_chain_block(
        session,
        scan.scan_id,
        payload={
            "scan_id": scan.scan_id,
            "domain": scan.domain,
            "assets": len(assets),
            "avg_hndl_risk": avg_risk,
            "labels": labels,
            "cbom_components": len(
                (cbom.cbom_json if cbom else {}).get("components", [])
            ),
            "backfilled": True,
        },
        difficulty=2,
    )


def _backfill_completed_scans(session) -> None:
    completed = (
        session.execute(select(Scan).where(Scan.status == "completed")).scalars().all()
    )
    for scan in completed:
        _ensure_chain_block_for_completed_scan(session, scan)


def _verify_chain_integrity(session) -> dict:
    blocks = (
        session.execute(
            select(ChainBlock).order_by(
                ChainBlock.block_index.asc(), ChainBlock.id.asc()
            )
        )
        .scalars()
        .all()
    )
    if not blocks:
        return {
            "chain_type": "tamper-evident hash chain",
            "valid": True,
            "block_count": 0,
            "issues": [],
            "message": "No chain blocks found.",
        }

    issues: list[dict] = []
    expected_prev_hash = "0" * 64
    previous_index = 0
    for b in blocks:
        if b.block_index <= previous_index:
            issues.append(
                {
                    "type": "index_order",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "expected_gt": previous_index,
                }
            )
        if b.prev_hash != expected_prev_hash:
            issues.append(
                {
                    "type": "prev_hash_mismatch",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "expected_prev_hash": expected_prev_hash,
                    "actual_prev_hash": b.prev_hash,
                }
            )
        seed = (
            f"{b.block_index}|{b.scan_id}|{b.payload_hash}|{b.prev_hash}|{b.difficulty}"
        )
        computed = hashlib.sha256(f"{seed}|{b.nonce}".encode("utf-8")).hexdigest()
        if computed != b.block_hash:
            issues.append(
                {
                    "type": "block_hash_mismatch",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "expected_hash": computed,
                    "actual_hash": b.block_hash,
                }
            )
        prefix = "0" * max(1, int(b.difficulty or 0))
        if not str(b.block_hash or "").startswith(prefix):
            issues.append(
                {
                    "type": "difficulty_mismatch",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "difficulty": b.difficulty,
                }
            )
        expected_prev_hash = b.block_hash
        previous_index = b.block_index

    return {
        "chain_type": "tamper-evident hash chain",
        "valid": len(issues) == 0,
        "block_count": len(blocks),
        "head_block_index": blocks[-1].block_index,
        "head_hash": blocks[-1].block_hash,
        "issues": issues,
    }


@app.on_event("startup")
def startup() -> None:
    for model, db_engine in get_all_engines().items():
        Base.metadata.create_all(bind=db_engine)
        token = set_active_scan_model(model)
        try:
            with get_session() as session:
                _backfill_completed_scans(session)
        finally:
            reset_active_scan_model(token)


@app.middleware("http")
async def vpn_access_guard(request: Request, call_next):
    if request.url.path == "/api/network-status":
        return await call_next(request)

    if not VPN_BLOCK_ENABLED:
        return await call_next(request)

    ip = _client_ip_from_request(request)
    if not ip or not _is_public_ip(ip):
        return await call_next(request)

    status = await _check_vpn_status(ip)
    blocked = bool(status.get("blocked"))
    reason = str(status.get("reason") or "")
    if not blocked:
        return await call_next(request)

    detail = f"Turn off VPN before using QuantHunt. Detected IP: {ip}."
    if reason:
        detail = (
            f"Turn off VPN before using QuantHunt. Detected IP: {ip}. Reason: {reason}."
        )

    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=403,
            content={
                "detail": detail,
                "code": "VPN_BLOCKED",
                "ip": ip,
                "reason": reason,
                "vpn_score": status.get("score", 0),
            },
        )

    html = (
        "<html><head><title>Access Blocked</title></head>"
        "<body style='font-family:Arial,sans-serif;background:#f7f7f7;color:#222;padding:40px;'>"
        "<h2>Access blocked</h2>"
        "<p>VPN or proxy usage is not allowed while accessing this prototype.</p>"
        f"<p><strong>Reason:</strong> {reason or 'network privacy relay detected'}</p>"
        "<p>Please disable VPN/proxy and refresh this page.</p>"
        "</body></html>"
    )
    return Response(content=html, media_type="text/html", status_code=403)


@app.get("/api/network-status")
async def network_status(request: Request) -> dict[str, object]:
    ip = _client_ip_from_request(request)
    headers = request.headers
    connection_type = headers.get("x-connection-type")
    effective_type = headers.get("x-effective-type")
    downlink_header = headers.get("x-downlink-mbps")
    rtt_header = headers.get("x-rtt-ms")
    downlink_mbps = float(downlink_header) if downlink_header else None
    rtt_ms = float(rtt_header) if rtt_header else None

    if not ip:
        return {
            "ip": "unknown",
            "vpn_detected": False,
            "blocked": False,
            "permissible": True,
            "reason": "",
            "score": 0,
            "network": {
                "type": "unknown",
                "confidence": "low",
                "ip": "unknown",
                "connection_type": connection_type or "",
                "effective_type": effective_type or "",
                "downlink_mbps": downlink_mbps,
                "rtt_ms": rtt_ms,
            },
            "message": "IP unavailable",
        }

    if not _is_public_ip(ip):
        status = {
            "ip": ip,
            "vpn_detected": False,
            "blocked": False,
            "permissible": True,
            "reason": "private/local address",
            "score": 0,
        }
        enriched = _network_signal_payload(
            ip,
            status,
            connection_type,
            effective_type,
            downlink_mbps,
            rtt_ms,
            headers.get("user-agent"),
        )
        enriched["message"] = "Private/local network detected"
        return enriched

    status = await _check_vpn_status(ip)
    if status["blocked"]:
        message = "Turn off VPN before using QuantHunt."
    elif status["permissible"]:
        message = "VPN detected but currently permissible within policy limit."
    else:
        message = "No VPN/proxy relay detected."

    enriched = _network_signal_payload(
        ip,
        status,
        connection_type,
        effective_type,
        downlink_mbps,
        rtt_ms,
        headers.get("user-agent"),
    )
    enriched["message"] = message
    return enriched


@app.post("/api/network-status")
async def network_status_with_hints(
    request: Request, hints: NetworkHintsRequest
) -> dict[str, object]:
    ip = _client_ip_from_request(request)
    if not ip or not _is_public_ip(ip):
        ip = ip or "unknown"
        base = {
            "ip": ip,
            "vpn_detected": False,
            "blocked": False,
            "permissible": True,
            "reason": "private/local address" if ip != "unknown" else "",
            "score": 0,
        }
    else:
        base = await _check_vpn_status(ip)
        if hints.vpn_hint and not base.get("vpn_detected"):
            base["vpn_detected"] = True
            base["reason"] = str(
                base.get("reason") or "browser hint indicates vpn/proxy"
            )

    enriched = _network_signal_payload(
        ip,
        base,
        hints.connection_type,
        hints.effective_type,
        hints.downlink_mbps,
        hints.rtt_ms,
        request.headers.get("user-agent"),
    )
    enriched["message"] = (
        "Turn off VPN before using QuantHunt."
        if enriched.get("blocked")
        else "Network profile detected."
    )
    return enriched


@app.get("/")
async def root() -> FileResponse:
    return FileResponse(str(FRONTEND_DIR / "index.html"))


@app.get("/styles.css")
async def frontend_styles() -> FileResponse:
    return FileResponse(str(FRONTEND_DIR / "styles.css"), media_type="text/css")


@app.get("/app.jsx")
async def frontend_app_jsx() -> FileResponse:
    return FileResponse(
        str(FRONTEND_DIR / "app.jsx"), media_type="text/javascript"
    )


@app.post("/api/pqc/simulate")
async def pqc_simulate(req: PqcSimRequest) -> dict:
    mss = 1460
    iw = 10
    min_rto = 200.0
    classical_size = 2500
    hybrid_size = 16800

    live = {
        "status": "skipped",
        "rtt_ms": None,
        "classical_tls_ms": None,
        "error": None,
    }

    domain = _normalize_domain(req.domain or "")
    rtt = float(req.rtt_ms) if req.rtt_ms is not None else None
    loss_rate = max(0.0, min(0.35, float(req.loss_rate)))

    if rtt is None:
        if not domain:
            raise HTTPException(status_code=400, detail="Provide domain or rtt_ms")
        live = await asyncio.to_thread(_profile_domain_latency, domain)
        if live["status"] != "success":
            raise HTTPException(
                status_code=502, detail=f"Domain profiling failed: {live['error']}"
            )
        rtt = float(live["rtt_ms"])

    classical = _simulate_pqc_latency(
        rtt, classical_size, loss_rate, min_rto=min_rto, mss=mss, iw=iw, crypto_ms=5.0
    )
    hybrid = _simulate_pqc_latency(
        rtt, hybrid_size, loss_rate, min_rto=min_rto, mss=mss, iw=iw, crypto_ms=5.0
    )

    increase_pct_classical = 0.0
    if classical["total_latency_ms"] > 0:
        increase_pct_classical = (
            (hybrid["total_latency_ms"] / classical["total_latency_ms"]) - 1
        ) * 100

    baseline_ttfb_ms = (
        float(req.baseline_ttfb_ms)
        if req.baseline_ttfb_ms is not None
        else float(classical["total_latency_ms"])
    )
    if baseline_ttfb_ms <= 0:
        baseline_ttfb_ms = float(classical["total_latency_ms"])

    absolute_latency_delta_ms = float(hybrid["total_latency_ms"]) - baseline_ttfb_ms
    latency_degradation_pct = 0.0
    if baseline_ttfb_ms > 0:
        latency_degradation_pct = (absolute_latency_delta_ms / baseline_ttfb_ms) * 100

    total_ttfb_for_risk = float(hybrid["total_latency_ms"])
    if total_ttfb_for_risk < 100:
        risk_label = "Safe"
    elif total_ttfb_for_risk <= 300:
        risk_label = "Warning"
    else:
        risk_label = "Critical"

    connection_status = (
        "Connected"
        if (live.get("status") == "success" or req.rtt_ms is not None)
        else "Awaiting Scan"
    )

    return {
        "system_config": {
            "constants": {
                "mss_bytes": mss,
                "tcp_initial_window": iw,
                "min_rto_ms": min_rto,
                "packet_loss_rate": round(loss_rate, 4),
                "crypto_processing_overhead_ms": 5.0,
                "target_pqc_hybrid_payload_bytes": hybrid_size,
            },
            "payload_profiles": {
                "classical_tls_bytes": classical_size,
                "pqc_hybrid_bytes": hybrid_size,
            },
        },
        "live_app_inputs": {
            "target_domain": domain,
            "endpoint_category": req.endpoint_category,
            "current_cipher_suite": req.current_cipher_suite,
            "measured_rtt_ms": round(float(rtt), 2),
            "baseline_ttfb_ms": round(float(baseline_ttfb_ms), 2),
            "estimated_packet_loss_pct": round(loss_rate * 100.0, 2),
        },
        "calculated_simulation_output": {
            "connection_status": connection_status,
            "classical_metrics": {
                "tcp_segments_required": classical["segments"],
                "extra_tcp_flights": classical["extra_flights"],
                "expected_packet_loss_penalty_ms": classical["t_loss_ms"],
                "total_handshake_ttfb_ms": classical["total_latency_ms"],
            },
            "pqc_hybrid_metrics": {
                "tcp_segments_required": hybrid["segments"],
                "extra_tcp_flights": hybrid["extra_flights"],
                "expected_packet_loss_penalty_ms": hybrid["t_loss_ms"],
                "total_handshake_ttfb_ms": hybrid["total_latency_ms"],
                "latency_degradation_percentage": round(increase_pct_classical, 2),
            },
            "proof_panel": {
                "baseline_rtt": {
                    "label": "Baseline RTT (ms)",
                    "value_ms": round(float(rtt), 2),
                    "formula": "Current ping = measured_rtt_ms",
                },
                "tcp_segments_required": {
                    "label": "TCP Segments Required",
                    "value": hybrid["segments"],
                    "formula": f"ceil(S_TLS/MSS) = ceil({hybrid_size}/{mss})",
                },
                "extra_tcp_flights": {
                    "label": "Extra TCP Flights",
                    "value": hybrid["extra_flights"],
                    "formula": (
                        f"N_seg({hybrid['segments']}) > iw({iw})"
                        if hybrid["segments"] > iw
                        else f"N_seg({hybrid['segments']}) <= iw({iw})"
                    ),
                },
                "latency_degradation": {
                    "label": "Latency Degradation %",
                    "value_pct": round(latency_degradation_pct, 2),
                    "formula": "((hybrid_ttfb_ms - baseline_ttfb_ms) / baseline_ttfb_ms) x 100",
                },
            },
            "dependent_variables": {
                "required_tcp_segments_n_seg": hybrid["segments"],
                "extra_tcp_flights": hybrid["extra_flights"],
                "simulated_packet_loss_penalty_t_loss_ms": hybrid["t_loss_ms"],
                "total_simulated_pqc_ttfb_ms": hybrid["total_latency_ms"],
            },
        },
        "headline_metrics": {
            "absolute_latency_delta_ms": round(absolute_latency_delta_ms, 2),
            "latency_degradation_percentage": round(latency_degradation_pct, 2),
            "risk_categorization": {
                "label": risk_label,
                "thresholds_ms": {
                    "safe_lt": 100,
                    "warning_range": "100-300",
                    "critical_gt": 300,
                },
                "basis_total_ttfb_ms": round(total_ttfb_for_risk, 2),
            },
        },
        "domain": domain or None,
        "profile": req.profile,
        "loss_rate": loss_rate,
        "mss": mss,
        "iw": iw,
        "min_rto": min_rto,
        "live_profile": live,
        "classical": classical,
        "hybrid": hybrid,
        "latency_increase_pct": round(increase_pct_classical, 2),
    }


@app.post("/api/pqc/fleet-export.csv")
async def pqc_fleet_export_csv(req: PqcFleetExportRequest) -> Response:
    domains = [_normalize_domain(d) for d in req.domains if _normalize_domain(d)]
    valid_domains = [d for d in domains if _is_valid_scan_domain(d)]
    if not valid_domains:
        raise HTTPException(status_code=400, detail="No valid domains provided")

    loss_rate = max(0.0, min(0.35, float(req.loss_rate)))
    baseline_override = req.baseline_ttfb_ms
    rows: list[dict[str, object]] = []
    max_domains = max(1, int(os.getenv("PQC_FLEET_EXPORT_MAX_DOMAINS", "24")))
    per_domain_timeout = max(
        1.0, float(os.getenv("PQC_FLEET_EXPORT_DOMAIN_TIMEOUT_SEC", "6"))
    )
    concurrency = max(1, int(os.getenv("PQC_FLEET_EXPORT_CONCURRENCY", "8")))

    domains_to_process = valid_domains[:max_domains]
    skipped_domains = valid_domains[max_domains:]
    sem = asyncio.Semaphore(concurrency)

    async def build_row(domain: str) -> dict[str, object]:
        async with sem:
            try:
                live = await asyncio.wait_for(
                    asyncio.to_thread(_profile_domain_latency, domain),
                    timeout=per_domain_timeout,
                )
            except asyncio.TimeoutError:
                live = {"status": "failed", "error": "profiling timed out"}
            except Exception as exc:
                live = {"status": "failed", "error": str(exc) or "profiling failed"}

            if live.get("status") != "success":
                return {
                    "domain": domain,
                    "status": "failed",
                    "baseline_rtt_ms": "",
                    "baseline_ttfb_ms": "",
                    "pqc_ttfb_ms": "",
                    "extra_flights": "",
                    "degradation_pct": "",
                    "packet_loss_pct": round(loss_rate * 100, 2),
                    "error": str(live.get("error") or "profiling failed"),
                }

            rtt = float(live.get("rtt_ms") or 0)
            classical = _simulate_pqc_latency(rtt, 2500, loss_rate)
            hybrid = _simulate_pqc_latency(rtt, 16800, loss_rate)
            baseline_ttfb = (
                float(baseline_override)
                if baseline_override is not None
                else float(classical["total_latency_ms"])
            )
            degradation_pct = (
                ((float(hybrid["total_latency_ms"]) - baseline_ttfb) / baseline_ttfb)
                * 100
                if baseline_ttfb > 0
                else 0.0
            )
            return {
                "domain": domain,
                "status": "ok",
                "baseline_rtt_ms": round(rtt, 2),
                "baseline_ttfb_ms": round(baseline_ttfb, 2),
                "pqc_ttfb_ms": round(float(hybrid["total_latency_ms"]), 2),
                "extra_flights": int(hybrid["extra_flights"]),
                "degradation_pct": round(degradation_pct, 2),
                "packet_loss_pct": round(loss_rate * 100, 2),
                "error": "",
            }

    rows = await asyncio.gather(*(build_row(domain) for domain in domains_to_process))
    if skipped_domains:
        rows.extend(
            {
                "domain": domain,
                "status": "failed",
                "baseline_rtt_ms": "",
                "baseline_ttfb_ms": "",
                "pqc_ttfb_ms": "",
                "extra_flights": "",
                "degradation_pct": "",
                "packet_loss_pct": round(loss_rate * 100, 2),
                "error": f"skipped to keep export responsive (max {max_domains} domains per request)",
            }
            for domain in skipped_domains
        )

    out = StringIO()
    writer = csv.DictWriter(
        out,
        fieldnames=[
            "domain",
            "status",
            "baseline_rtt_ms",
            "baseline_ttfb_ms",
            "pqc_ttfb_ms",
            "extra_flights",
            "degradation_pct",
            "packet_loss_pct",
            "error",
        ],
    )
    writer.writeheader()
    writer.writerows(rows)
    csv_text = out.getvalue()
    out.close()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=quanthunt-fleet-sim-{stamp}.csv"
        },
    )


@app.post("/api/scan")
async def create_scan(req: ScanRequest) -> dict[str, str | bool]:
    requested_scan_model = _assert_scan_model(req.scan_model)
    domain_in = _normalize_domain(req.domain)
    if not _is_valid_scan_domain(domain_in):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain. Please provide a valid hostname like pnb.bank.in",
        )
    scan_model = _effective_scan_model_for_domain(domain_in, requested_scan_model)
    token = set_active_scan_model(scan_model)
    try:
        with get_session() as session:
            if REUSE_COMPLETED_SCANS:
                reusable = _latest_reusable_scan(session, domain_in)
                if reusable is not None:
                    _ensure_chain_block_for_completed_scan(session, reusable)
                    return {
                        "scan_id": reusable.scan_id,
                        "status": reusable.status,
                        "reused": True,
                        "scan_model": scan_model,
                    }
            scan = create_scan_record(session, domain_in, deep_scan=req.deep_scan)
            scan_id = scan.scan_id
            domain = scan.domain
            status = scan.status
        payload: dict[str, str | bool] = {
            "scan_id": scan_id,
            "status": status,
            "reused": False,
            "scan_model": scan_model,
        }
        if USE_CELERY:
            run_scan_task.delay(scan_id, domain, scan_model)
        else:
            asyncio.create_task(
                run_scan_pipeline(scan_id, domain, scan_model=scan_model)
            )
        return payload
    finally:
        reset_active_scan_model(token)


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan_model = _find_scan_model_for_scan_id(scan_id)
    if scan_model is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    token = set_active_scan_model(scan_model)
    try:
        with get_session() as session:
            row = session.get(Scan, scan_id)
            if row:
                _ensure_chain_block_for_completed_scan(session, row)
            scan = scan_detail_payload(session, scan_id)
    finally:
        reset_active_scan_model(token)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    scan["scan"]["scan_model"] = scan_model
    return scan


@app.get("/api/scan/{scan_id}/certification-status")
async def get_certification_status(scan_id: str) -> dict:
    scan_model = _find_scan_model_for_scan_id(scan_id)
    if scan_model is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    token = set_active_scan_model(scan_model)
    try:
        with get_session() as session:
            scan = assemble_scan_payload(session, scan_id)
    finally:
        reset_active_scan_model(token)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    eligible, reasons, avg_risk = _certificate_eligibility(scan)
    return {
        "scan_id": scan_id,
        "eligible": eligible,
        "avg_hndl_risk": avg_risk,
        "reasons": reasons,
    }


@app.get("/api/scans")
async def list_scans(scan_model: str = Query(DEFAULT_SCAN_MODEL)) -> list[dict]:
    model = _assert_scan_model(scan_model)
    token = set_active_scan_model(model)
    try:
        with get_session() as session:
            rows = scans_list_payload(session)
    finally:
        reset_active_scan_model(token)
    if model == "banking":
        rows = [row for row in rows if _domain_forces_banking(row.get("domain"))]
    else:
        rows = [row for row in rows if not _domain_forces_banking(row.get("domain"))]
    for row in rows:
        row["scan_model"] = model
    return rows


@app.get("/api/chain/verify")
async def verify_chain(scan_model: str = Query(DEFAULT_SCAN_MODEL)) -> dict:
    model = _assert_scan_model(scan_model)
    token = set_active_scan_model(model)
    try:
        with get_session() as session:
            payload = _verify_chain_integrity(session)
    finally:
        reset_active_scan_model(token)
    payload["scan_model"] = model
    return payload


@app.get("/api/scan/{scan_id}/findings")
async def get_findings(scan_id: str) -> dict:
    scan_model = _find_scan_model_for_scan_id(scan_id)
    if scan_model is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    token = set_active_scan_model(scan_model)
    try:
        with get_session() as session:
            data = findings_payload(session, scan_id)
    finally:
        reset_active_scan_model(token)
    if data is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    data["scan_model"] = scan_model
    return data


@app.get("/api/scan/{scan_id}/cbom")
async def get_scan_cbom(scan_id: str) -> JSONResponse:
    scan_model = _find_scan_model_for_scan_id(scan_id)
    if scan_model is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    token = set_active_scan_model(scan_model)
    try:
        with get_session() as session:
            row = session.get(Scan, scan_id)
            if row:
                _ensure_chain_block_for_completed_scan(session, row)
            scan = assemble_scan_payload(session, scan_id)
    finally:
        reset_active_scan_model(token)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    if not scan.get("cbom"):
        raise HTTPException(status_code=409, detail="CBOM not ready")
    return JSONResponse(scan["cbom"], media_type="application/vnd.cyclonedx+json")


@app.get("/api/scan/{scan_id}/report.pdf")
async def get_scan_pdf(scan_id: str) -> Response:
    scan_model = _find_scan_model_for_scan_id(scan_id)
    if scan_model is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    token = set_active_scan_model(scan_model)
    try:
        with get_session() as session:
            row = session.get(Scan, scan_id)
            if row:
                _ensure_chain_block_for_completed_scan(session, row)
            scan = assemble_scan_payload(session, scan_id)
    finally:
        reset_active_scan_model(token)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    if not scan.get("findings"):
        raise HTTPException(status_code=409, detail="Scan report not ready")
    pdf = build_scan_pdf(scan)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=quanthunt-{scan_id}.pdf"
        },
    )


@app.get("/api/scan/{scan_id}/certificate.pdf")
async def get_scan_certificate(scan_id: str) -> Response:
    scan_model = _find_scan_model_for_scan_id(scan_id)
    if scan_model is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    token = set_active_scan_model(scan_model)
    try:
        with get_session() as session:
            row = session.get(Scan, scan_id)
            if row:
                _ensure_chain_block_for_completed_scan(session, row)
            scan = assemble_scan_payload(session, scan_id)
    finally:
        reset_active_scan_model(token)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    findings = scan.get("findings") or []
    if not findings:
        raise HTTPException(
            status_code=409,
            detail="Scan findings are required before certificate generation",
        )
    eligible, reasons, avg_risk = _certificate_eligibility(scan)
    pdf = build_quantum_certificate(scan, avg_risk, eligible=eligible, reasons=reasons)
    certificate_kind = "pass" if eligible else "failed"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=quanthunt-certificate-{certificate_kind}-{scan_id}.pdf"
        },
    )


@app.post("/api/pdf/generate")
async def generate_pdf_on_demand(req: PdfGenerateRequest) -> Response:
    if not req.scan_id and not req.domain:
        raise HTTPException(status_code=400, detail="Provide scan_id or domain")

    requested_model = DEFAULT_SCAN_MODEL
    if req.scan_id:
        resolved = _find_scan_model_for_scan_id(req.scan_id)
        if resolved is None:
            raise HTTPException(status_code=404, detail="scan_id not found")
        requested_model = resolved

    token = set_active_scan_model(requested_model)
    try:
        with get_session() as session:
            target_scan_id = (req.scan_id or "").strip()
            if not target_scan_id:
                domain_in = _normalize_domain(req.domain or "")
                if not _is_valid_scan_domain(domain_in):
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid domain. Please provide a valid hostname like pnb.bank.in",
                    )
                latest = (
                    session.execute(
                        select(Scan)
                        .where(Scan.domain == domain_in, Scan.status == "completed")
                        .order_by(desc(Scan.completed_at), desc(Scan.created_at))
                    )
                    .scalars()
                    .first()
                )
                if latest is None:
                    raise HTTPException(
                        status_code=404,
                        detail=f"No completed scan found for domain: {domain_in}",
                    )
                target_scan_id = latest.scan_id

            row = session.get(Scan, target_scan_id)
            if row:
                _ensure_chain_block_for_completed_scan(session, row)
            scan = assemble_scan_payload(session, target_scan_id)
    finally:
        reset_active_scan_model(token)

    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    findings = scan.get("findings") or []
    if not findings:
        raise HTTPException(
            status_code=409,
            detail="Scan findings are required before branded PDF generation",
        )

    if req.kind == "certificate":
        eligible, reasons, avg_risk = _certificate_eligibility(scan)
        pdf = build_quantum_certificate(scan, avg_risk, eligible=eligible, reasons=reasons)
        certificate_kind = "pass" if eligible else "failed"
        filename = f"quanthunt-certificate-{certificate_kind}-{scan.get('scan_id', target_scan_id)}.pdf"
    else:
        pdf = build_scan_pdf(scan)
        filename = f"quanthunt-{scan.get('scan_id', target_scan_id)}-report.pdf"

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/api/scan/batch")
async def create_batch_scan(req: BatchScanRequest) -> dict:
    requested_scan_model = _assert_scan_model(req.scan_model)
    items: list[dict[str, str | bool]] = []
    queued: list[tuple[str, str, str]] = []
    invalid: list[str] = []
    normalized: list[str] = []
    domains_by_model: dict[str, list[str]] = {m: [] for m in SCAN_MODELS}
    seen_domains: set[str] = set()

    for domain in req.domains:
        d = _normalize_domain(domain)
        if _is_valid_scan_domain(d):
            if d not in seen_domains:
                seen_domains.add(d)
                normalized.append(d)
        else:
            invalid.append(domain)
    if invalid:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Batch contains invalid domains. Provide valid hostnames like pnb.bank.in.",
                "invalid_domains": invalid,
            },
        )

    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one valid domain.",
        )

    if len(normalized) > FLEET_MAX_DOMAINS:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Fleet instant mode supports up to {FLEET_MAX_DOMAINS} unique domains per request.",
                "max_domains": FLEET_MAX_DOMAINS,
                "submitted_domains": len(normalized),
            },
        )

    execution_mode = (
        "backend_instant"
        if len(normalized) > FLEET_BACKEND_INSTANT_THRESHOLD
        else "interactive"
    )

    for domain in normalized:
        effective_model = _effective_scan_model_for_domain(domain, requested_scan_model)
        domains_by_model.setdefault(effective_model, []).append(domain)

    for model, model_domains in domains_by_model.items():
        if not model_domains:
            continue
        token = set_active_scan_model(model)
        try:
            with get_session() as session:
                for domain in model_domains:
                    if REUSE_COMPLETED_SCANS:
                        reusable = _latest_reusable_scan(session, domain)
                        if reusable is not None:
                            _ensure_chain_block_for_completed_scan(session, reusable)
                            items.append(
                                {
                                    "domain": reusable.domain,
                                    "scan_id": reusable.scan_id,
                                    "status": reusable.status,
                                    "reused": True,
                                    "scan_model": model,
                                }
                            )
                            continue
                    scan = create_scan_record(session, domain, deep_scan=req.deep_scan)
                    items.append(
                        {
                            "domain": scan.domain,
                            "scan_id": scan.scan_id,
                            "status": scan.status,
                            "reused": False,
                            "scan_model": model,
                        }
                    )
                    queued.append((scan.scan_id, scan.domain, model))
        finally:
            reset_active_scan_model(token)

    for scan_id, domain, model in queued:
        if USE_CELERY:
            run_scan_task.delay(scan_id, domain, model)
        else:
            asyncio.create_task(run_scan_pipeline(scan_id, domain, scan_model=model))

    routed_models = sorted(
        {str(item.get("scan_model")) for item in items if item.get("scan_model")}
    )
    return {
        "submitted": len(items),
        "scheduled": len(queued),
        "reused": len(items) - len(queued),
        "scan_model": requested_scan_model,
        "execution_mode": execution_mode,
        "backend_threshold": FLEET_BACKEND_INSTANT_THRESHOLD,
        "max_domains": FLEET_MAX_DOMAINS,
        "routed_models": routed_models,
        "scans": items,
    }


@app.post("/api/scan/batch/progress")
async def batch_scan_progress(req: BatchProgressRequest) -> dict:
    if not req.scans:
        raise HTTPException(status_code=400, detail="No scans were provided.")
    if len(req.scans) > FLEET_MAX_DOMAINS:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Batch progress supports up to {FLEET_MAX_DOMAINS} scans per request.",
                "max_domains": FLEET_MAX_DOMAINS,
                "submitted_scans": len(req.scans),
            },
        )

    grouped_ids: dict[str, list[str]] = {m: [] for m in SCAN_MODELS}
    lookup: dict[str, dict] = {}
    for item in req.scans:
        model = normalize_scan_model(item.scan_model)
        scan_id = str(item.scan_id or "").strip()
        if not scan_id:
            continue
        grouped_ids.setdefault(model, []).append(scan_id)
        lookup[scan_id] = {
            "scan_id": scan_id,
            "domain": str(item.domain or "").strip().lower() or None,
            "scan_model": model,
            "status": "queued",
            "progress": 0,
            "found": False,
        }

    for model, scan_ids in grouped_ids.items():
        if not scan_ids:
            continue
        token = set_active_scan_model(model)
        try:
            with get_session() as session:
                rows = (
                    session.execute(select(Scan).where(Scan.scan_id.in_(scan_ids)))
                    .scalars()
                    .all()
                )
        finally:
            reset_active_scan_model(token)

        for row in rows:
            state = str(row.status or "queued").lower()
            progress = int(row.progress or 0)
            if state in {"completed", "failed"}:
                progress = 100
            progress = max(0, min(progress, 100))
            lookup[row.scan_id] = {
                "scan_id": row.scan_id,
                "domain": row.domain,
                "scan_model": model,
                "status": state,
                "progress": progress,
                "found": True,
            }

    scans = [lookup[item.scan_id] for item in req.scans if str(item.scan_id or "").strip() in lookup]
    total = len(scans)
    if total == 0:
        return {
            "total": 0,
            "completed": 0,
            "failed": 0,
            "running": 0,
            "queued": 0,
            "in_progress": False,
            "progress_pct": 0.0,
            "execution_mode": "interactive",
            "backend_threshold": FLEET_BACKEND_INSTANT_THRESHOLD,
            "scans": [],
        }

    completed = sum(1 for x in scans if x["status"] == "completed")
    failed = sum(1 for x in scans if x["status"] == "failed")
    running = sum(1 for x in scans if x["status"] == "running")
    queued = sum(1 for x in scans if x["status"] == "queued")
    in_progress = (completed + failed) < total
    progress_pct = round(
        sum(float(x["progress"]) for x in scans) / max(total, 1),
        2,
    )

    execution_mode = (
        "backend_instant"
        if total > FLEET_BACKEND_INSTANT_THRESHOLD
        else "interactive"
    )

    return {
        "total": total,
        "completed": completed,
        "failed": failed,
        "running": running,
        "queued": queued,
        "in_progress": in_progress,
        "progress_pct": progress_pct,
        "execution_mode": execution_mode,
        "backend_threshold": FLEET_BACKEND_INSTANT_THRESHOLD,
        "scans": scans,
    }


@app.get("/api/leaderboard")
async def leaderboard(scan_model: str = Query(DEFAULT_SCAN_MODEL)) -> list[dict]:
    model = _assert_scan_model(scan_model)
    token = set_active_scan_model(model)
    try:
        with get_session() as session:
            rows = leaderboard_payload(session)
    finally:
        reset_active_scan_model(token)
    if model == "banking":
        rows = [row for row in rows if _domain_forces_banking(row.get("domain"))]
    else:
        rows = [row for row in rows if not _domain_forces_banking(row.get("domain"))]
    for row in rows:
        row["scan_model"] = model
    return rows


def _extract_gemini_text(data: dict) -> str:
    for candidate in data.get("candidates", []):
        content = candidate.get("content") or {}
        chunks: list[str] = []
        for part in content.get("parts", []):
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                chunks.append(text.strip())
        if chunks:
            return "\n".join(chunks).strip()
    return ""


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _rows_from_context(context: str | None) -> list[dict]:
    if not context:
        return []
    rows: list[dict] = []
    for line in context.splitlines():
        m = re.match(
            r"\s*\d+\.\s*([^\s]+)\s+score=([0-9]+(?:\.[0-9]+)?)\s+assets=([0-9]+)",
            line.strip(),
        )
        if not m:
            continue
        domain = m.group(1)
        score = float(m.group(2))
        assets = int(m.group(3))
        rows.append({"domain": domain, "score": score, "assets": assets})
    return rows


def _source_from_context(context: str | None) -> str:
    if not context:
        return "unknown"
    for line in context.splitlines():
        if line.lower().startswith("source="):
            return line.split("=", 1)[1].strip().lower()
    return "unknown"


def _load_offline_kb(scan_model: str = DEFAULT_SCAN_MODEL) -> dict:
    model = normalize_scan_model(scan_model)
    kb_dir = Path(__file__).parent
    candidates = [
        kb_dir / f"offline_kb_{model}.json",
        kb_dir / "offline_kb.json",
    ]
    for kb_path in candidates:
        if kb_path.exists():
            try:
                with open(kb_path, "r") as f:
                    return json.load(f).get("entries", {})
            except Exception:
                continue
    return {}


def _offline_chain_reply(
    message: str,
    context: str | None = None,
    scan_model: str = DEFAULT_SCAN_MODEL,
) -> tuple[str, str]:
    model = normalize_scan_model(scan_model)
    scope_label = "bank" if model == "banking" else "domain"
    msg = _normalize_text(message)
    if "focus:analysis" in msg and "analysis" not in msg:
        msg = "analysis"
    if "focus:prediction" in msg and "prediction" not in msg and "predict" not in msg:
        msg = "prediction"
    if "focus:solutions" in msg and "solution" not in msg:
        msg = "solutions"
    rows = _rows_from_context(context)
    source = _source_from_context(context)
    ranked = sorted(rows, key=lambda x: x["score"]) if rows else []
    safest = ranked[0] if ranked else None
    riskiest = ranked[-1] if ranked else None
    top_domain = (riskiest or {}).get("domain", f"your highest-risk {scope_label}")

    if (
        (
            "best bank" in msg
            or "safest bank" in msg
            or msg in {"best", "safest", "best bank in terms of safety"}
        )
        and "top 3" not in msg
        and "top three" not in msg
    ):
        if safest:
            return (
                f"Safest bank candidate right now: {safest['domain']}.\n"
                f"Risk score: {safest['score']:.1f} across {safest['assets']} assets.\n"
                f"Context source: {source}. Lower score means safer posture in this model.",
                "best_bank",
            )
        return (
            f"No {scope_label} ranking context available yet. Run scans or open leaderboard first.",
            "best_bank",
        )

    technical_terms = {
        "tls",
        "cipher",
        "hndl",
        "pqc",
        "kyber",
        "dilithium",
        "fips",
        "latency",
        "ttfb",
        "packet loss",
        "cbom",
        "signature",
        "certificate",
    }
    technical_overrides = (
        "pqc detection limits" in msg
        or ("certificate" in msg and ("criteria" in msg or "eligible" in msg or "require" in msg))
        or "chain block" in msg
        or "tamper evidence" in msg
    )
    if any(term in msg for term in technical_terms) and not technical_overrides:
        if ranked:
            avg = sum(r["score"] for r in ranked) / len(ranked)
            return (
                "Technical posture summary (data-driven):\n"
                f"- Sample size: {len(ranked)} domains\n"
                f"- Lowest HNDL score: {ranked[0]['domain']} ({ranked[0]['score']:.1f})\n"
                f"- Highest HNDL score: {ranked[-1]['domain']} ({ranked[-1]['score']:.1f})\n"
                f"- Mean HNDL score: {avg:.1f}\n"
                "- Interpretation: lower HNDL indicates stronger TLS/certificate posture and lower harvest-now-decrypt-later exposure.",
                "technical_summary",
            )
        return (
            "Technical answer: HNDL is computed from key exchange, authentication, TLS version, certificate profile, and symmetric ciphers. "
            "Run at least one scan to receive a data-driven ranked analysis.",
            "technical_summary",
        )

    dynamic_kb = _load_offline_kb(model)

    for cat in dynamic_kb.values():
        for k, v in cat.items():
            if k == "pqc" and "pqc detection limits" in msg:
                continue
            if k in msg:
                return (v, f"kb_{k.replace(' ', '_')}")

    FALLBACKS = {
        "hi": "Hello! I am QuantHunt AI, your Quanthunt assistant. How can I help you with quantum-risk analysis today?",
        "hello": "Hello! Ready to explore PQC posture and HNDL risk? Ask me about specific banks or general solutions.",
        "how are you": "I'm functioning at peak efficiency. Ready to analyze crypto-assets and detect quantum vulnerabilities.",
        "who are you": "I am QuantHunt AI, an AI assistant integrated into Quanthunt to help you navigate post-quantum cryptography transitions.",
        "what is quanthunt": "Quanthunt is a PQC posture dashboard. It scans assets, evaluates HNDL crypto risk, and generates roadmap + CBOM outputs.",
        "what is quantumshield": "QuantumShield is the underlying engine for Quanthunt, focusing on heuristic PQC detection and risk scoring.",
        "hndl": "Harvest Now, Decrypt Later (HNDL) is a threat where attackers collect encrypted data today to decrypt it once quantum computers are viable.",
        "pqc": "Post-Quantum Cryptography (PQC) refers to cryptographic algorithms thought to be secure against quantum computer attacks.",
        "best bank": "The safest organization is determined by the lowest aggregate HNDL score in current scan context.",
        "safest bank": "We rank safety based on modern TLS versions, strong key exchanges, and robust certificate signatures.",
        "riskiest bank": "Risk is calculated from legacy TLS (1.0/1.1), weak RSA keys, and lack of PQC-ready forward secrecy.",
        "analysis": "I can provide a portfolio-wide analysis of scanned banks, including average risk and safety spread.",
        "prediction": "My 90-day predictions estimate risk drift based on current hardening cadence and emerging quantum threats.",
        "solutions": "Primary solutions include disabling legacy TLS, upgrading to ECDHE/PQC-ready key exchange, and automating cert rotation.",
        "roadmap": "A typical 30-day roadmap involves inventory, patching high-risk assets, piloting PQC, and full rollout.",
        "cbom": "A Cryptography Bill of Materials (CBOM) lists all cryptographic assets, their algorithms, and migration priorities.",
        "pqc detection limits": "Detection is heuristic-based from observable TLS/cert metadata, not direct proof of internal implementation.",
        "chain block meaning": "The audit chain is a tamper-evident hash chain, not a decentralized blockchain. Each completed scan writes one hash-linked block for integrity tracking and audit replay.",
        "certificate criteria": "Certificate rule: strict eligibility requires average HNDL <= 70, no unknown/failed TLS assets, no critical crypto statuses, and at least one NIST PQC signal (FIPS 203/204/205).",
        "testing coverage": "Current offline regression checks cover HNDL label thresholds, key-exchange calibration, and offline intent routing.",
        "frontend polish": "UI guidance: maintain high contrast, consistent legends, and clear labels for quantum-readiness states.",
        "demo script": "3-min Demo: Scan -> Show HNDL -> Audit Chain -> CBOM -> Ask QuantHunt AI for analysis.",
        "cors": "CORS should be strictly scoped to authorized origins in production environments.",
        "limitations": "1. Heuristic detection. 2. External-only view. 3. Deterministic offline state.",
        "help": "You can ask: 'who are you', 'what is HNDL', 'top 3 risky', 'give analysis', 'solutions', or 'demo script'.",
        "compare": "Comparison: High-risk increases breach exposure; PQC-ready reduces long-term migration costs.",
        "security": "Security is evaluated through internal algorithm posture and external TLS handshake characteristics.",
        "encryption": "We audit AES, RSA, ECC, and check for transition readiness to ML-KEM and ML-DSA.",
        "compliance": "Our mapping aligns with NIST PQC standards and FIPS 140-3 transition guidelines.",
        "offline mode": "I am currently in offline mode using local context. Real-time Gemini API is used when 'online' or 'auto' is selected with a valid key.",
        "thank you": "You're welcome! Let me know if you need more quantum-risk insights.",
        "bye": "Goodbye! Stay secure in the quantum age.",
    }

    for k, v in FALLBACKS.items():
        if k in msg:
            if "top 3" in msg:
                if "safe" in msg:
                    break
            if k == "top 3 safest":
                return (v, "top_3_safest")
            if k == "top 3 risky":
                return (v, "top_3_risky")
            if k == "safest bank":
                return (v, "best_bank")
            if k == "best bank":
                return (v, "best_bank")
            if k == "certificate criteria":
                return (v, "certificate_criteria")
            if k == "chain block meaning":
                return (v, "chain_clarity")
            if k == "limitations":
                return (v, "limitations")
            if k == "pqc":
                return (v, "pqc_limits")
            if k == "testing coverage":
                return (v, "testing")
            return (v, f"fallback_{k.replace(' ', '_')}")

    if "top 3" in msg:
        if "safe" in msg:
            if ranked:
                top = ranked[:3]
                lines = [
                    f"{i + 1}. {r['domain']} ({r['score']:.1f})"
                    for i, r in enumerate(top)
                ]
                return ("Top 3 safest banks:\n" + "\n".join(lines), "top_3_safest")
            return ("No ranking context available yet.", "top_3_safest")
        if "risky" in msg or "highest risk" in msg:
            if ranked:
                top = list(reversed(ranked[-3:]))
                lines = [
                    f"{i + 1}. {r['domain']} ({r['score']:.1f})"
                    for i, r in enumerate(top)
                ]
                return ("Top 3 risky banks:\n" + "\n".join(lines), "top_3_risky")
            return ("No ranking context available yet.", "top_3_risky")

    options = (
        "Try: hi | intro | best bank | riskiest bank | analysis | prediction | "
        "solutions | roadmap | top 3 risky | top 3 safest | pqc limits | "
        "chain block | certificate | testing | demo script | help"
    )

    if (
        (
            "best bank" in msg
            or "safest bank" in msg
            or msg in {"best", "safest", "best bank in terms of safety"}
        )
        and "top 3" not in msg
        and "top three" not in msg
    ):
        if safest:
            return (
                f"Safest bank candidate right now: {safest['domain']}.\n"
                f"Risk score: {safest['score']:.1f} across {safest['assets']} assets.\n"
                f"Context source: {source}. Lower score means safer posture in this model.",
                "best_bank",
            )
        return (
            f"No {scope_label} ranking context available yet. Run scans or open leaderboard first.",
            "best_bank",
        )
    if "riskiest bank" in msg or "worst bank" in msg or "highest risk" in msg:
        if riskiest:
            return (
                f"Highest-risk bank candidate: {riskiest['domain']}.\n"
                f"Risk score: {riskiest['score']:.1f} across {riskiest['assets']} assets.\n"
                "Why: higher average HNDL exposure and larger weak-asset footprint.",
                "riskiest_bank",
            )
        return (
            f"No risk ranking context available yet. Run {scope_label} scans to generate this.",
            "riskiest_bank",
        )
    if (
        ("top 3" in msg or "top three" in msg or "three")
        and ("risky" in msg or "highest risk" in msg)
    ) or msg in {"top 3 risky", "top risky"}:
        if ranked:
            top = list(reversed(ranked[-3:]))
            lines = [
                f"{i + 1}. {r['domain']} ({r['score']:.1f})" for i, r in enumerate(top)
            ]
            return ("Top 3 risky banks:\n" + "\n".join(lines), "top_3_risky")
        return ("No ranking context available yet.", "top_3_risky")
    if (
        ("top 3" in msg or "top three" in msg or "three")
        and ("safe" in msg or "safest" in msg)
    ) or msg in {"top 3 safest", "top safest"}:
        if ranked:
            top = ranked[:3]
            lines = [
                f"{i + 1}. {r['domain']} ({r['score']:.1f})" for i, r in enumerate(top)
            ]
            return ("Top 3 safest banks:\n" + "\n".join(lines), "top_3_safest")
        return ("No ranking context available yet.", "top_3_safest")
    if msg in {"analysis", "give analysis"} or "analysis" in msg:
        if ranked:
            avg = sum(r["score"] for r in ranked) / len(ranked)
            spread = ranked[-1]["score"] - ranked[0]["score"]
            return (
                f"Bank portfolio analysis ({source}):\n"
                f"- Safest: {ranked[0]['domain']} ({ranked[0]['score']:.1f})\n"
                f"- Riskiest: {ranked[-1]['domain']} ({ranked[-1]['score']:.1f})\n"
                f"- Average risk: {avg:.1f}\n"
                f"- Risk spread: {spread:.1f}",
                "analysis",
            )
        return ("No portfolio context available for analysis yet.", "analysis")
    if (
        msg in {"prediction", "forecast", "give prediction", "predict"}
        or "prediction" in msg
    ):
        if riskiest:
            predicted = min(100.0, riskiest["score"] + 6.0)
            return (
                f"90-day prediction for {riskiest['domain']}:\n"
                f"- Current risk: {riskiest['score']:.1f}\n"
                f"- Projected risk without remediation: {predicted:.1f}\n"
                "- Key drivers: exposed legacy crypto, weak TLS hardening cadence.",
                "prediction",
            )
        return (
            "No data to predict yet. Complete at least one bank scan.",
            "prediction",
        )
    if msg in {"solution", "solutions", "give solution plan"} or "solution" in msg:
        return (
            "Recommended solutions:\n"
            "1. Patch top weak bank assets first by risk score.\n"
            "2. Enforce TLS/cipher baseline and rotate weak cert signatures.\n"
            "3. Add monthly bank-domain batch scan with drift alerts.\n"
            "4. Track safest vs riskiest delta to measure remediation impact.",
            "solutions",
        )
    if msg in {"3", "risk", "risks", "top risk", "top risky domains"} or (
        "risk" in msg and "domain" in msg
    ):
        return (
            f"Top risk focus: {top_domain}.\n"
            "Immediate actions: upgrade key exchange to PQC-ready profile, harden TLS config, and rotate weak cert/signature chains.",
            "risks",
        )
    if (
        msg in {"4", "roadmap", "migration roadmap", "30 day roadmap"}
        or "roadmap" in msg
    ):
        return (
            f"30-day roadmap for {top_domain}:\n"
            "Week 1: inventory crypto + classify by risk.\n"
            "Week 2: patch TLS/cert weaknesses.\n"
            "Week 3: pilot PQC-capable endpoints.\n"
            "Week 4: rollout + monitor regression.",
            "roadmap",
        )
    if msg in {"5", "cbom", "sbom", "what is cbom"} or "cbom" in msg:
        return (
            "CBOM explains where cryptography is used, current algorithm posture, and migration priority.\n"
            "Use it to plan PQC transitions by business impact.",
            "cbom",
        )
    if (
        "pqc detection" in msg
        or "real pqc" in msg
        or "fips validation" in msg
        or "heuristic" in msg
    ):
        return (
            "PQC detection here is an external-observation heuristic.\n"
            "It uses observed TLS/certificate metadata and signals likely posture, not cryptographic proof of full production ML-KEM/ML-DSA deployment.",
            "pqc_limits",
        )
    if "blockchain" in msg or "chain block" in msg or "tamper evidence" in msg:
        return (
            "The audit chain is a tamper-evident hash chain, not a decentralized blockchain.\n"
            "Each completed scan writes one hash-linked block for integrity tracking and audit replay.",
            "chain_clarity",
        )
    if "certificate" in msg and (
        "criteria" in msg or "eligible" in msg or "require" in msg
    ):
        return (
            "Certificate rule: strict eligibility requires average HNDL <= 70, no unknown/failed TLS assets, no critical crypto statuses, and at least one NIST PQC signal (FIPS 203/204/205).",
            "certificate_criteria",
        )
    if (
        "testing" in msg
        or "test coverage" in msg
        or msg in {"tests", "testing coverage"}
    ):
        return (
            "Current offline regression checks cover HNDL label thresholds, key-exchange calibration, and offline intent routing.\n"
            "Add network-integration tests for scanner probes as the next hardening step.",
            "testing",
        )
    if "frontend polish" in msg or "ui polish" in msg:
        return (
            "Frontend polish guidance:\n"
            "1. Keep current layout, tighten copy clarity.\n"
            "2. Keep risk legends consistent with backend thresholds.\n"
            "3. Keep offline assistant prompts explicit for demo flow.",
            "frontend_polish",
        )
    if "demo script" in msg or "pitch flow" in msg or "demo flow" in msg:
        return (
            "Recommended 3-minute demo flow:\n"
            "1. Scan domain (or reuse existing completed scan).\n"
            "2. Show HNDL breakdown + findings.\n"
            "3. Open CBOM with FIPS mapping.\n"
            "4. Show hash-chain audit block.\n"
            "5. Ask QuantHunt AI offline: analysis, prediction, solutions.",
            "demo_script",
        )
    if "cors" in msg:
        return (
            "Demo posture: CORS is allowlisted by origin now.\n"
            "For production, set CORS_ALLOW_ORIGINS strictly to approved intranet/app origins only.",
            "cors",
        )
    if "limitations" in msg or "weakness" in msg:
        return (
            "Known limitations:\n"
            "1. PQC/FIPS detection is heuristic from observable metadata.\n"
            "2. External scanning reflects exposed posture, not internal key-management internals.\n"
            "3. Offline assistant is deterministic and context-bound.",
            "limitations",
        )
    if msg in {"6", "compare", "comparison", "secure vs risk"} or "compare" in msg:
        return (
            "Business comparison:\n"
            "High-risk assets increase breach and compliance exposure.\n"
            "PQC-ready assets reduce migration cost and long-term cryptographic risk.",
            "compare",
        )
    return (
        "Live model unavailable, so I switched to offline guided answers.\n"
        f"{options}",
        "menu",
    )


@app.post("/api/quanthunt/chat")
@app.post("/api/quanthunt")
async def quanthunt_chat(req: QuantHuntChatRequest) -> dict:
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    mode = req.mode or "auto"
    focus = req.focus or "general"

    scan_model = _assert_scan_model(req.scan_model)

    system = (
        "You are QuantHunt AI inside Quanthunt, a cybersecurity assistant focused on "
        "quantum-risk, HNDL, TLS posture, CBOM guidance, and practical remediation. "
        "Be explicit that PQC/FIPS detection here is heuristic from observable metadata and that chain blocks are tamper-evident hash-chain records, not decentralized blockchain consensus."
    )
    user_text = req.message.strip()
    if focus != "general":
        user_text = f"{user_text}\n\nfocus:{focus}"
    user_payload = (
        user_text
        if not req.context
        else f"Context:\n{req.context}\n\nUser request:\n{user_text}"
    )

    response_errors: list[str] = []
    if not api_key and mode != "offline":
        response_errors.append("live model key missing")
    if api_key and mode != "offline":
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user_payload}]}],
            "generationConfig": {"temperature": 0.25, "maxOutputTokens": 420},
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, params={"key": api_key}, json=payload)
                resp.raise_for_status()
                text = _extract_gemini_text(resp.json())
                if text:
                    return {
                        "reply": text,
                        "model": model,
                        "source": "gemini-live",
                        "offline_mode": False,
                    }
                response_errors.append("gemini returned empty text")
        except Exception as ex:
            response_errors.append(f"gemini request failed: {ex}")
    elif mode == "offline":
        response_errors.append("forced offline mode")

    reply, intent = _offline_chain_reply(user_text, req.context, scan_model=scan_model)
    if response_errors:
        reply = (
            f"Live model is unavailable right now. Switched to offline mode.\n\n{reply}"
        )
    return {
        "reply": reply,
        "model": model,
        "scan_model": scan_model,
        "source": (
            "offline-fallback" if response_errors or not api_key else "gemini-live"
        ),
        "offline_mode": True,
        "offline_reason": (
            ", ".join(response_errors) if response_errors else "live model unavailable"
        ),
        "intent": intent,
        "errors": response_errors,
    }
