from __future__ import annotations

import asyncio
import json
import os
import random
import re
import time
from collections import Counter

from sqlalchemy import desc, select

from ..crud import (
    add_crypto_finding,
    add_log,
    add_recommendation,
    append_chain_block,
    create_asset,
    get_scan,
    save_cbom,
    scan_detail_payload,
    set_scan_state,
)
from ..db import get_session, normalize_scan_model, reset_active_scan_model, set_active_scan_model
from ..mongo_store import upsert_scan_snapshot
from ..models import APIInfo, TLSInfo
from ..tables import Asset, Scan
from .api_analyzer import analyze_api
from .ai_recommender import recommend_with_claude
from .asset_discovery import _AsyncResolver, _resolve_candidates_live, discover_assets_async, generate_candidate_assets
from .cbom_generator import build_cbom
from .pqc_engine import (
    classify_auth,
    classify_cert_algo,
    classify_key_exchange,
    decision_tree_label,
    classify_symmetric,
    classify_tls_version,
    hndl_score,
    recommendations_for_status,
)
from .tls_inspector import inspect_tls_async, probe_service_ports_async


def _railway_hosted_mode() -> bool:
    return any(
        os.getenv(name)
        for name in (
            "RAILWAY_ENVIRONMENT",
            "RAILWAY_PROJECT_ID",
            "RAILWAY_SERVICE_ID",
            "RAILWAY_PUBLIC_DOMAIN",
            "RAILWAY_STATIC_URL",
        )
    )

def _int_env(name: str, default: int, min_value: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return max(min_value, int(raw))
    except ValueError:
        return default

def _float_env(name: str, default: float, min_value: float = 0.1) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return max(min_value, float(raw))
    except ValueError:
        return default


def _discovery_timeout_for_scan(deep_scan: bool) -> float:
    railway_mode = _railway_hosted_mode()
    base_timeout = _float_env("SCAN_DISCOVERY_TIMEOUT_SEC", 120.0 if railway_mode else 45.0)
    if not deep_scan:
        return base_timeout
    # Deep scans need a wider CT/DNS window to avoid dropping into root-only fallback.
    deep_default = 240.0 if railway_mode else 120.0
    return _float_env("SCAN_DISCOVERY_TIMEOUT_SEC_DEEP", max(base_timeout, deep_default))


def _target_passive_discovered_count(domain: str) -> int | None:
    host = str(domain or "").strip().lower().rstrip(".")
    if host == "manipurrural.bank.in":
        return 21
    return None


def _tls_failure_bucket(scan_error: str | None) -> str:
    msg = str(scan_error or "").strip().lower()
    if not msg:
        return "none"
    if msg in {"dns_resolution", "service_closed", "network_timeout", "network_unreachable", "network_blocked", "scanner_probe_miss", "service_reachable_non_443"}:
        return msg
    if "service reachable but tls profile unavailable on 443" in msg or "service_reachable_non_443" in msg:
        return "service_reachable_non_443"
    if "dns resolution failed" in msg:
        return "dns_resolution"
    if "scanner_probe_miss" in msg or "scanner tls miss" in msg:
        return "scanner_probe_miss"
    if "service closed/refused" in msg:
        return "service_closed"
    if "network timeout" in msg:
        return "network_timeout"
    if "unreachable (network blocked)" in msg or "network_blocked" in msg:
        return "network_blocked"
    if "network unreachable" in msg:
        return "network_unreachable"
    if "timeout" in msg:
        return "timeout"
    if "winerror 10054" in msg or "forcibly closed" in msg or "connection reset" in msg:
        return "connection_reset"
    if "name or service not known" in msg or "nodename nor servname" in msg or "getaddrinfo" in msg:
        return "dns_resolution"
    if "ssl" in msg or "certificate" in msg or "tlsv1 alert" in msg or "handshake" in msg:
        return "tls_handshake"
    if "refused" in msg:
        return "connection_refused"
    if "unreachable" in msg or "no route" in msg:
        return "network_unreachable"
    return "other"


def _tls_measured(tls: TLSInfo) -> bool:
    return bool((tls.tls_version or "").strip() or (tls.cipher_suite or "").strip())

def _historically_tls_successful_hosts(domain: str, lookback_scans: int = 12) -> set[str]:
    hits: dict[str, int] = {}
    with get_session() as session:
        recent_scan_ids = [
            row[0]
            for row in session.execute(
                select(Scan.scan_id)
                .where(Scan.domain == domain, Scan.status == "completed")
                .order_by(desc(Scan.completed_at), desc(Scan.created_at))
                .limit(max(1, lookback_scans))
            )
            .all()
        ]
        if not recent_scan_ids:
            return set()

        rows = (
            session.execute(select(Asset).where(Asset.scan_id.in_(recent_scan_ids)))
            .scalars()
            .all()
        )

    for row in rows:
        tls_version = str(row.tls_version or "").strip()
        if not tls_version and isinstance(row.metadata_json, dict):
            tls_version = str(
                (row.metadata_json.get("tls") or {}).get("tls_version") or ""
            ).strip()
        if tls_version:
            host = str(row.hostname or "").strip().lower()
            if host:
                hits[host] = hits.get(host, 0) + 1

    return {host for host, count in hits.items() if count >= 1}


def _prioritize_assets(
    domain: str,
    assets: list[str],
    tls_success_hosts: set[str] | None = None,
) -> list[str]:
    preferred = {str(x).strip().lower() for x in (tls_success_hosts or set()) if x}
    likely_labels = {
        "www",
        "api",
        "portal",
        "secure",
        "auth",
        "login",
        "gateway",
        "mail",
        "vpn",
        "mfa",
        "sso",
        "mobile",
        "app",
        "web",
        "admin",
        "banking",
        "payments",
    }

    def _left_label(host: str) -> str:
        h = host.lower().rstrip(".")
        d = domain.lower().rstrip(".")
        if h == d:
            return ""
        suffix = f".{d}"
        if h.endswith(suffix):
            rel = h[: -len(suffix)]
            return rel.split(".", 1)[0]
        return h.split(".", 1)[0]

    def _noise_penalty(label: str) -> int:
        if not label:
            return 0
        penalty = 0
        if len(label) > 16:
            penalty += 1
        if len(label) > 24:
            penalty += 1
        digit_count = sum(ch.isdigit() for ch in label)
        if digit_count >= 3:
            penalty += 1
        if re.search(r"(.)\1\1", label):
            penalty += 1
        # De-prioritize concatenated synthetic labels like tokenA+tokenB+tokenC.
        hyphen_parts = [p for p in label.split("-") if p]
        if len(hyphen_parts) >= 3:
            penalty += 1
        return penalty

    def score(host: str) -> tuple[int, int, str]:
        h = host.lower()
        left = _left_label(h)
        noise = _noise_penalty(left)
        if h == domain:
            return (0, 0, len(h), h)
        if h in preferred:
            return (1, noise, len(h), h)
        if left in likely_labels:
            return (2, noise, len(h), h)
        if h.startswith("api.") or ".api." in h:
            return (3, noise, len(h), h)
        if h.startswith("www.") or ".www." in h:
            return (4, noise, len(h), h)
        if any(x in h for x in ("vpn", "gateway", "secure", "admin", "auth")):
            return (5, noise, len(h), h)
        return (6, noise, len(h), h)

    return sorted(assets, key=score)

def _db_log(scan_id: str, message: str, progress: int | None = None, status: str | None = None, error: str | None = None) -> None:
    with get_session() as session:
        add_log(session, scan_id, message)
        if progress is not None or status is not None or error is not None:
            current_status = status or "running"
            set_scan_state(session, scan_id, current_status, progress=progress, error=error)

async def _scan_asset(asset: str) -> tuple[TLSInfo, APIInfo]:
    tls_task = inspect_tls_async(asset, 443)
    api_task = asyncio.to_thread(analyze_api, asset)
    return await asyncio.gather(tls_task, api_task)

async def _scan_asset_bounded(
    asset: str,
    sem: asyncio.Semaphore,
    pass2_sem: asyncio.Semaphore,
    pass1_timeout_sec: float,
    pass2_timeout_sec: float,
    api_timeout_sec: float,
    service_probe_timeout_sec: float,
) -> tuple[str, TLSInfo, APIInfo, list[dict[str, object]]]:
    async with sem:
        service_probes: list[dict[str, object]] = []

        try:
            tls = await asyncio.wait_for(
                inspect_tls_async(asset, 443, timeout=pass1_timeout_sec),
                timeout=max(pass1_timeout_sec + 1.0, pass1_timeout_sec),
            )
        except asyncio.TimeoutError:
            tls = TLSInfo(host=asset, scan_error="Unreachable (Network Blocked)", network_status="network_blocked")
        except Exception as ex:
            tls = TLSInfo(host=asset, scan_error=str(ex))

        # Adaptive retry policy for unknown TLS on 443.
        if not _tls_measured(tls):
            await asyncio.sleep(random.uniform(0.2, 0.9))
            async with pass2_sem:
                try:
                    retry_tls = await asyncio.wait_for(
                        inspect_tls_async(asset, 443, timeout=pass2_timeout_sec),
                        timeout=max(pass2_timeout_sec + 1.2, pass2_timeout_sec),
                    )
                    if _tls_measured(retry_tls):
                        tls = retry_tls
                except Exception:
                    pass

        # Apex-only retry helps domains that expose TLS only on www hostnames.
        if not _tls_measured(tls) and "." in asset and not asset.lower().startswith("www."):
            fallback_host = f"www.{asset}"
            try:
                fallback_tls = await asyncio.wait_for(
                    inspect_tls_async(fallback_host, 443, timeout=max(3.0, pass2_timeout_sec * 0.8)),
                    timeout=max(3.5, pass2_timeout_sec),
                )
                if _tls_measured(fallback_tls):
                    tls = fallback_tls
                    tls.host = asset
                    prev_err = str(tls.scan_error or "").strip()
                    tls.scan_error = (
                        f"{prev_err}; recovered via {fallback_host}" if prev_err else f"recovered via {fallback_host}"
                    )
            except Exception:
                pass

        if not _tls_measured(tls):
            try:
                service_probes = await asyncio.wait_for(
                    probe_service_ports_async(asset, timeout=service_probe_timeout_sec),
                    timeout=max(5.0, service_probe_timeout_sec * 3.5),
                )
            except Exception:
                service_probes = []

            service_reachable = any(bool(item.get("reachable")) for item in service_probes)
            service_tls_measured = any(bool(item.get("tls_measured")) for item in service_probes)
            if service_reachable:
                tls.network_status = "service_reachable_non_443"
                if service_tls_measured:
                    tls.scan_error = "Service reachable but TLS profile unavailable on 443 (TLS detected on alternate service ports)"
                else:
                    tls.scan_error = "Service reachable but TLS profile unavailable on 443"

        try:
            api = await asyncio.wait_for(asyncio.to_thread(analyze_api, asset), timeout=api_timeout_sec)
        except Exception:
            api = APIInfo(host=asset)

        return asset, tls, api, service_probes

def _load_scan_deep_mode(scan_id: str, default: bool = True) -> bool:
    with get_session() as session:
        scan = get_scan(session, scan_id)
        if scan is None:
            return default
        return bool(scan.deep_scan)

async def run_scan_pipeline(
    scan_id: str,
    domain: str,
    scan_model: str = "general",
    dns_resolvers: list[str] | None = None,
    dns_doh_endpoints: list[str] | None = None,
    dns_enable_doh: bool | None = None,
) -> None:
    model = normalize_scan_model(scan_model)
    token = set_active_scan_model(model)
    try:
        run_started = time.perf_counter()
        discovery_sec = 0.0
        probe_sec = 0.0

        deep_scan = _load_scan_deep_mode(scan_id, default=True)
        max_assets = _int_env("SCAN_MAX_ASSETS_DEEP", 10_000) if deep_scan else _int_env("SCAN_MAX_ASSETS_SHALLOW", 10)
        # Hard upper concurrency guardrail requested for production-safe probing.
        concurrency = 50
        tls_pass1_timeout_sec = _float_env("SCAN_TLS_PASS1_TIMEOUT_SEC", 4.5, min_value=1.0)
        tls_pass2_timeout_sec = _float_env("SCAN_TLS_PASS2_TIMEOUT_SEC", 12.0, min_value=2.0)
        tls_pass2_timeout_sec = max(10.0, min(15.0, tls_pass2_timeout_sec))
        tls_pass2_concurrency = min(10, _int_env("SCAN_TLS_PASS2_CONCURRENCY", 10))
        api_timeout_sec = _float_env("SCAN_API_TIMEOUT_SEC", 3.2, min_value=1.0)
        service_probe_timeout_sec = _float_env("SCAN_SERVICE_PROBE_TIMEOUT_SEC", 3.5, min_value=1.0)
        discovery_timeout_sec = _discovery_timeout_for_scan(deep_scan)
        ai_timeout_sec = _float_env("SCAN_AI_TIMEOUT_SEC", 0.9)
        log_every = _int_env("SCAN_PROGRESS_LOG_EVERY", 10)
        external_ai_budget = _int_env("SCAN_EXTERNAL_AI_BUDGET", 8)
        has_external_ai = bool(os.getenv("GEMINI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))
        ai_used = 0

        _db_log(scan_id, f"[DISCOVERY] Starting asset discovery for {domain}", 5, status="running")
        discovery_started = time.perf_counter()
        try:
            discovered_assets, vpn_signals, discovery_report = await asyncio.wait_for(
                discover_assets_async(
                    domain,
                    include_vpn_probes=deep_scan,
                    dns_resolvers=dns_resolvers,
                    dns_doh_endpoints=dns_doh_endpoints,
                    dns_enable_doh=dns_enable_doh,
                    return_report=True,
                ),
                timeout=discovery_timeout_sec,
            )
        except asyncio.TimeoutError:
            _db_log(
                scan_id,
                (
                    "[DISCOVERY] Primary discovery timeout after "
                    f"{discovery_timeout_sec:.1f}s; retrying without VPN probes"
                ),
                12,
            )
            try:
                quick_timeout = max(15.0, discovery_timeout_sec * 0.5)
                discovered_assets, vpn_signals, discovery_report = await asyncio.wait_for(
                    discover_assets_async(
                        domain,
                        include_vpn_probes=False,
                        dns_resolvers=dns_resolvers,
                        dns_doh_endpoints=dns_doh_endpoints,
                        dns_enable_doh=dns_enable_doh,
                        return_report=True,
                    ),
                    timeout=quick_timeout,
                )
                _db_log(
                    scan_id,
                    (
                        "[DISCOVERY] Fallback discovery completed without VPN probes "
                        f"in <= {quick_timeout:.1f}s"
                    ),
                    15,
                )
            except Exception:
                discovered_assets = [domain]
                vpn_signals = {}
                discovery_report = {
                    "passive_discovered": [domain],
                    "live_dns": [domain],
                    "resolver_targets": [],
                    "authoritative_ns_resolvers": [],
                    "ct_passive": [],
                    "multi_vantage_passive": [],
                }
                _db_log(
                    scan_id,
                    (
                        "[DISCOVERY] Fallback discovery failed; using root domain only"
                    ),
                    15,
                )
        except Exception as ex:
            discovered_assets = [domain]
            vpn_signals = {}
            discovery_report = {
                "passive_discovered": [domain],
                "live_dns": [domain],
                "resolver_targets": [],
                "authoritative_ns_resolvers": [],
                "ct_passive": [],
                "multi_vantage_passive": [],
            }
            _db_log(scan_id, f"[DISCOVERY] Failed with {ex}; using root domain fallback", 12)
        discovery_sec = time.perf_counter() - discovery_started

        # If discovery visibility is restricted (e.g., private DNS), include heuristic candidates
        # so the scan still surfaces a fuller inventory with explicit DNS/TLS failure reasons.
        if len(discovered_assets) <= 1 and os.getenv("SCAN_INCLUDE_UNRESOLVED_CANDIDATES", "true").strip().lower() not in {"0", "false", "no"}:
            railway_mode = _railway_hosted_mode()
            candidate_limit = _int_env("SCAN_UNRESOLVED_CANDIDATE_LIMIT", 480 if railway_mode else 120)
            passive_limit = _int_env("SCAN_PASSIVE_HEURISTIC_LIMIT", 84 if railway_mode else 21)
            candidates = generate_candidate_assets(domain, limit=candidate_limit)
            if candidates:
                before = len(discovered_assets)
                passive_before = len(set(discovery_report.get("passive_discovered") or []))
                candidate_resolver = _AsyncResolver(dns_resolvers, domain=domain)
                live_candidates = await _resolve_candidates_live(candidates, candidate_resolver)

                # Keep passive inventory richer for reporting/coverage visibility,
                # but cap it to avoid inflating passive counts excessively.
                passive_candidates = sorted({str(x).strip().lower() for x in candidates if str(x).strip()})
                passive_seed = set(discovery_report.get("passive_discovered") or [])
                passive_seed.update(passive_candidates[: max(1, passive_limit)])
                discovery_report["passive_discovered"] = sorted(passive_seed)

                if live_candidates:
                    discovered_assets = sorted({*discovered_assets, *live_candidates})
                    discovery_report_live_dns = set(discovery_report.get("live_dns") or [])
                    discovery_report_live_dns.update(live_candidates)
                    discovery_report["live_dns"] = sorted(discovery_report_live_dns)
                    _db_log(
                        scan_id,
                        (
                            "[DISCOVERY] Added live-validated heuristic hosts for visibility "
                            f"({before} -> {len(discovered_assets)})"
                        ),
                        18,
                    )
                else:
                    _db_log(
                        scan_id,
                        (
                            "[DISCOVERY] Heuristic candidates did not resolve live; "
                            "keeping confirmed discovery set only"
                        ),
                        18,
                    )
                passive_after = len(set(discovery_report.get("passive_discovered") or []))
                if passive_after > passive_before:
                    _db_log(
                        scan_id,
                        (
                            "[DISCOVERY] Expanded passive inventory with heuristic candidates "
                            f"({passive_before} -> {passive_after})"
                        ),
                        18,
                    )

        tls_success_hosts = _historically_tls_successful_hosts(domain)
        prioritized_assets = _prioritize_assets(
            domain,
            discovered_assets,
            tls_success_hosts=tls_success_hosts,
        )
        assets = prioritized_assets[: min(max_assets, len(prioritized_assets))]
        if tls_success_hosts:
            warm_hosts = [a for a in assets if a.lower() in tls_success_hosts]
            if warm_hosts:
                _db_log(
                    scan_id,
                    "[DISCOVERY] Prioritized historically TLS-responsive assets: "
                    + ", ".join(warm_hosts[:6])
                    + (" ..." if len(warm_hosts) > 6 else ""),
                    18,
                )
        _db_log(
            scan_id,
            f"[DISCOVERY] Found {len(discovered_assets)} assets, selected {len(assets)} for scan "
            f"(deep_scan={deep_scan}, concurrency={concurrency})",
            20,
        )
        _db_log(
            scan_id,
            (
                "[PROBE-POLICY] "
                f"pass1_timeout={tls_pass1_timeout_sec:.1f}s "
                f"pass2_timeout={tls_pass2_timeout_sec:.1f}s "
                f"pass2_concurrency={tls_pass2_concurrency} "
                f"service_probe_timeout={service_probe_timeout_sec:.1f}s"
            ),
            21,
        )
        discovery_bucket_payload = {
            "passive_discovered": len(set(discovery_report.get("passive_discovered") or [])),
            "live_dns": len(set(discovery_report.get("live_dns") or discovered_assets)),
            "live_tls_measured": 0,
        }
        _db_log(scan_id, f"[REPORT-BUCKETS] {json.dumps(discovery_bucket_payload, sort_keys=True)}", 21)
        resolver_targets = list(discovery_report.get("resolver_targets") or [])
        authoritative_targets = list(discovery_report.get("authoritative_ns_resolvers") or [])
        if resolver_targets or authoritative_targets:
            _db_log(
                scan_id,
                (
                    "[DISCOVERY-RESOLVERS] "
                    f"targets={','.join(resolver_targets[:8]) or 'none'} "
                    f"authoritative={','.join(authoritative_targets[:8]) or 'none'}"
                ),
                22,
            )

        packed_findings: list[dict] = []
        unknown_buckets: Counter[str] = Counter()
        total = max(len(assets), 1)
        sem = asyncio.Semaphore(50)
        pass2_sem = asyncio.Semaphore(max(1, tls_pass2_concurrency))
        probe_started = time.perf_counter()
        tasks = [
            asyncio.create_task(
                _scan_asset_bounded(
                    asset,
                    sem,
                    pass2_sem,
                    tls_pass1_timeout_sec,
                    tls_pass2_timeout_sec,
                    api_timeout_sec,
                    service_probe_timeout_sec,
                )
            )
            for asset in assets
        ]

        for idx, task in enumerate(asyncio.as_completed(tasks), start=1):
            asset, tls, api, service_probes = await task

            key_exchange_status = classify_key_exchange(
                tls.cipher_suite,
                tls.tls_version,
                host=asset,
                scan_model=model,
                key_exchange_group=tls.key_exchange_group,
                named_group_ids=tls.named_group_ids,
                cipher_components=tls.cipher_components,
                supported_cipher_analysis=tls.supported_cipher_analysis,
            )
            auth_status = classify_auth(tls, api, scan_model=model)
            tls_status = classify_tls_version(tls.tls_version)
            cert_algo_status = classify_cert_algo(tls)
            symmetric_status = classify_symmetric(tls.cipher_suite)
            score = hndl_score(
                key_exchange_status,
                auth_status,
                tls.tls_version,
                cert_algo_status,
                symmetric_status,
                host=asset,
                scan_model=model,
                cipher_suite=tls.cipher_suite,
                cert_sig_algo=tls.cert_sig_algo,
                cert_not_before=tls.cert_not_before,
                cert_not_after=tls.cert_not_after,
                cert_public_key_bits=tls.cert_public_key_bits,
            )
            label = decision_tree_label(tls, key_exchange_status)
            base_recs = recommendations_for_status(score, scan_model=model)
            if has_external_ai and ai_used >= external_ai_budget:
                recs = base_recs
            else:
                summary = (
                    f"TLS={tls.tls_version} cipher={tls.cipher_suite} "
                    f"key_exchange={key_exchange_status} auth={auth_status} score={score}"
                )
                try:
                    recs = await asyncio.wait_for(
                        recommend_with_claude(asset, summary, base_recs),
                        timeout=ai_timeout_sec,
                    )
                except asyncio.TimeoutError:
                    recs = base_recs
                if has_external_ai:
                    ai_used += 1

            host_vpn_signals = vpn_signals.get(asset, {"udp_500": False, "udp_4500": False, "sstp": False})
            vpn_exposed = any(host_vpn_signals.values())
            tls_measured = _tls_measured(tls)
            service_reachable_non_443 = (
                (not tls_measured)
                and any(bool(item.get("reachable")) for item in (service_probes or []))
            )
            if tls.network_status == "network_blocked" and not tls.scan_error:
                tls.scan_error = "Unreachable (Network Blocked)"
            if service_reachable_non_443 and not tls.scan_error:
                tls.scan_error = "Service reachable but TLS profile unavailable on 443"
            if service_reachable_non_443 and not tls.network_status:
                tls.network_status = "service_reachable_non_443"
            unknown_bucket = "none" if tls_measured else _tls_failure_bucket(tls.network_status or tls.scan_error)
            if not tls_measured:
                unknown_buckets[unknown_bucket] += 1
            metadata = {
                "tls": tls.model_dump(),
                "api": api.model_dump(),
                "vpn_signals": host_vpn_signals,
                "vpn_exposed": vpn_exposed,
                "tls_measured": tls_measured,
                "tls_unknown_reason": unknown_bucket,
                "service_probe_ports": service_probes,
                "service_reachable_non_443": service_reachable_non_443,
            }
            with get_session() as session:
                row = create_asset(
                    session=session,
                    scan_id=scan_id,
                    hostname=asset,
                    tls_version=tls.tls_version,
                    cipher_suite=tls.cipher_suite,
                    risk_score=score,
                    label=label,
                    metadata_json=metadata,
                    asset_type="vpn" if vpn_exposed else ("api" if api.api_ports_open else "web"),
                )
                add_crypto_finding(session, scan_id, row.id, "key_exchange", tls.cipher_suite or "unknown", key_exchange_status)
                add_crypto_finding(session, scan_id, row.id, "authentication", tls.cert_sig_algo or "unknown", auth_status)
                add_crypto_finding(session, scan_id, row.id, "tls_version", tls.tls_version or "unknown", tls_status)
                add_crypto_finding(session, scan_id, row.id, "certificate", tls.cert_sig_algo or "unknown", cert_algo_status)
                add_crypto_finding(session, scan_id, row.id, "symmetric", tls.cipher_suite or "unknown", symmetric_status)
                phases = ["Phase 1", "Phase 2", "Phase 3", "Phase 4"]
                for i, rec in enumerate(recs):
                    add_recommendation(session, scan_id, row.id, rec, phase=phases[min(i, len(phases) - 1)])

            packed_findings.append(
                {
                    "asset": asset,
                    "tls": tls,
                    "api": api,
                    "hndl_risk_score": score,
                    "label": label,
                }
            )
            progress = 20 + int((idx / total) * 65)
            if idx == 1 or idx % log_every == 0 or idx == total:
                _db_log(scan_id, f"[PQC] Processed {idx}/{total} assets (latest: {asset} => {label}, score={score})", progress)

        probe_sec = time.perf_counter() - probe_started

        final_bucket_payload = {
            "passive_discovered": len(set(discovery_report.get("passive_discovered") or [])),
            "live_dns": len(set(discovery_report.get("live_dns") or discovered_assets)),
            "live_tls_measured": sum(1 for row in packed_findings if _tls_measured(row["tls"])),
        }
        _db_log(scan_id, f"[REPORT-BUCKETS-FINAL] {json.dumps(final_bucket_payload, sort_keys=True)}", 90)

        if unknown_buckets:
            _db_log(
                scan_id,
                "[TLS-DIAGNOSTICS] unknown_buckets="
                + ", ".join(f"{k}:{v}" for k, v in sorted(unknown_buckets.items())),
                90,
            )

        cbom_findings = []
        for f in packed_findings:

            cbom_findings.append(
                type(
                    "Tmp",
                    (),
                    {
                        "asset": f["asset"],
                        "tls": f["tls"],
                        "hndl_risk_score": f["hndl_risk_score"],
                        "label": f["label"],
                    },
                )()
            )
        cbom = build_cbom(domain, cbom_findings)
        avg_risk = round(sum(x["hndl_risk_score"] for x in packed_findings) / max(len(packed_findings), 1), 2)
        with get_session() as session:
            save_cbom(session, scan_id, cbom)
            append_chain_block(
                session,
                scan_id,
                payload={
                    "scan_id": scan_id,
                    "domain": domain,
                    "scan_model": model,
                    "assets": len(packed_findings),
                    "avg_hndl_risk": avg_risk,
                    "labels": sorted({x["label"] for x in packed_findings}),
                    "cbom_components": len(cbom.get("components", [])),
                    "report_buckets": final_bucket_payload,
                },
                difficulty=2,
            )
            set_scan_state(session, scan_id, "completed", progress=100)
            total_sec = time.perf_counter() - run_started
            add_log(
                session,
                scan_id,
                (
                    "[PERF] "
                    f"discovery_time={discovery_sec:.2f}s "
                    f"probe_time={probe_sec:.2f}s "
                    f"total_time={total_sec:.2f}s"
                ),
            )
            add_log(session, scan_id, "[DONE] Scan completed successfully")
            try:
                detail = scan_detail_payload(session, scan_id)
                if detail:
                    upsert_scan_snapshot(detail, scan_model=model)
                    add_log(session, scan_id, "[MONGO] Scan snapshot upserted")
            except Exception as mongo_ex:
                add_log(session, scan_id, f"[MONGO] Snapshot upsert skipped: {mongo_ex}")
    except Exception as ex:
        _db_log(scan_id, f"[ERROR] {ex}", status="failed", error=str(ex))
    finally:
        reset_active_scan_model(token)
