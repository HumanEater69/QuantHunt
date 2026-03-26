from __future__ import annotations

import asyncio
import os
import time

from ..crud import (
    add_crypto_finding,
    add_log,
    add_recommendation,
    append_chain_block,
    create_asset,
    get_scan,
    save_cbom,
    set_scan_state,
)
from ..db import get_session, normalize_scan_model, reset_active_scan_model, set_active_scan_model
from ..models import APIInfo, TLSInfo
from .api_analyzer import analyze_api
from .ai_recommender import recommend_with_claude
from .asset_discovery import discover_assets_with_vpn_signals
from .cbom_generator import build_cbom
from .pqc_engine import (
    classify_auth,
    classify_cert_algo,
    classify_key_exchange,
    classify_symmetric,
    classify_tls_version,
    hndl_score,
    label_for_score,
    recommendations_for_status,
)
from .tls_inspector import inspect_tls

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

def _prioritize_assets(domain: str, assets: list[str]) -> list[str]:
    def score(host: str) -> tuple[int, int, str]:
        h = host.lower()
        if h == domain:
            return (0, len(h), h)
        if h.startswith("api.") or ".api." in h:
            return (1, len(h), h)
        if h.startswith("www.") or ".www." in h:
            return (2, len(h), h)
        if any(x in h for x in ("vpn", "gateway", "secure", "admin", "auth")):
            return (3, len(h), h)
        return (4, len(h), h)

    return sorted(assets, key=score)

def _db_log(scan_id: str, message: str, progress: int | None = None, status: str | None = None, error: str | None = None) -> None:
    with get_session() as session:
        add_log(session, scan_id, message)
        if progress is not None or status is not None or error is not None:
            current_status = status or "running"
            set_scan_state(session, scan_id, current_status, progress=progress, error=error)

async def _scan_asset(asset: str) -> tuple[TLSInfo, APIInfo]:
    tls_task = asyncio.to_thread(inspect_tls, asset, 443)
    api_task = asyncio.to_thread(analyze_api, asset)
    return await asyncio.gather(tls_task, api_task)

async def _scan_asset_bounded(asset: str, sem: asyncio.Semaphore, timeout_sec: float) -> tuple[str, TLSInfo, APIInfo]:
    async with sem:
        try:
            tls, api = await asyncio.wait_for(_scan_asset(asset), timeout=timeout_sec)
            return asset, tls, api
        except asyncio.TimeoutError:
            return asset, TLSInfo(host=asset, scan_error="scan timeout"), APIInfo(host=asset)
        except Exception as ex:
            return asset, TLSInfo(host=asset, scan_error=str(ex)), APIInfo(host=asset)

def _load_scan_deep_mode(scan_id: str, default: bool = True) -> bool:
    with get_session() as session:
        scan = get_scan(session, scan_id)
        if scan is None:
            return default
        return bool(scan.deep_scan)

async def run_scan_pipeline(scan_id: str, domain: str, scan_model: str = "general") -> None:
    model = normalize_scan_model(scan_model)
    token = set_active_scan_model(model)
    try:
        run_started = time.perf_counter()
        discovery_sec = 0.0
        probe_sec = 0.0

        deep_scan = _load_scan_deep_mode(scan_id, default=True)
        max_assets = _int_env("SCAN_MAX_ASSETS_DEEP", 120) if deep_scan else _int_env("SCAN_MAX_ASSETS_SHALLOW", 40)
        concurrency = _int_env("SCAN_CONCURRENCY_DEEP", 20) if deep_scan else _int_env("SCAN_CONCURRENCY_SHALLOW", 10)
        asset_timeout_sec = _float_env("SCAN_ASSET_TIMEOUT_SEC", 12.0)
        ai_timeout_sec = _float_env("SCAN_AI_TIMEOUT_SEC", 2.2)
        log_every = _int_env("SCAN_PROGRESS_LOG_EVERY", 10)
        external_ai_budget = _int_env("SCAN_EXTERNAL_AI_BUDGET", 20)
        has_external_ai = bool(os.getenv("GEMINI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))
        ai_used = 0

        _db_log(scan_id, f"[DISCOVERY] Starting asset discovery for {domain}", 5, status="running")
        discovery_started = time.perf_counter()
        discovered_assets, vpn_signals = await asyncio.to_thread(discover_assets_with_vpn_signals, domain)
        discovery_sec = time.perf_counter() - discovery_started
        prioritized_assets = _prioritize_assets(domain, discovered_assets)
        assets = prioritized_assets[:max_assets]
        _db_log(
            scan_id,
            f"[DISCOVERY] Found {len(discovered_assets)} assets, selected {len(assets)} for scan "
            f"(deep_scan={deep_scan}, concurrency={concurrency})",
            20,
        )

        packed_findings: list[dict] = []
        total = max(len(assets), 1)
        sem = asyncio.Semaphore(concurrency)
        probe_started = time.perf_counter()
        tasks = [
            asyncio.create_task(_scan_asset_bounded(asset, sem, asset_timeout_sec))
            for asset in assets
        ]

        for idx, task in enumerate(asyncio.as_completed(tasks), start=1):
            asset, tls, api = await task

            key_exchange_status = classify_key_exchange(
                tls.cipher_suite,
                tls.tls_version,
                host=asset,
                scan_model=model,
            )
            auth_status = classify_auth(tls, api, scan_model=model)
            tls_status = classify_tls_version(tls.tls_version)
            cert_algo_status = classify_cert_algo(tls)
            symmetric_status = classify_symmetric(tls.cipher_suite)
            score = hndl_score(
                key_exchange_status,
                auth_status,
                tls_status,
                cert_algo_status,
                symmetric_status,
                host=asset,
                scan_model=model,
            )
            label = label_for_score(score, scan_model=model)
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
            metadata = {
                "tls": tls.model_dump(),
                "api": api.model_dump(),
                "vpn_signals": host_vpn_signals,
                "vpn_exposed": vpn_exposed,
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
    except Exception as ex:
        _db_log(scan_id, f"[ERROR] {ex}", status="failed", error=str(ex))
    finally:
        reset_active_scan_model(token)
