import re

with open("backend/scanner/pipeline.py", "r") as f:
    content = f.read()

# 1. Add ag_report = None
content = content.replace(
    '        ai_used = 0\n\n        _db_log(scan_id, f"[DISCOVERY]',
    '        ai_used = 0\n        ag_report = None\n\n        _db_log(scan_id, f"[DISCOVERY]'
)

# 2. Run Antigravity Discovery before prioritizations
antigravity_discovery_code = """
        # ── Stage 10: Antigravity Discovery (Google Dorking + Infra) ──
        if _ANTIGRAVITY_AVAILABLE and deep_scan:
            try:
                _db_log(scan_id, "[ANTIGRAVITY] Starting Stage 10 Web-enhanced discovery...", 18)
                ag_engine = AntigravityEngine()
                ag_report = await ag_engine.execute(domain)
                if ag_report and ag_report.discovered_subdomains:
                    ag_hosts = list(ag_report.discovered_subdomains)
                    before_ag = len(discovered_assets)
                    discovered_assets = sorted({*discovered_assets, *ag_hosts})
                    
                    # Update report buckets so metrics reflect these new assets
                    passive_set = set(discovery_report.get("passive_discovered") or [])
                    passive_set.update(ag_hosts)
                    discovery_report["passive_discovered"] = sorted(passive_set)
                    
                    live_set = set(discovery_report.get("live_dns") or [])
                    live_set.update(ag_hosts)
                    discovery_report["live_dns"] = sorted(live_set)

                    _db_log(
                        scan_id,
                        f"[ANTIGRAVITY] Expanded asset pool via OSINT ({before_ag} -> {len(discovered_assets)} assets)",
                        19,
                    )
            except Exception as ag_ex:
                _db_log(scan_id, f"[ANTIGRAVITY] Discovery skipped: {ag_ex}", 19)

        tls_success_hosts = _historically_tls_successful_hosts(domain)"""

content = content.replace(
    '        tls_success_hosts = _historically_tls_successful_hosts(domain)',
    antigravity_discovery_code
)

# 3. Change the end to only do recalibration
old_recalibration = """        # ── Stage 10-11: Antigravity Discovery + HNDL v2 Recalibration ──
        antigravity_summary = None
        if _ANTIGRAVITY_AVAILABLE:
            try:
                _db_log(scan_id, "[ANTIGRAVITY] Stage 10-11: Web-enhanced discovery starting", 92)
                ag_engine = AntigravityEngine()
                ag_report = await ag_engine.execute(domain)
                hndl_v2 = HNDLv2RecalibrationEngine()
                antigravity_summary = hndl_v2.recalibrate_domain(
                    domain=domain,
                    baseline_assets=packed_findings,
                    antigravity_report=ag_report,
                )
                _db_log(
                    scan_id,
                    f"[ANTIGRAVITY] Stage 10-11 complete: "
                    f"baseline_avg={antigravity_summary.domain_hndl_baseline_avg:.2f} → "
                    f"v2_avg={antigravity_summary.domain_hndl_v2_avg:.2f} "
                    f"(Δ={antigravity_summary.domain_hndl_delta:+.2f}), "
                    f"new_assets={antigravity_summary.net_new_asset_count}, "
                    f"confidence={antigravity_summary.antigravity_confidence_score}",
                    93,
                )
            except Exception as ag_ex:
                _db_log(scan_id, f"[ANTIGRAVITY] Stage 10-11 skipped: {ag_ex}", 93)"""

new_recalibration = """        # ── Stage 11: HNDL v2 Recalibration ──
        antigravity_summary = None
        if _ANTIGRAVITY_AVAILABLE:
            try:
                _db_log(scan_id, "[ANTIGRAVITY] Stage 11: HNDL v2 Recalibration starting", 92)
                hndl_v2 = HNDLv2RecalibrationEngine()
                antigravity_summary = hndl_v2.recalibrate_domain(
                    domain=domain,
                    baseline_assets=packed_findings,
                    antigravity_report=ag_report,
                )
                _db_log(
                    scan_id,
                    f"[ANTIGRAVITY] Stage 11 complete: "
                    f"baseline_avg={antigravity_summary.domain_hndl_baseline_avg:.2f} → "
                    f"v2_avg={antigravity_summary.domain_hndl_v2_avg:.2f} "
                    f"(Δ={antigravity_summary.domain_hndl_delta:+.2f}), "
                    f"new_assets={antigravity_summary.net_new_asset_count}, "
                    f"confidence={antigravity_summary.antigravity_confidence_score}",
                    93,
                )
            except Exception as ag_ex:
                _db_log(scan_id, f"[ANTIGRAVITY] Stage 11 skipped: {ag_ex}", 93)"""

content = content.replace(old_recalibration, new_recalibration)

with open("backend/scanner/pipeline.py", "w") as f:
    f.write(content)

print("Patched successfully!")
