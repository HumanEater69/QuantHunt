"""
QuantHunt Core Engine v2 — Production-Grade PQC & ASM Scanner.

Phase 5: Orchestration & Structured Output.
Wires Phases 1-4 into a single async scan function returning Supabase-ready JSON.

Usage:
    from backend.scanner.quanthunt_engine_v2 import run_quanthunt_scan
    result = await run_quanthunt_scan("example.com")
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Set

import aiohttp

from .quanthunt_connector import (
    MAX_CONCURRENT,
    AntiWafConnector,
    DomScraper,
    PQCAssetData,
    TlsHarvester,
)
from .quanthunt_resolver import DnsResolver, SubdomainMutator

logger = logging.getLogger("quanthunt.engine_v2")


async def run_quanthunt_scan(target_domain: str) -> Dict[str, Any]:
    """
    Execute a complete QuantHunt scan across all 5 phases.

    Returns a structured dict ready for Supabase JSONB storage with:
      - scan_id, target_domain, wildcard_detected
      - metrics (passive, generated, live counts)
      - pqc_raw_data (per-asset TLS/PQC posture)
    """
    # Normalize input
    target = (
        target_domain.strip().lower()
        .replace("https://", "").replace("http://", "")
        .split("/")[0].split(":")[0]
    )

    scan_id = str(uuid.uuid4())
    start = time.time()
    logger.info(f"[SCAN {scan_id}] Target: {target}")

    # Initialize components
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    connector = AntiWafConnector(semaphore)
    harvester = TlsHarvester()
    scraper = DomScraper(connector)
    resolver = DnsResolver()
    mutator = SubdomainMutator()

    passive_hosts: Set[str] = set()
    san_hosts: Set[str] = set()
    generated: Set[str] = set()
    live_assets: List[PQCAssetData] = []
    unique_ips: Set[str] = set()
    wildcard_detected = False

    try:
        # Phase 4.1: Wildcard Detection (run first to prime filter)
        logger.info(f"[SCAN {scan_id}] Phase 4.1: Wildcard detection")
        wildcard_detected = await resolver.detect_wildcard(target)

        async with aiohttp.ClientSession() as session:
            # Phase 2: Passive Discovery (SAN + DOM/JS scraping in parallel)
            logger.info(f"[SCAN {scan_id}] Phase 2: Passive discovery")
            san_task = harvester.harvest(target)
            crawl_task = scraper.scrape(session, target)
            san_result, crawl_result = await asyncio.gather(san_task, crawl_task)

            if san_result:
                san_hosts.update(san_result.sans)
                san_hosts.add(target)
            passive_hosts.update(crawl_result)

            # Phase 3: Mathematical Mutations
            logger.info(f"[SCAN {scan_id}] Phase 3: Generating mutations")
            generated = mutator.generate(target)

        # Aggregate all candidates
        all_candidates = passive_hosts | san_hosts | generated
        all_candidates.add(target)
        logger.info(
            f"[SCAN {scan_id}] Candidates: {len(passive_hosts)} passive, "
            f"{len(san_hosts)} SAN, {len(generated)} generated = "
            f"{len(all_candidates)} total"
        )

        # Phase 4.2: Mass DNS Resolution
        logger.info(f"[SCAN {scan_id}] Phase 4.2: DNS resolution ({len(all_candidates)} hosts)")
        resolved_map = await resolver.bulk_resolve(all_candidates)

        # Ensure target itself is included if resolvable
        if target not in resolved_map:
            target_ip = await resolver.resolve_host(target)
            if target_ip:
                resolved_map[target] = target_ip

        unique_ips = set(resolved_map.values())
        logger.info(
            f"[SCAN {scan_id}] Resolved {len(resolved_map)} live hosts "
            f"to {len(unique_ips)} unique IPs"
        )

        # Phase 2.2: TLS Harvesting on live assets
        logger.info(f"[SCAN {scan_id}] Phase 2.2: TLS harvesting")
        tls_sem = asyncio.Semaphore(100)

        async def _harvest(hostname: str) -> PQCAssetData | None:
            async with tls_sem:
                return await harvester.harvest(hostname)

        tls_tasks = [_harvest(h) for h in resolved_map]
        tls_results = await asyncio.gather(*tls_tasks)

        for hostname, tls_data in zip(resolved_map, tls_results):
            if tls_data:
                tls_data.hostname = hostname
                tls_data.ip = resolved_map[hostname]
                live_assets.append(tls_data)

    except Exception as exc:
        logger.error(f"[SCAN {scan_id}] Critical error: {exc}", exc_info=True)

    elapsed = time.time() - start
    service_reachable = sum(1 for a in live_assets if a.tls_version != "UNKNOWN")

    payload: Dict[str, Any] = {
        "scan_id": scan_id,
        "target_domain": target,
        "target": target,  # backward compat with old tests
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_duration_seconds": round(elapsed, 2),
        "wildcard_detected": wildcard_detected,
        "metrics": {
            "passive_discovered": len(passive_hosts | san_hosts),
            "mathematically_generated": len(generated),
            "total_candidates": len(passive_hosts | san_hosts | generated),
            "live_dns": len(resolved_map),
            "live_tls_measured": len(live_assets),
            "service_reachable_non_443": 0,
            "unique_ips": len(unique_ips),
            "waf_blocks_detected": connector.blocked_count,
            "dns_failures": resolver.failed_count,
        },
        "pqc_raw_data": [asdict(a) for a in live_assets],
        "pqc_posture_data": [asdict(a) for a in live_assets],  # backward compat
        "wildcard_sinkholes": sorted(resolver.wildcard_ips) if wildcard_detected else [],
        "summary": {
            "total_hostnames_tested": len(passive_hosts | san_hosts | generated),
            "resolved_hostnames_tested": len(resolved_map),
            "live_assets_with_tls": len(live_assets),
            "pqc_hybrid_detected": sum(1 for a in live_assets if a.is_pqc_hybrid),
        },
    }

    logger.info(
        f"[SCAN {scan_id}] Complete: {len(live_assets)} live assets in {elapsed:.2f}s"
    )
    return payload


# --- CLI entry point ---
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    domain = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(f"\n{'='*60}")
    print(f"[*] QuantHunt Engine v2 — PQC Scanner")
    print(f"[*] Target: {domain}")
    print(f"{'='*60}\n")

    try:
        result = asyncio.run(run_quanthunt_scan(domain))
        print(json.dumps(result, indent=2, default=str))
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
