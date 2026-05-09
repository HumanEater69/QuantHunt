"""
QuantHunt Core Engine Integration Layer

Bridges the production-grade QuantHunt core engine with the existing
QuantHunt scanner pipeline for enhanced asset discovery and PQC posture assessment.
"""

import asyncio
import logging
from typing import Dict, List, Set, Any, Optional

try:
    from .quanthunt_engine_v2 import run_quanthunt_scan
    from .quanthunt_connector import PQCAssetData
except ImportError:
    from .quanthunt_core import run_quanthunt_scan, PQCAssetData  # type: ignore[assignment]

from .quanthunt_core import logger as core_logger

logger = logging.getLogger("quanthunt.integration")

class QuantHuntScannerBridge:
    """Bridge between core engine and pipeline for seamless integration."""
    
    @staticmethod
    async def discover_and_harvest(
        domain: str,
        timeout_sec: float = 120.0,
        include_tls: bool = True
    ) -> Dict[str, Any]:
        """
        Run integrated QuantHunt scan (discovery + TLS harvesting).
        
        Args:
            domain: Target domain
            timeout_sec: Maximum scan duration
            include_tls: Whether to perform TLS analysis
            
        Returns:
            {
                "hostnames": Set[str],
                "assets": List[PQCAssetData],
                "scan_result": Dict,
                "metrics": Dict
            }
        """
        try:
            logger.info(f"[BRIDGE] Starting integrated scan on {domain}")
            result = await asyncio.wait_for(
                run_quanthunt_scan(domain),
                timeout=timeout_sec
            )

            summary = result.get("summary") or {}
            internet_hostnames_tested = int(summary.get("total_hostnames_tested") or 0)
            resolved_hostnames = int(summary.get("resolved_hostnames_tested") or 0)
            
            # Extract hostnames from pqc_raw_data and metrics
            hostnames: Set[str] = {domain}
            assets: List[Any] = []
            
            if result.get("pqc_raw_data"):
                for asset_dict in result["pqc_raw_data"]:
                    hostnames.add(asset_dict.get("hostname", domain))
                    assets.append(asset_dict)
            
            logger.info(
                f"[BRIDGE] Scan complete. Discovered {len(hostnames)} unique hostnames, "
                f"{len(assets)} with TLS analysis"
            )
            
            return {
                "hostnames": hostnames,
                "assets": assets,
                "scan_result": result,
                "metrics": {
                    **(result.get("metrics", {}) or {}),
                    "internet_hostnames_tested": internet_hostnames_tested,
                    "resolved_hostnames_tested": resolved_hostnames,
                },
                "internet_candidates": result.get("internet_candidates", []),
                "internet_hostnames_tested": internet_hostnames_tested,
                "resolved_hostnames_tested": resolved_hostnames,
                "success": True
            }
            
        except asyncio.TimeoutError:
            logger.error(f"[BRIDGE] Scan timeout after {timeout_sec}s on {domain}")
            return {
                "hostnames": {domain},
                "assets": [],
                "scan_result": None,
                "metrics": {},
                "success": False,
                "error": "timeout"
            }
        except Exception as e:
            logger.error(f"[BRIDGE] Integration error: {e}", exc_info=True)
            return {
                "hostnames": {domain},
                "assets": [],
                "scan_result": None,
                "metrics": {},
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def merge_with_existing_discovery(
        existing_assets: List[str],
        quanthunt_result: Dict[str, Any]
    ) -> tuple[List[str], Dict[str, Any]]:
        """Merge QuantHunt discovery results with existing asset discovery."""
        merged = set(existing_assets)
        merged.update(quanthunt_result.get("hostnames", set()))
        
        metadata = {
            "quanthunt_hostnames": len(quanthunt_result.get("hostnames", set())),
            "quanthunt_tls_assets": len(quanthunt_result.get("assets", [])),
            "existing_count": len(existing_assets),
            "merged_count": len(merged),
            "new_discoveries": len(merged) - len(existing_assets),
            "internet_hostnames_tested": int(quanthunt_result.get("internet_hostnames_tested") or 0),
            "resolved_hostnames_tested": int(quanthunt_result.get("resolved_hostnames_tested") or 0),
            "internet_candidates": list(quanthunt_result.get("internet_candidates", []) or []),
            "metrics": quanthunt_result.get("metrics", {}),
            "success": quanthunt_result.get("success", False)
        }
        
        return list(merged), metadata

async def integrate_quanthunt_discovery(
    domain: str,
    existing_assets: List[str],
    timeout_sec: float = 120.0,
    enable_integration: bool = True
) -> tuple[List[str], Dict[str, Any]]:
    """
    Unified discovery: existing + QuantHunt core engine.
    """
    if not enable_integration:
        return existing_assets, {"quanthunt_enabled": False}
    
    bridge = QuantHuntScannerBridge()
    result = await bridge.discover_and_harvest(domain, timeout_sec=timeout_sec)
    merged, metadata = bridge.merge_with_existing_discovery(existing_assets, result)
    
    return merged, metadata
