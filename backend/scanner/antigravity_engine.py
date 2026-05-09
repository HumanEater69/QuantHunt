"""
QuantHunt Antigravity Discovery Engine — Stages 10-11

Surfaces hidden assets via Google dorking, hosting provider metadata,
and certificate transparency intelligence. Feeds HNDL v2 recalibration.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus, urlparse

import aiohttp

try:
    import aiodns
except ImportError:
    aiodns = None

try:
    from cryptography import x509 as cx509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    cx509 = None

logger = logging.getLogger("quanthunt.antigravity")

# ── Constants ─────────────────────────────────────────────
SEARCH_TIMEOUT = 12.0
SEARCH_CONCURRENCY = 6
TLS_PROBE_TIMEOUT = 4.0
TLS_PROBE_CONCURRENCY = 60
RDNS_CONCURRENCY = 80
CYMRU_WHOIS = "whois.cymru.com"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

CAPTCHA_SIGNALS = ("captcha", "recaptcha", "unusual traffic", "verify you are human")

# ASN risk tier mapping (Step 2a)
ASN_RISK_MAP: Dict[str, Tuple[str, float]] = {
    "NIC INDIA": ("HIGH", 1.0), "BSNL": ("HIGH", 1.0), "SBI": ("HIGH", 1.0),
    "RBI": ("HIGH", 1.0), "NPCI": ("HIGH", 1.0), "NICSI": ("HIGH", 1.0),
    "AWS": ("MEDIUM", 0.7), "AMAZON": ("MEDIUM", 0.7), "GOOGLE": ("MEDIUM", 0.7),
    "GCP": ("MEDIUM", 0.7), "AZURE": ("MEDIUM", 0.7), "MICROSOFT": ("MEDIUM", 0.7),
    "CLOUDFLARE": ("MEDIUM", 0.7), "AKAMAI": ("LOW", 0.5), "FASTLY": ("LOW", 0.5),
}


# ── Data Classes ──────────────────────────────────────────
@dataclass
class DiscoveredAsset:
    """Output format per the spec: one discovered asset."""
    asset_url: str
    hostname: str = ""
    discovery_source: str = "google_dork"  # google_dork | ct_log | reverse_ip
    first_seen_date: str = ""
    hosting_provider: str = ""
    asn: str = ""
    asn_risk_tier: str = "MEDIUM"
    asn_risk_factor: float = 0.7
    tls_fingerprint: str = "unknown"
    tls_version: str = ""
    cipher_suite: str = ""
    is_pqc: bool = False
    hndl_harvest_window_days: int = 0
    priority_scan_flag: bool = False
    sensitivity: str = "normal"  # normal | exposed_config | dev_server | leaked_cred
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_url": self.asset_url,
            "hostname": self.hostname,
            "discovery_source": self.discovery_source,
            "first_seen_date": self.first_seen_date,
            "hosting_provider": self.hosting_provider,
            "asn": self.asn,
            "asn_risk_tier": self.asn_risk_tier,
            "asn_risk_factor": self.asn_risk_factor,
            "tls_fingerprint": self.tls_fingerprint,
            "hndl_harvest_window_days": self.hndl_harvest_window_days,
            "priority_scan_flag": self.priority_scan_flag,
            "sensitivity": self.sensitivity,
            "verified": self.verified,
        }


@dataclass
class AntigravityReport:
    """Full Stage 10-11 output."""
    target_domain: str
    discovered_assets: List[DiscoveredAsset] = field(default_factory=list)
    discovered_subdomains: Set[str] = field(default_factory=set)
    # Penalty buckets
    exposed_env_files: int = 0
    exposed_dev_servers: int = 0
    exposed_certs_keys: int = 0
    # Infrastructure
    bgp_prefixes: Set[str] = field(default_factory=set)
    asn_infos: List[Dict[str, str]] = field(default_factory=list)
    cloud_provider: str = ""
    tls_modern_count: int = 0
    tls_legacy_count: int = 0
    pqc_detected_count: int = 0
    # Metrics
    total_queries: int = 0
    captcha_blocks: int = 0
    elapsed_seconds: float = 0.0

    @property
    def modern_tls_ratio(self) -> float:
        total = self.tls_modern_count + self.tls_legacy_count
        return self.tls_modern_count / max(total, 1)

    @property
    def env_penalty(self) -> float:
        return min(40.0, self.exposed_env_files * 8.0)

    @property
    def dev_penalty(self) -> float:
        return min(30.0, self.exposed_dev_servers * 5.0)

    @property
    def cred_penalty(self) -> float:
        return min(48.0, self.exposed_certs_keys * 12.0)

    @property
    def total_search_penalty(self) -> float:
        return self.env_penalty + self.dev_penalty + self.cred_penalty

    @property
    def infrastructure_reward(self) -> float:
        r = self.modern_tls_ratio
        if r >= 0.99: return -20.0
        if r >= 0.95: return -15.0
        if r >= 0.90: return -10.0
        if r >= 0.80: return -5.0
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "discovered_assets": [a.to_dict() for a in self.discovered_assets],
            "discovered_subdomains": sorted(self.discovered_subdomains),
            "penalty_summary": {
                "exposed_env_files": self.exposed_env_files,
                "exposed_dev_servers": self.exposed_dev_servers,
                "exposed_certs_keys": self.exposed_certs_keys,
                "env_penalty": self.env_penalty,
                "dev_penalty": self.dev_penalty,
                "cred_penalty": self.cred_penalty,
                "total_search_penalty": self.total_search_penalty,
            },
            "infrastructure": {
                "bgp_prefixes": sorted(self.bgp_prefixes),
                "cloud_provider": self.cloud_provider,
                "tls_modern_count": self.tls_modern_count,
                "tls_legacy_count": self.tls_legacy_count,
                "pqc_detected_count": self.pqc_detected_count,
                "modern_tls_ratio": round(self.modern_tls_ratio, 4),
                "infrastructure_reward": self.infrastructure_reward,
            },
            "metrics": {
                "total_queries": self.total_queries,
                "captcha_blocks": self.captcha_blocks,
                "elapsed_seconds": round(self.elapsed_seconds, 2),
            },
        }


# ── Main Orchestrator ─────────────────────────────────────
class AntigravityEngine:
    """
    Stage 10-11 entry point. Previously orchestrated Google dorking + hosting
    enumeration. Now deprecated as discovery is natively handled by 
    SearchIntelligenceBridge and InfrastructureExpander at Stage 1.
    """

    async def execute(self, target_domain: str, seed_ips: List[str] | None = None) -> AntigravityReport:
        logger.info(
            f"[ANTIGRAVITY] Skipping redundant discovery for {target_domain}. "
            "Discovery is now natively handled by pipeline core via SearchIntelligenceBridge and InfrastructureExpander."
        )
        return AntigravityReport(target_domain=target_domain.lower().strip())
