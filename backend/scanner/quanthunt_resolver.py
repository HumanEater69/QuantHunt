"""
Phase 3: Mathematical Subdomain Mutator (combinatorial generator).
Phase 4: DNS Mass-Resolution with Wildcard Trap Detection.
"""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import string
import uuid
from typing import Dict, List, Optional, Set, Tuple

import aiodns

logger = logging.getLogger("quanthunt.resolver")

# --- Constants ---
DNS_CONCURRENCY = 500
DNS_TIMEOUT = 5.0

PREFIXES = [
    "dev", "stg", "uat", "prod", "sandbox", "test", "staging", "qa",
    "preprod", "beta", "demo", "lab", "internal", "corp", "old",
]
SERVICES = [
    "api", "mail", "vpn", "auth", "k8s", "git", "jenkins", "app",
    "db", "cache", "proxy", "vault", "identity", "admin", "backup",
    "storage", "queue", "worker", "kafka", "redis", "elastic",
    "grafana", "kibana", "metrics", "sso", "idp", "gateway",
    "cdn", "web", "secure", "portal", "mobile", "support",
]
REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1", "ap-south-1",
]
NUM_RANGE = 20  # 01..20


# --- Phase 3: Mathematical Mutator ---
class SubdomainMutator:
    """Generate mathematically permuted subdomains using combinatorics."""

    @staticmethod
    def generate(root_domain: str) -> Set[str]:
        mutations: Set[str] = set()
        root = root_domain.lower().strip()

        # Single-token patterns
        for p in PREFIXES:
            mutations.add(f"{p}.{root}")
        for s in SERVICES:
            mutations.add(f"{s}.{root}")

        # prefix-service combos
        for p in PREFIXES:
            for s in SERVICES:
                mutations.add(f"{p}-{s}.{root}")

        # service-region combos
        for s in SERVICES[:12]:
            for r in REGIONS:
                mutations.add(f"{s}-{r}.{root}")

        # prefix-service-region combos (capped to avoid explosion)
        for p in PREFIXES[:6]:
            for s in SERVICES[:8]:
                for r in REGIONS[:4]:
                    mutations.add(f"{p}-{s}-{r}.{root}")

        # Numeric increments
        for n in range(1, NUM_RANGE + 1):
            num = str(n).zfill(2)
            mutations.add(f"node{num}.{root}")
            mutations.add(f"server{num}.{root}")
            mutations.add(f"api-v{n}.{root}")
            mutations.add(f"v{n}.{root}")
            for p in PREFIXES[:5]:
                mutations.add(f"{p}-{num}.{root}")

        # Versioned API patterns
        for p in PREFIXES[:5]:
            for v in range(1, 4):
                mutations.add(f"{p}-api-v{v}.{root}")
                mutations.add(f"api-v{v}-{p}.{root}")

        return mutations


# --- Phase 4: DNS Resolver with Wildcard Trap ---
class DnsResolver:
    """High-concurrency DNS resolver with wildcard sinkhole detection."""

    def __init__(self) -> None:
        self.resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1", "9.9.9.9"])
        self.wildcard_ips: Set[str] = set()
        self.cache: Dict[str, Optional[str]] = {}
        self.failed_count = 0

    async def detect_wildcard(self, root_domain: str) -> bool:
        """Generate 3 impossible subdomains. If they all resolve to the same IP, it's a wildcard."""
        test_subs = [
            f"xkq9-{uuid.uuid4().hex[:8]}.{root_domain}",
            f"zxlp2-{uuid.uuid4().hex[:8]}.{root_domain}",
            f"impossible-{uuid.uuid4().hex[:8]}.{root_domain}",
        ]
        resolved_sets: List[Set[str]] = []
        for sub in test_subs:
            try:
                res = await asyncio.wait_for(self.resolver.query(sub, "A"), timeout=DNS_TIMEOUT)
                ips = {item.host for item in res}
                if ips:
                    resolved_sets.append(ips)
            except Exception:
                pass

        if len(resolved_sets) >= 2:
            common = resolved_sets[0]
            for s in resolved_sets[1:]:
                common = common & s
            if common:
                self.wildcard_ips.update(common)
                logger.warning(f"[WILDCARD] Sinkhole IPs detected: {common}")
                return True
        return False

    async def resolve_host(self, hostname: str) -> Optional[str]:
        """Resolve a single hostname, filtering wildcard IPs."""
        if hostname in self.cache:
            return self.cache[hostname]

        # Try A record
        for qtype in ("A", "AAAA"):
            try:
                res = await asyncio.wait_for(self.resolver.query(hostname, qtype), timeout=DNS_TIMEOUT)
                for item in res:
                    ip = item.host
                    if ip not in self.wildcard_ips:
                        self.cache[hostname] = ip
                        return ip
            except Exception:
                pass

        self.failed_count += 1
        self.cache[hostname] = None
        return None

    async def bulk_resolve(self, hostnames: Set[str]) -> Dict[str, str]:
        """Mass-resolve with semaphore-bounded concurrency."""
        sem = asyncio.Semaphore(DNS_CONCURRENCY)
        results: Dict[str, str] = {}

        async def _resolve(h: str) -> None:
            async with sem:
                ip = await self.resolve_host(h)
                if ip:
                    results[h] = ip

        await asyncio.gather(*(_resolve(h) for h in hostnames), return_exceptions=True)
        return results
