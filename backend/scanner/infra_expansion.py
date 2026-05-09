"""
Module 2: Hosting Infrastructure Expansion (BGP, ASN & Reverse-IP Mapping)

Discovers the target's full IP space via ASN/BGP resolution, then performs
reverse DNS and cloud provider certificate scanning to find assets hosted
on shared infrastructure not explicitly linked to the main domain.

Usage:
    expander = InfrastructureExpander()
    report = await expander.execute(target_domain="example.com", seed_ips=["1.2.3.4"])
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import aiohttp

try:
    import aiodns
except ImportError:
    aiodns = None

logger = logging.getLogger("quanthunt.infra_expand")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BGP_WHOIS_HOST = "whois.radb.net"
BGP_WHOIS_PORT = 43
TEAM_CYMRU_WHOIS = "whois.cymru.com"
RDNS_CONCURRENCY = 100
TLS_PROBE_CONCURRENCY = 80
TLS_PROBE_TIMEOUT = 4.0

# Known cloud provider CIDR blocks (representative samples for scanning)
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
CLOUD_PROVIDER_ASN_PREFIXES: Dict[str, List[str]] = {
    "aws": ["AS16509", "AS14618"],
    "gcp": ["AS15169", "AS396982"],
    "azure": ["AS8075", "AS8068"],
    "cloudflare": ["AS13335"],
    "akamai": ["AS20940", "AS16625"],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ASNInfo:
    """Autonomous System Number resolution result."""
    ip: str
    asn: str = ""
    asn_name: str = ""
    bgp_prefix: str = ""
    country: str = ""
    registry: str = ""


@dataclass
class ReverseDNSResult:
    """Reverse DNS lookup result for a single IP."""
    ip: str
    hostnames: List[str] = field(default_factory=list)
    tls_cert_domains: List[str] = field(default_factory=list)
    tls_version: str = ""
    cipher_suite: str = ""
    is_pqc: bool = False


@dataclass
class InfrastructureReport:
    """Aggregated output from the infrastructure expansion pipeline."""
    target_domain: str
    seed_ips: List[str] = field(default_factory=list)
    resolved_asns: List[ASNInfo] = field(default_factory=list)
    bgp_prefixes: Set[str] = field(default_factory=set)
    prefix_ip_count: int = 0
    sampled_ips: List[str] = field(default_factory=list)
    reverse_dns_results: List[ReverseDNSResult] = field(default_factory=list)
    discovered_hostnames: Set[str] = field(default_factory=set)
    discovered_cert_domains: Set[str] = field(default_factory=set)
    cloud_provider_detected: str = ""
    tls_modern_count: int = 0
    tls_legacy_count: int = 0
    pqc_detected_count: int = 0
    elapsed_seconds: float = 0.0

    @property
    def tls_total(self) -> int:
        return self.tls_modern_count + self.tls_legacy_count

    @property
    def modern_tls_ratio(self) -> float:
        """Fraction of probed IPs with TLS 1.3 or PQC."""
        total = self.tls_total
        return self.tls_modern_count / max(total, 1)

    @property
    def infrastructure_reward(self) -> float:
        """
        HNDL reward: if ≥99% of ASN block enforces modern TLS/PQC, reward up to -20.
        If <80%, no reward. Linear interpolation between.
        """
        ratio = self.modern_tls_ratio
        if ratio >= 0.99:
            return -20.0
        if ratio >= 0.95:
            return -15.0
        if ratio >= 0.90:
            return -10.0
        if ratio >= 0.80:
            return -5.0
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "seed_ips": self.seed_ips,
            "asn_count": len(self.resolved_asns),
            "bgp_prefixes": sorted(self.bgp_prefixes),
            "prefix_ip_count": self.prefix_ip_count,
            "sampled_ips_count": len(self.sampled_ips),
            "discovered_hostnames": sorted(self.discovered_hostnames),
            "discovered_cert_domains": sorted(self.discovered_cert_domains),
            "cloud_provider": self.cloud_provider_detected,
            "tls_modern_count": self.tls_modern_count,
            "tls_legacy_count": self.tls_legacy_count,
            "pqc_detected_count": self.pqc_detected_count,
            "modern_tls_ratio": round(self.modern_tls_ratio, 4),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "hndl_adjustment": {
                "infrastructure_reward": self.infrastructure_reward,
            },
        }


# ---------------------------------------------------------------------------
# ASN & BGP Resolution
# ---------------------------------------------------------------------------
class ASNResolver:
    """Resolve IPs to ASN/BGP prefix via Team Cymru whois protocol."""

    @staticmethod
    async def resolve_ip(ip: str) -> ASNInfo:
        """Query Team Cymru whois for ASN info."""
        info = ASNInfo(ip=ip)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(TEAM_CYMRU_WHOIS, BGP_WHOIS_PORT),
                timeout=6.0,
            )
            writer.write(f" -v {ip}\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=6.0)
            writer.close()
            await writer.wait_closed()

            text = data.decode("utf-8", errors="ignore")
            for line in text.strip().splitlines():
                if line.startswith("AS") or "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 5:
                        info.asn = parts[0].strip()
                        info.bgp_prefix = parts[1].strip()
                        info.country = parts[2].strip()
                        info.registry = parts[3].strip()
                        info.asn_name = parts[4].strip() if len(parts) > 4 else ""
                        break
        except Exception as exc:
            logger.debug(f"ASN resolve failed for {ip}: {exc}")
        return info

    @staticmethod
    async def resolve_batch(ips: List[str]) -> List[ASNInfo]:
        """Resolve multiple IPs concurrently."""
        sem = asyncio.Semaphore(20)

        async def _resolve(ip: str) -> ASNInfo:
            async with sem:
                return await ASNResolver.resolve_ip(ip)

        return await asyncio.gather(*(_resolve(ip) for ip in ips))

    @staticmethod
    def expand_prefix(prefix: str, sample_limit: int = 256) -> List[str]:
        """Expand a BGP prefix (e.g., 203.0.113.0/24) to individual IPs, capped."""
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            if len(ips) > sample_limit:
                # Deterministic sampling: take evenly spaced IPs
                step = len(ips) // sample_limit
                return ips[::step][:sample_limit]
            return ips
        except ValueError:
            return []


# ---------------------------------------------------------------------------
# Reverse DNS & TLS Certificate Scanner
# ---------------------------------------------------------------------------
class ReverseIPScanner:
    """Reverse DNS + TLS certificate probing on discovered IP space."""

    PQC_MARKERS = frozenset({
        "MLKEM", "ML-KEM", "KYBER", "X25519MLKEM768",
        "SECP256R1MLKEM768", "SECP384R1MLKEM1024",
    })

    def __init__(self) -> None:
        self._resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"]) if aiodns else None
        self._rdns_sem = asyncio.Semaphore(RDNS_CONCURRENCY)
        self._tls_sem = asyncio.Semaphore(TLS_PROBE_CONCURRENCY)

    async def reverse_dns(self, ip: str) -> List[str]:
        """Reverse DNS lookup for an IP."""
        async with self._rdns_sem:
            hostnames: List[str] = []
            # aiodns reverse lookup
            if self._resolver:
                try:
                    result = await asyncio.wait_for(
                        self._resolver.query(
                            ".".join(reversed(ip.split("."))) + ".in-addr.arpa", "PTR"
                        ),
                        timeout=3.0,
                    )
                    for entry in result:
                        hostname = str(entry.host).strip().rstrip(".")
                        if hostname:
                            hostnames.append(hostname.lower())
                except Exception:
                    pass

            # Fallback: system resolver
            if not hostnames:
                try:
                    hostname, _, _ = await asyncio.get_running_loop().run_in_executor(
                        None, socket.gethostbyaddr, ip
                    )
                    if hostname:
                        hostnames.append(hostname.lower().rstrip("."))
                except Exception:
                    pass

            return hostnames

    async def probe_tls_cert(self, ip: str, target_domain: str) -> ReverseDNSResult:
        """Connect via TLS to IP and extract certificate SANs."""
        result = ReverseDNSResult(ip=ip)
        async with self._tls_sem:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=target_domain),
                    timeout=TLS_PROBE_TIMEOUT,
                )
                sslobj = writer.get_extra_info("ssl_object")
                if sslobj:
                    result.tls_version = sslobj.version() or ""
                    cipher = sslobj.cipher()
                    result.cipher_suite = cipher[0] if cipher else ""
                    result.is_pqc = any(
                        m in result.cipher_suite.upper()
                        for m in self.PQC_MARKERS
                    )

                    # Extract cert SANs
                    der = sslobj.getpeercert(binary_form=True)
                    if der:
                        try:
                            from cryptography import x509 as cx509
                            from cryptography.hazmat.backends import default_backend
                            cert = cx509.load_der_x509_certificate(der, default_backend())
                            try:
                                san = cert.extensions.get_extension_for_oid(
                                    cx509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                                )
                                result.tls_cert_domains = [
                                    n.value.lower()
                                    for n in san.value.get_values_for_type(cx509.DNSName)
                                ]
                            except cx509.ExtensionNotFound:
                                pass
                        except Exception:
                            pass

                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return result

    async def scan_ip_batch(
        self,
        ips: List[str],
        target_domain: str,
    ) -> List[ReverseDNSResult]:
        """Scan a batch of IPs: reverse DNS + TLS cert probing in parallel."""
        tasks: List[asyncio.Task] = []
        for ip in ips:
            tasks.append(asyncio.create_task(self._scan_single(ip, target_domain)))
        return await asyncio.gather(*tasks)

    async def _scan_single(self, ip: str, target_domain: str) -> ReverseDNSResult:
        rdns_hostnames = await self.reverse_dns(ip)
        tls_result = await self.probe_tls_cert(ip, target_domain)
        tls_result.hostnames = rdns_hostnames
        return tls_result


# ---------------------------------------------------------------------------
# Cloud provider detection
# ---------------------------------------------------------------------------
def detect_cloud_provider(asn_infos: List[ASNInfo]) -> str:
    """Detect if the target's ASN belongs to a known cloud provider."""
    for info in asn_infos:
        asn_upper = info.asn.upper()
        for provider, asns in CLOUD_PROVIDER_ASN_PREFIXES.items():
            if any(asn_upper.startswith(a.upper().replace("AS", "")) or asn_upper == a.upper() for a in asns):
                return provider
    return ""


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
class InfrastructureExpander:
    """
    Module 2 entry point.
    Takes seed IPs, resolves ASN/BGP, expands to full IP blocks,
    then runs reverse DNS + TLS cert scanning to discover related assets.
    """

    def __init__(self, sample_limit: int = 256) -> None:
        self._sample_limit = sample_limit

    async def resolve_seed_ips(self, target_domain: str) -> List[str]:
        """Resolve target domain to seed IPs via DNS."""
        ips: List[str] = []
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                target_domain, 443, type=socket.SOCK_STREAM
            )
            for family, _, _, _, sockaddr in infos:
                if family in (socket.AF_INET, socket.AF_INET6):
                    ip = str(sockaddr[0]).strip()
                    if ip and ip not in ips:
                        ips.append(ip)
        except Exception:
            pass
        return ips

    async def execute(
        self,
        target_domain: str,
        seed_ips: List[str] | None = None,
    ) -> InfrastructureReport:
        """Run the full infrastructure expansion pipeline."""
        target = target_domain.lower().strip()
        report = InfrastructureReport(target_domain=target)
        start_time = time.perf_counter()

        # Step 1: Resolve seed IPs if not provided
        if not seed_ips:
            seed_ips = await self.resolve_seed_ips(target)
        report.seed_ips = list(seed_ips)

        if not seed_ips:
            logger.warning(f"[INFRA] No seed IPs for {target}")
            report.elapsed_seconds = time.perf_counter() - start_time
            return report

        # Step 2: ASN resolution
        logger.info(f"[INFRA] Resolving ASN for {len(seed_ips)} seed IPs")
        asn_infos = await ASNResolver.resolve_batch(seed_ips)
        report.resolved_asns = asn_infos

        # Step 3: Detect cloud provider
        report.cloud_provider_detected = detect_cloud_provider(asn_infos)

        # Step 4: Expand BGP prefixes
        all_sample_ips: Set[str] = set()
        for info in asn_infos:
            if info.bgp_prefix:
                report.bgp_prefixes.add(info.bgp_prefix)
                expanded = ASNResolver.expand_prefix(info.bgp_prefix, self._sample_limit)
                report.prefix_ip_count += len(expanded)
                all_sample_ips.update(expanded)

        # Cap total scanned IPs
        max_scan = int(os.getenv("QUANTHUNT_INFRA_MAX_SCAN_IPS", "512"))
        sample_list = sorted(all_sample_ips)[:max_scan]
        report.sampled_ips = sample_list
        logger.info(
            f"[INFRA] {len(report.bgp_prefixes)} BGP prefixes, "
            f"{report.prefix_ip_count} total IPs, scanning {len(sample_list)}"
        )

        # Step 5: Reverse DNS + TLS certificate scanning
        scanner = ReverseIPScanner()
        rdns_results = await scanner.scan_ip_batch(sample_list, target)
        report.reverse_dns_results = rdns_results

        for result in rdns_results:
            for hostname in result.hostnames:
                report.discovered_hostnames.add(hostname)
            for cert_domain in result.tls_cert_domains:
                if target in cert_domain or cert_domain.endswith(f".{target}"):
                    report.discovered_cert_domains.add(cert_domain)

            # TLS version classification
            version = result.tls_version.upper()
            if "1.3" in version or result.is_pqc:
                report.tls_modern_count += 1
            elif version:
                report.tls_legacy_count += 1
            if result.is_pqc:
                report.pqc_detected_count += 1

        report.elapsed_seconds = time.perf_counter() - start_time
        logger.info(
            f"[INFRA] {target}: {len(report.discovered_hostnames)} rDNS hosts, "
            f"{len(report.discovered_cert_domains)} cert domains, "
            f"modern_ratio={report.modern_tls_ratio:.2%}, reward={report.infrastructure_reward}"
        )
        return report
