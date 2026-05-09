"""
QuantHunt Core Engine: Next-Gen Post-Quantum Cryptography (PQC) & Attack Surface Management Scanner

This module implements a pure algorithmic, zero-API asset discovery and PQC posture assessment engine.
It uses direct network socket connections, deep web scraping, and mathematical permutation to discover
and analyze cryptographic infrastructure without relying on external OSINT databases.

Architecture Phases:
  - Phase 1: Resilient Network Connector (Anti-WAF with exponential backoff & jitter)
  - Phase 2: Deep Extraction & TLS Harvesting (X.509 cert analysis, DOM/JS scraping)
  - Phase 3: Mathematical Mutator (Combinatorial subdomain generation)
  - Phase 4: DNS Mass-Resolution & Wildcard Trap Detection
  - Phase 5: Structured Output (Supabase-ready JSON with PQC posture data)
"""

import asyncio
import json
import logging
import os
import random
import re
import socket
import ssl
import time
import contextlib
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
import aiodns
from bs4 import BeautifulSoup

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    x509 = None  # Graceful degradation

# --- LOGGING CONFIGURATION ---
logger = logging.getLogger("quanthunt.core")
logger.setLevel(logging.INFO)

# --- CONFIGURATION & CONSTANTS ---
MAX_CONCURRENT_CONNECTIONS = 200
MAX_DNS_CONCURRENCY = 500
TIMEOUT_CONNECT = 5.0
TIMEOUT_TOTAL = 15.0
MAX_RETRIES = 3
BACKOFF_FACTOR = 1.5
WAF_TRIGGER_THRESHOLD = 5  # Circuit breaker threshold
RESOLVER_POOL_SIZE = 100
DNS_RESOLUTION_BATCH_SIZE = 256
DNS_RESOLUTION_BUDGET = max(800, int(os.getenv("QUANTHUNT_DNS_RESOLUTION_BUDGET", "1800")))
DNS_RESOLUTION_WALL_TIMEOUT_SEC = max(8.0, float(os.getenv("QUANTHUNT_DNS_WALL_TIMEOUT_SEC", "22.0")))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

SUBDOMAIN_PREFIXES = [
    "dev", "stg", "uat", "prod", "sandbox", "test", "staging",
    "api", "mail", "vpn", "auth", "k8s", "git", "jenkins", "app",
    "aws", "azure", "cloud", "internal", "backup", "old", "beta",
    "demo", "qa", "preprod", "portal", "corp", "web", "secure",
    "sso", "idp", "ci", "cd", "nexus", "jira", "gitlab", "bitbucket",
    "grafana", "splunk", "monitoring", "grafana", "prometheus"
]

SERVICE_NAMES = [
    "api", "service", "db", "cache", "proxy", "internal", "secure",
    "vault", "identity", "admin", "backup", "storage", "queue", "worker",
    "kafka", "redis", "postgres", "mysql", "elastic", "rabbit",
    "log", "grafana", "kibana", "metrics", "tracing", "telemetry"
]

REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-south-1", "ca-central-1", "sa-east-1"
]

# Advanced regex patterns for subdomain extraction from JS/HTML
SUBDOMAIN_PATTERNS = [
    re.compile(r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', re.I),
    re.compile(r'"(?:https?:)?//([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', re.I),
    re.compile(r'api[._-]v?\d+\.([a-z0-9\-]+\.)+[a-z]{2,63}', re.I),
    re.compile(r'(dev|staging|prod|test)[._-]([a-z0-9\-]+\.)+[a-z]{2,63}', re.I),
]


def _ordered_unique(hostnames: List[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for hostname in hostnames:
        value = str(hostname or "").strip().lower().rstrip(".")
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered

# --- ENUMS & DATA CLASSES ---

class TlsVersionEnum(str, Enum):
    TLS_1_0 = "TLSv1.0"
    TLS_1_1 = "TLSv1.1"
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"
    UNKNOWN = "UNKNOWN"

@dataclass
class ScanMetrics:
    """Aggregated metrics for a single scan."""
    passive_count: int = 0
    generated_count: int = 0
    internet_candidates_count: int = 0
    live_resolved_count: int = 0
    unique_ips: int = 0
    wildcard_detected: bool = False
    waf_blocks_detected: int = 0
    dns_failures: int = 0
    tls_errors: int = 0

@dataclass
class PQCAssetData:
    """Post-Quantum Cryptography posture data for a single asset."""
    hostname: str
    ip: str
    port: int = 443
    tls_version: str = TlsVersionEnum.UNKNOWN
    cipher_suite: str = "UNKNOWN"
    key_algorithm: str = "UNKNOWN"
    key_size: int = 0
    is_pqc_hybrid: bool = False
    certificate_authority: str = ""
    certificate_fingerprint: str = ""
    sans: List[str] = field(default_factory=list)

# --- PHASE 1: RESILIENT NETWORK CONNECTOR (ANTI-WAF) ---

class WafCircuitBreaker:
    """Circuit breaker pattern to detect and adapt to WAF blocks."""
    
    def __init__(self, threshold: int = WAF_TRIGGER_THRESHOLD):
        self.threshold = threshold
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.is_open = False
        self.backoff_multiplier = 1.0

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.threshold:
            self.is_open = True
            self.backoff_multiplier = min(self.backoff_multiplier * 2.0, 8.0)
            logger.warning(f"[WAF] Circuit breaker OPEN. Failures: {self.failure_count}")

    def record_success(self) -> None:
        if self.failure_count > 0:
            self.failure_count = max(0, self.failure_count - 1)
        if self.failure_count == 0:
            self.is_open = False
            self.backoff_multiplier = 1.0

    def get_backoff_delay(self) -> float:
        """Calculate adaptive backoff delay."""
        return self.backoff_multiplier + random.uniform(0.1, 0.5)

class AntiWafConnector:
    """Asynchronous HTTP connector with WAF evasion and resilience."""
    
    def __init__(self, semaphore: asyncio.Semaphore):
        self.semaphore = semaphore
        self.circuit_breaker = WafCircuitBreaker()
        self.retry_codes = {429, 403, 502, 503, 504}
        self.request_count = 0
        self.blocked_count = 0

    async def get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        retry: int = 0
    ) -> Optional[str]:
        """Fetch URL with anti-WAF measures and exponential backoff."""
        
        if self.circuit_breaker.is_open:
            await asyncio.sleep(self.circuit_breaker.get_backoff_delay())

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

        async with self.semaphore:
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=TIMEOUT_TOTAL, connect=TIMEOUT_CONNECT),
                    ssl=False
                ) as response:
                    self.request_count += 1
                    
                    if response.status == 200:
                        self.circuit_breaker.record_success()
                        return await response.text()
                    
                    elif response.status in self.retry_codes:
                        self.blocked_count += 1
                        self.circuit_breaker.record_failure()
                        
                        if retry < MAX_RETRIES:
                            wait = (BACKOFF_FACTOR ** retry) + random.uniform(0.5, 1.5)
                            await asyncio.sleep(wait)
                            return await self.get(session, url, retry + 1)
                    
                    else:
                        self.circuit_breaker.record_success()
                        return await response.text()

            except asyncio.TimeoutError:
                self.circuit_breaker.record_failure()
                if retry < MAX_RETRIES:
                    await asyncio.sleep(BACKOFF_FACTOR ** retry)
                    return await self.get(session, url, retry + 1)

            except (aiohttp.ClientError, socket.error) as e:
                self.circuit_breaker.record_failure()
                logger.debug(f"Connection error for {url}: {e}")
                if retry < MAX_RETRIES:
                    await asyncio.sleep(BACKOFF_FACTOR ** retry)
                    return await self.get(session, url, retry + 1)

            except Exception as e:
                logger.error(f"Unexpected error fetching {url}: {e}")

        return None

# --- PHASE 2: DEEP EXTRACTION & TLS HARVESTING ---

class TlsHarvester:
    """TLS/SSL certificate and cipher extraction with PQC detection."""
    
    PQC_KEYWORDS = {
        "MLKEM", "KYBER", "FRODO", "BIKE", "HQC",
        "DILITHIUM", "FALCON", "SPHINCS", "SLH-DSA"
    }

    @classmethod
    def get_pqc_status(cls, cipher_name: str) -> bool:
        """Detect post-quantum cryptography signatures in cipher names."""
        return any(kw in cipher_name.upper() for kw in cls.PQC_KEYWORDS)

    @staticmethod
    def normalize_tls_version(version: str) -> str:
        """Normalize TLS version string."""
        mapping = {
            "TLSv1": TlsVersionEnum.TLS_1_0,
            "TLSv1.0": TlsVersionEnum.TLS_1_0,
            "TLSv1.1": TlsVersionEnum.TLS_1_1,
            "TLSv1.2": TlsVersionEnum.TLS_1_2,
            "TLSv1.3": TlsVersionEnum.TLS_1_3,
        }
        return mapping.get(version, TlsVersionEnum.UNKNOWN)

    async def harvest_cert(
        self,
        hostname: str,
        port: int = 443
    ) -> Optional[PQCAssetData]:
        """Extract TLS certificate and cryptographic posture from target."""
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    hostname,
                    port,
                    ssl=context,
                    server_hostname=hostname
                ),
                timeout=TIMEOUT_CONNECT
            )

            sslobj = writer.get_extra_info('ssl_object')
            if not sslobj:
                logger.warning(f"No SSL object for {hostname}:{port}")
                writer.close()
                await writer.wait_closed()
                return None

            # Extract TLS metadata
            tls_version = self.normalize_tls_version(sslobj.version())
            cipher = sslobj.cipher()
            cipher_name = cipher[0] if cipher else "UNKNOWN"

            # Extract certificate data
            cert_der = sslobj.getpeercert(binary_form=True)
            sans = []
            ca_name = ""
            fingerprint = ""
            key_algo = "UNKNOWN"
            key_size = 0

            # Parse certificate if cryptography is available
            if x509 and cert_der:
                try:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Extract SANs
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        )
                        sans = [name.value for name in san_ext.value.get_values_for_type(x509.DNSName)]
                    except x509.ExtensionNotFound:
                        pass

                    # Extract issuer (CA)
                    issuer = cert.issuer
                    ca_name = ", ".join(
                        f"{attr.oid._name}={attr.value}" for attr in issuer
                    ) if issuer else ""

                    # Extract public key info
                    pub_key = cert.public_key()
                    key_algo = type(pub_key).__name__.replace("PartiallyImplemented", "")
                    key_size = getattr(pub_key, "key_size", 0)

                    # Certificate fingerprint (SHA-256)
                    fingerprint = cert.fingerprint(
                        __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
                    ).hex()

                except Exception as e:
                    logger.debug(f"Error parsing cert for {hostname}: {e}")

            writer.close()
            await writer.wait_closed()

            return PQCAssetData(
                hostname=hostname,
                ip="",  # Will be filled by resolver
                port=port,
                tls_version=tls_version,
                cipher_suite=cipher_name,
                key_algorithm=key_algo,
                key_size=key_size,
                is_pqc_hybrid=self.get_pqc_status(cipher_name),
                certificate_authority=ca_name,
                certificate_fingerprint=fingerprint,
                sans=sans
            )

        except socket.timeout:
            logger.debug(f"Socket timeout: {hostname}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"Connection refused: {hostname}:{port}")
        except ssl.SSLError as e:
            logger.debug(f"SSL error for {hostname}:{port}: {e}")
        except Exception as e:
            logger.debug(f"TLS harvest error {hostname}:{port}: {e}")

        return None

class DomScraper:
    """Deep crawler with JS extraction for hidden subdomain discovery."""
    
    def __init__(self, connector: AntiWafConnector):
        self.connector = connector
        self.js_endpoint_regex = re.compile(r'(?:api|endpoint|gateway)\s*[=:]\s*["\']([^"\']*)', re.I)

    async def scrape(
        self,
        session: aiohttp.ClientSession,
        root_domain: str,
        depth: int = 3
    ) -> Set[str]:
        """Recursively scrape domain and extract all discovered hostnames."""
        
        found_hostnames = {root_domain}
        visited_urls = set()
        queue = {f"https://{root_domain}"}

        for current_depth in range(depth):
            if not queue:
                break

            current_batch = list(queue)
            queue = set()
            tasks = [self.connector.get(session, url) for url in current_batch]
            pages = await asyncio.gather(*tasks)

            for url_idx, content in enumerate(pages):
                if not content:
                    continue

                current_url = current_batch[url_idx]
                visited_urls.add(current_url)

                # Parse HTML
                try:
                    soup = BeautifulSoup(content, 'html.parser')

                    # Extract links and scripts
                    for tag in soup.find_all(['a', 'script', 'link', 'img']):
                        for attr in ['href', 'src', 'data', 'content']:
                            value = tag.get(attr)
                            if not value:
                                continue

                            target = urljoin(current_url, value)
                            parsed = urlparse(target)

                            if root_domain in parsed.netloc:
                                found_hostnames.add(parsed.netloc)
                                if parsed.suffix in ('.html', '.php', '.asp', '.jsp', '') or \
                                   parsed.path in ('/', '/index.html', '/api'):
                                    if target not in visited_urls:
                                        queue.add(target)

                except Exception as e:
                    logger.debug(f"HTML parse error: {e}")

                # Advanced regex extraction from content
                for pattern in SUBDOMAIN_PATTERNS:
                    matches = pattern.findall(content)
                    for match in matches:
                        if isinstance(match, tuple):
                            domain_part = match[0] if match else ""
                        else:
                            domain_part = match

                        if domain_part and root_domain in domain_part:
                            found_hostnames.add(domain_part.lower())

                # Extract API endpoints and hardcoded routes
                endpoints = self.js_endpoint_regex.findall(content)
                for ep in endpoints:
                    if root_domain in ep:
                        found_hostnames.add(ep.lower())

        return found_hostnames

# --- PHASE 3: MATHEMATICAL MUTATOR ---

class OsintHarvester:
    """Zero-API OSINT Harvester for deep asset discovery (Web Scraping Public DBs)."""
    
    @staticmethod
    async def crt_sh_search(target_domain: str, fetcher: AntiWafConnector, session: aiohttp.ClientSession) -> Set[str]:
        """Scrape crt.sh without using an official API key for deep certificate historical search."""
        hostnames: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{target_domain}&output=json"
        try:
            # We use the generic AntiWafConnector to grab this
            html = await fetcher.get(session, url)
            if html:
                import json
                try:
                    data = json.loads(html)
                    if isinstance(data, list):
                        for entry in data:
                            name = entry.get("name_value", "")
                            if name:
                                for n in name.split("\\n"):
                                    n = n.strip().lower()
                                    if "*" not in n and n.endswith(target_domain):
                                        hostnames.add(n)
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.debug(f"crt.sh harvesting failed for {target_domain}: {e}")
        
        return hostnames

class SubdomainMutator:
    """Generate mathematically permuted subdomains for attack surface expansion."""

    @staticmethod
    def generate_mutations(root_domain: str, num_increments: int = 50) -> Set[str]:
        """Generate comprehensive mutation set using combinatorics."""
        
        mutations: Set[str] = set()
        base_patterns = [
            "{prefix}.{root}",
            "{prefix}-{service}.{root}",
            "{service}.{root}",
            "{service}-{region}.{root}",
            "{prefix}-{service}-{region}.{root}",
            "{prefix}-{num}.{root}",
            "{service}-{num}.{root}",
            "{prefix}-{service}-{num}.{root}",
            "v{num}.{root}",
            "api-v{num}.{root}",
            "{prefix}-api-v{num}.{root}",
            "admin-{prefix}.{root}",
            "{prefix}-internal.{root}",
        ]

        for pattern in base_patterns:
            if "{prefix}" in pattern:
                for prefix in SUBDOMAIN_PREFIXES:
                    p = pattern.replace("{prefix}", prefix)
                    if "{service}" not in p and "{region}" not in p and "{num}" not in p:
                        mutations.add(p.format(root=root_domain))
                    elif "{service}" in p:
                        for service in SERVICE_NAMES:
                            p2 = p.replace("{service}", service)
                            if "{region}" not in p2 and "{num}" not in p2:
                                mutations.add(p2.format(root=root_domain))
                            elif "{region}" in p2:
                                for region in REGIONS:
                                    mutations.add(p2.replace("{region}", region).format(root=root_domain))
                            elif "{num}" in p2:
                                for i in range(1, min(num_increments + 1, 21)):
                                    mutations.add(p2.replace("{num}", str(i).zfill(2)).format(root=root_domain))
            
            elif "{service}" in pattern:
                for service in SERVICE_NAMES:
                    p = pattern.replace("{service}", service)
                    if "{region}" not in p and "{num}" not in p:
                        mutations.add(p.format(root=root_domain))
                    elif "{region}" in p:
                        for region in REGIONS:
                            mutations.add(p.replace("{region}", region).format(root=root_domain))
                    elif "{num}" in p:
                        for i in range(1, min(num_increments + 1, 11)):
                            mutations.add(p.replace("{num}", str(i).zfill(2)).format(root=root_domain))

        return mutations

# --- PHASE 4: DNS MASS-RESOLUTION & WILDCARD TRAP ---

class DnsResolver:
    """High-concurrency DNS resolver with wildcard detection and filtering."""
    
    def __init__(self):
        self.resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "8.8.4.4", "1.1.1.1"])
        self.wildcard_ips: Set[str] = set()
        self.resolved_cache: Dict[str, Optional[str]] = {}
        self.failed_count = 0

    async def detect_wildcard(self, root_domain: str) -> bool:
        """Detect wildcard DNS sinkhole by testing high-entropy subdomains."""
        
        test_subs = [
            f"quanthunt-{uuid.uuid4().hex[:12]}.{root_domain}",
            f"xkq9-zxlp2-{uuid.uuid4().hex[:8]}.{root_domain}",
            f"impossible-{int(time.time())}.{root_domain}",
        ]

        for sub in test_subs:
            try:
                res = await asyncio.wait_for(
                    self.resolver.query(sub, 'A'),
                    timeout=TIMEOUT_CONNECT
                )
                for item in res:
                    self.wildcard_ips.add(item.host)
                    logger.warning(f"[WILDCARD] Detected sinkhole IP: {item.host}")
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                pass
            except Exception as e:
                logger.debug(f"Wildcard detection error: {e}")

        return len(self.wildcard_ips) > 0

    async def resolve_safe(self, hostname: str) -> Optional[str]:
        """Resolve hostname with wildcard filtering."""
        
        if hostname in self.resolved_cache:
            return self.resolved_cache[hostname]

        try:
            # Try A record first
            res_a = await asyncio.wait_for(
                self.resolver.query(hostname, 'A'),
                timeout=TIMEOUT_CONNECT
            )
            for item in res_a:
                ip = item.host
                if ip not in self.wildcard_ips:
                    self.resolved_cache[hostname] = ip
                    return ip

        except (aiodns.error.DNSError, asyncio.TimeoutError):
            pass
        except Exception as e:
            logger.debug(f"DNS resolution error for {hostname}: {e}")
            self.failed_count += 1

        try:
            # Try AAAA record as fallback
            res_aaaa = await asyncio.wait_for(
                self.resolver.query(hostname, 'AAAA'),
                timeout=TIMEOUT_CONNECT
            )
            for item in res_aaaa:
                ip = item.host
                if ip not in self.wildcard_ips:
                    self.resolved_cache[hostname] = ip
                    return ip

        except (aiodns.error.DNSError, asyncio.TimeoutError):
            pass
        except Exception:
            pass

        self.resolved_cache[hostname] = None
        return None

# --- PHASE 5: EXECUTION ENGINE ---

async def run_quanthunt_scan(target_domain: str) -> Dict[str, Any]:
    """
    Execute complete QuantHunt scan on target domain.
    
    Returns beautifully structured JSON ready for Supabase JSONB storage.
    """
    
    scan_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Initialize components
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
    connector = AntiWafConnector(semaphore)
    harvester = TlsHarvester()
    scraper = DomScraper(connector)
    resolver = DnsResolver()
    mutator = SubdomainMutator()
    
    metrics = ScanMetrics()
    pending_resolution: Set[str] = set()
    live_assets: List[PQCAssetData] = []
    unique_ips: Set[str] = set()

    logger.info(f"[SCAN {scan_id}] Starting scan on: {target_domain}")

    try:
        # Phase 4.1: Wildcard Detection
        logger.info(f"[SCAN {scan_id}] Phase 4.1: Detecting wildcard DNS")
        metrics.wildcard_detected = await resolver.detect_wildcard(target_domain)

        breaker = WafCircuitBreaker()
        http_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
        fetcher = AntiWafConnector(http_semaphore)
        fetcher.breaker = breaker  # assuming AntiWafConnector has access or we just pass it manually

        async with aiohttp.ClientSession() as session:
            # Inject session into fetcher
            fetcher.session = session
            
            # Phase 2: Deep Scraping & OSINT Discovery
            logger.info(f"[SCAN {scan_id}] Phase 2: Deep scraping and OSINT for passive assets")
            initial_hostnames = await scraper.scrape(session, target_domain)
            
            # Integrate the newly scaled OSINT web scraper
            osint_hostnames = await OsintHarvester.crt_sh_search(target_domain, fetcher, session)
            initial_hostnames.update(osint_hostnames)

            metrics.passive_count = len(initial_hostnames)
            logger.info(f"[SCAN {scan_id}] Passive + OSINT discovery: {metrics.passive_count} hostnames")

            # Phase 3: Mathematical Mutations
            logger.info(f"[SCAN {scan_id}] Phase 3: Generating mathematical mutations")
            mutated = mutator.generate_mutations(target_domain)
            metrics.generated_count = len(mutated)
            logger.info(f"[SCAN {scan_id}] Generated mutations: {metrics.generated_count}")

            ordered_candidates = _ordered_unique([*sorted(initial_hostnames), *sorted(mutated)])
            metrics.internet_candidates_count = len(ordered_candidates)
            resolution_targets = ordered_candidates[:DNS_RESOLUTION_BUDGET]
            pending_resolution.update(resolution_targets)
            logger.info(
                f"[SCAN {scan_id}] Phase 4.2: Mass DNS resolution "
                f"({len(resolution_targets)}/{metrics.internet_candidates_count} candidates, budget={DNS_RESOLUTION_BUDGET})"
            )
            dns_semaphore = asyncio.Semaphore(MAX_DNS_CONCURRENCY)
            
            async def resolve_with_sem(hostname: str) -> Tuple[str, Optional[str]]:
                async with dns_semaphore:
                    ip = await resolver.resolve_safe(hostname)
                    return hostname, ip

            resolve_tasks = [
                asyncio.create_task(resolve_with_sem(hostname))
                for hostname in resolution_targets
            ]
            resolve_results: List[Tuple[str, Optional[str]]] = []
            deadline = time.monotonic() + DNS_RESOLUTION_WALL_TIMEOUT_SEC
            for task in asyncio.as_completed(resolve_tasks, timeout=DNS_RESOLUTION_WALL_TIMEOUT_SEC):
                try:
                    resolve_results.append(await task)
                except asyncio.TimeoutError:
                    break
                except Exception:
                    resolver.failed_count += 1
                if time.monotonic() >= deadline:
                    break
            for task in resolve_tasks:
                if not task.done():
                    task.cancel()
            if resolve_tasks:
                with contextlib.suppress(Exception):
                    await asyncio.gather(*resolve_tasks, return_exceptions=True)
            
            resolved_map: Dict[str, str] = {}
            for hostname, ip in resolve_results:
                if ip:
                    resolved_map[hostname] = ip
                    unique_ips.add(ip)

            metrics.live_resolved_count = len(resolved_map)
            metrics.unique_ips = len(unique_ips)
            metrics.dns_failures = resolver.failed_count
            logger.info(f"[SCAN {scan_id}] Resolved: {metrics.live_resolved_count} live hostnames to {metrics.unique_ips} unique IPs")

            # Phase 2.2: TLS Harvesting on Live Assets
            logger.info(f"[SCAN {scan_id}] Phase 2.2: TLS harvesting on live assets")
            tls_tasks = [harvester.harvest_cert(hostname) for hostname in resolved_map.keys()]
            tls_results = await asyncio.gather(*tls_tasks)

            for hostname, tls_data in zip(resolved_map.keys(), tls_results):
                if tls_data:
                    tls_data.hostname = hostname
                    tls_data.ip = resolved_map[hostname]
                    
                    # Recursive SAN discovery (future scans)
                    for san in tls_data.sans:
                        if san.endswith(target_domain) and san not in pending_resolution:
                            logger.debug(f"[SCAN {scan_id}] Discovered SAN: {san}")
                    
                    live_assets.append(tls_data)
                else:
                    metrics.tls_errors += 1

        metrics.waf_blocks_detected = connector.blocked_count

    except Exception as e:
        logger.error(f"[SCAN {scan_id}] Critical error during scan: {e}", exc_info=True)

    # Construct output payload
    elapsed_time = time.time() - start_time
    payload = {
        "scan_id": scan_id,
        "target_domain": target_domain,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_duration_seconds": round(elapsed_time, 2),
        "wildcard_detected": metrics.wildcard_detected,
        "metrics": {
            "passive_assets_discovered": metrics.passive_count,
            "mathematically_generated": metrics.generated_count,
            "internet_candidates_generated": metrics.internet_candidates_count,
            "internet_candidates_tested": len(resolution_targets),
            "live_resolved_assets": metrics.live_resolved_count,
            "unique_ips": metrics.unique_ips,
            "waf_blocks_detected": metrics.waf_blocks_detected,
            "dns_resolution_failures": metrics.dns_failures,
            "tls_handshake_errors": metrics.tls_errors,
        },
        "pqc_raw_data": [asdict(asset) for asset in live_assets],
        "wildcard_sinkholes": list(resolver.wildcard_ips) if metrics.wildcard_detected else [],
        "internet_candidates": resolution_targets,
        "summary": {
            "total_hostnames_tested": len(resolution_targets),
            "resolved_hostnames_tested": metrics.live_resolved_count,
            "live_assets_with_tls": len(live_assets),
            "pqc_hybrid_detected": sum(1 for a in live_assets if a.is_pqc_hybrid),
        }
    }

    logger.info(f"[SCAN {scan_id}] Scan complete. Found {len(live_assets)} live assets in {elapsed_time:.2f}s")
    return payload

# --- CLI ENTRY POINT ---

if __name__ == "__main__":
    import sys
    
    # Setup logging
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)

    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(f"\n{'='*60}")
    print(f"[*] QuantHunt Core Engine - Next-Gen PQC Scanner")
    print(f"[*] Target: {target}")
    print(f"{'='*60}\n")

    try:
        result = asyncio.run(run_quanthunt_scan(target))
        print(json.dumps(result, indent=2, default=str))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
