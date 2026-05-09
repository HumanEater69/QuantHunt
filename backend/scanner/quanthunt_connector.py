"""
Phase 1: Resilient Network Connector with Anti-WAF Circuit Breaker.
Phase 2: TLS Harvester & DOM Scraper for deep asset extraction.
"""
from __future__ import annotations

import asyncio
import logging
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.hashes import SHA256
except ImportError:
    x509 = None

logger = logging.getLogger("quanthunt.connector")

# --- Constants ---
MAX_CONCURRENT = 200
TIMEOUT_CONNECT = 5.0
TIMEOUT_TOTAL = 15.0
MAX_RETRIES = 3
BACKOFF_FACTOR = 1.5
WAF_THRESHOLD = 5
CRAWL_DEPTH = 3
JS_LIMIT = 10

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

SUBDOMAIN_RE = re.compile(
    r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', re.I
)
JS_ENDPOINT_RE = re.compile(
    r'(?:api|endpoint|gateway|baseUrl|BASE_URL)\s*[=:]\s*["\']([^"\']+)', re.I
)
PQC_KEYWORDS = frozenset({
    "MLKEM", "KYBER", "FRODO", "BIKE", "HQC",
    "DILITHIUM", "FALCON", "SPHINCS", "SLH-DSA", "ML-DSA",
})


# --- Data Classes ---
@dataclass
class PQCAssetData:
    """PQC posture data for a single live asset."""
    hostname: str
    ip: str
    port: int = 443
    tls_version: str = "UNKNOWN"
    cipher_suite: str = "UNKNOWN"
    key_algorithm: str = "UNKNOWN"
    key_size: int = 0
    is_pqc_hybrid: bool = False
    certificate_authority: str = ""
    certificate_fingerprint: str = ""
    sans: List[str] = field(default_factory=list)


# --- Phase 1: WAF Circuit Breaker ---
class WafCircuitBreaker:
    """Detects WAF blocks and adaptively throttles requests."""

    def __init__(self, threshold: int = WAF_THRESHOLD) -> None:
        self.threshold = threshold
        self.failures = 0
        self.is_open = False
        self.multiplier = 1.0

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold:
            self.is_open = True
            self.multiplier = min(self.multiplier * 2.0, 8.0)

    def record_success(self) -> None:
        self.failures = max(0, self.failures - 1)
        if self.failures == 0:
            self.is_open = False
            self.multiplier = 1.0

    def backoff_delay(self) -> float:
        return self.multiplier + random.uniform(0.1, 0.5)


class AntiWafConnector:
    """Async HTTP connector with exponential backoff, jitter, and WAF evasion."""

    def __init__(self, semaphore: asyncio.Semaphore) -> None:
        self.semaphore = semaphore
        self.breaker = WafCircuitBreaker()
        self.blocked_count = 0

    async def get(
        self, session: aiohttp.ClientSession, url: str, retry: int = 0
    ) -> Optional[str]:
        if self.breaker.is_open:
            await asyncio.sleep(self.breaker.backoff_delay())

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        async with self.semaphore:
            try:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=TIMEOUT_TOTAL, connect=TIMEOUT_CONNECT),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        self.breaker.record_success()
                        return await resp.text()
                    if resp.status in {429, 403, 502, 503, 504}:
                        self.blocked_count += 1
                        self.breaker.record_failure()
                        if retry < MAX_RETRIES:
                            await asyncio.sleep(BACKOFF_FACTOR ** retry + random.uniform(0.5, 1.5))
                            return await self.get(session, url, retry + 1)
                    else:
                        self.breaker.record_success()
                        return await resp.text()
            except (asyncio.TimeoutError, aiohttp.ClientError, socket.error):
                self.breaker.record_failure()
                if retry < MAX_RETRIES:
                    await asyncio.sleep(BACKOFF_FACTOR ** retry)
                    return await self.get(session, url, retry + 1)
            except Exception as exc:
                logger.debug(f"Unexpected error {url}: {exc}")
        return None


# --- Phase 2a: TLS/Cert Harvester ---
class TlsHarvester:
    """Extract X.509 certs, SANs, key algorithms, and PQC signals."""

    @staticmethod
    def is_pqc(cipher_name: str) -> bool:
        upper = cipher_name.upper()
        return any(kw in upper for kw in PQC_KEYWORDS)

    async def harvest(self, hostname: str, port: int = 443) -> Optional[PQCAssetData]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx, server_hostname=hostname),
                timeout=TIMEOUT_CONNECT,
            )
            sslobj = writer.get_extra_info("ssl_object")
            if not sslobj:
                writer.close()
                await writer.wait_closed()
                return None

            tls_version = sslobj.version() or "UNKNOWN"
            cipher = sslobj.cipher()
            cipher_name = cipher[0] if cipher else "UNKNOWN"
            der = sslobj.getpeercert(binary_form=True)

            sans: List[str] = []
            ca = ""
            fingerprint = ""
            key_algo = "UNKNOWN"
            key_size = 0

            if x509 is not None and der:
                try:
                    cert = x509.load_der_x509_certificate(der, default_backend())
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        )
                        sans = [n.value for n in san_ext.value.get_values_for_type(x509.DNSName)]
                    except x509.ExtensionNotFound:
                        pass
                    ca = ", ".join(f"{a.oid._name}={a.value}" for a in cert.issuer) if cert.issuer else ""
                    pub = cert.public_key()
                    key_algo = type(pub).__name__
                    key_size = getattr(pub, "key_size", 0)
                    fingerprint = cert.fingerprint(SHA256()).hex()
                except Exception:
                    pass

            writer.close()
            await writer.wait_closed()

            return PQCAssetData(
                hostname=hostname, ip="", port=port,
                tls_version=tls_version, cipher_suite=cipher_name,
                key_algorithm=key_algo, key_size=key_size,
                is_pqc_hybrid=self.is_pqc(cipher_name),
                certificate_authority=ca, certificate_fingerprint=fingerprint,
                sans=sans,
            )
        except Exception:
            return None


# --- Phase 2b: DOM/JS Scraper ---
class DomScraper:
    """Crawl seed domain to depth 3, extract subdomains from HTML and JS."""

    def __init__(self, connector: AntiWafConnector) -> None:
        self.connector = connector

    async def scrape(
        self, session: aiohttp.ClientSession, root_domain: str, depth: int = CRAWL_DEPTH
    ) -> Set[str]:
        found: Set[str] = {root_domain}
        visited: Set[str] = set()
        queue: Set[str] = {f"https://{root_domain}"}

        for _d in range(depth):
            if not queue:
                break
            batch = list(queue)[:50]
            queue = set()
            pages = await asyncio.gather(*(self.connector.get(session, u) for u in batch))

            for idx, content in enumerate(pages):
                if not content:
                    continue
                url = batch[idx]
                visited.add(url)

                # Extract hostnames from content
                for m in SUBDOMAIN_RE.findall(content):
                    host = m.lower().rstrip(".")
                    if root_domain in host:
                        found.add(host)

                # Extract JS endpoints
                for ep in JS_ENDPOINT_RE.findall(content):
                    if root_domain in ep:
                        found.add(ep.lower())

                # Discover JS files and mine them
                js_urls: Set[str] = set()
                for m in re.findall(r"['\"]([^'\"]+\.js(?:[?#][^'\"]*)?)['\"]", content, re.I):
                    js_urls.add(urljoin(url, m))
                for js_url in list(js_urls)[:JS_LIMIT]:
                    js_text = await self.connector.get(session, js_url)
                    if js_text:
                        for m in SUBDOMAIN_RE.findall(js_text):
                            host = m.lower().rstrip(".")
                            if root_domain in host:
                                found.add(host)

                # Queue same-origin links
                for m in re.findall(r'href=["\']([^"\']+)["\']', content, re.I):
                    full = urljoin(url, m)
                    parsed = urlparse(full)
                    if parsed.hostname and root_domain in parsed.hostname and full not in visited:
                        queue.add(full)
        return found
