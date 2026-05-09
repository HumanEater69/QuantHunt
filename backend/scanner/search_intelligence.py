"""
Module 1: Search Engine Intelligence Bridge (Advanced Dorking)

Implements headless search engine scraping with proxy rotation and algorithmic
dorking to discover subdomains, exposed endpoints, sensitive files, and
shadow IT assets via Google, Bing, and DuckDuckGo.

Usage:
    bridge = SearchIntelligenceBridge(proxy_pool=[...])
    result = await bridge.execute(target_domain="example.com")
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import quote_plus, urljoin, urlparse

import aiohttp

logger = logging.getLogger("quanthunt.search_intel")

# ---------------------------------------------------------------------------
# Constants & configuration
# ---------------------------------------------------------------------------
MAX_CONCURRENT_SEARCHES = 8
SEARCH_TIMEOUT_SEC = 12.0
MAX_RESULTS_PER_ENGINE = 120
BACKOFF_BASE = 2.0
CAPTCHA_RETRY_LIMIT = 3

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

CAPTCHA_SIGNALS = frozenset({
    "captcha", "recaptcha", "unusual traffic", "bot check",
    "verify you are human", "access denied", "sorry/index",
})


class SearchEngine(Enum):
    GOOGLE = "google"
    BING = "bing"
    DUCKDUCKGO = "duckduckgo"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------
@dataclass
class DorkResult:
    """A single result extracted from a search engine dork."""
    url: str
    hostname: str
    title: str = ""
    snippet: str = ""
    engine: str = ""
    dork_query: str = ""
    sensitivity: str = "normal"   # "normal", "exposed_config", "dev_server", "leaked_cred"


@dataclass
class SearchIntelReport:
    """Aggregated output from the entire search intelligence pipeline."""
    target_domain: str
    discovered_subdomains: Set[str] = field(default_factory=set)
    discovered_urls: Set[str] = field(default_factory=set)
    exposed_env_files: List[DorkResult] = field(default_factory=list)
    exposed_dev_servers: List[DorkResult] = field(default_factory=list)
    exposed_certs_keys: List[DorkResult] = field(default_factory=list)
    all_results: List[DorkResult] = field(default_factory=list)
    captcha_blocks: int = 0
    total_queries_executed: int = 0
    engines_used: Set[str] = field(default_factory=set)
    elapsed_seconds: float = 0.0

    # --- Penalty signals for HNDL calibration ---
    @property
    def env_file_penalty(self) -> float:
        """Each exposed .env adds +8 to HNDL risk, capped at 40."""
        return min(40.0, len(self.exposed_env_files) * 8.0)

    @property
    def dev_server_penalty(self) -> float:
        """Each exposed dev/staging server adds +5, capped at 30."""
        return min(30.0, len(self.exposed_dev_servers) * 5.0)

    @property
    def leaked_cred_penalty(self) -> float:
        """Each exposed cert/key file adds +12, capped at 48."""
        return min(48.0, len(self.exposed_certs_keys) * 12.0)

    @property
    def total_penalty(self) -> float:
        return self.env_file_penalty + self.dev_server_penalty + self.leaked_cred_penalty

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "discovered_subdomains": sorted(self.discovered_subdomains),
            "discovered_urls_count": len(self.discovered_urls),
            "exposed_env_files": len(self.exposed_env_files),
            "exposed_dev_servers": len(self.exposed_dev_servers),
            "exposed_certs_keys": len(self.exposed_certs_keys),
            "total_results": len(self.all_results),
            "captcha_blocks": self.captcha_blocks,
            "total_queries_executed": self.total_queries_executed,
            "engines_used": sorted(self.engines_used),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "hndl_penalties": {
                "env_file_penalty": self.env_file_penalty,
                "dev_server_penalty": self.dev_server_penalty,
                "leaked_cred_penalty": self.leaked_cred_penalty,
                "total_penalty": self.total_penalty,
            },
        }


# ---------------------------------------------------------------------------
# Proxy pool manager
# ---------------------------------------------------------------------------
class ProxyRotator:
    """Round-robin proxy rotation with health tracking."""

    def __init__(self, proxies: List[str] | None = None) -> None:
        raw = proxies or self._load_from_env()
        self._proxies: List[str] = [p.strip() for p in raw if p.strip()]
        self._index = 0
        self._failures: Dict[str, int] = {}
        self._max_failures = 5

    @staticmethod
    def _load_from_env() -> List[str]:
        raw = os.getenv("QUANTHUNT_PROXY_POOL", "").strip()
        return [p.strip() for p in raw.split(",") if p.strip()] if raw else []

    @property
    def has_proxies(self) -> bool:
        return len(self._proxies) > 0

    def next(self) -> Optional[str]:
        if not self._proxies:
            return None
        # Skip proxies that have exceeded failure threshold
        for _ in range(len(self._proxies)):
            proxy = self._proxies[self._index % len(self._proxies)]
            self._index += 1
            if self._failures.get(proxy, 0) < self._max_failures:
                return proxy
        return None

    def mark_failure(self, proxy: str) -> None:
        self._failures[proxy] = self._failures.get(proxy, 0) + 1

    def mark_success(self, proxy: str) -> None:
        self._failures[proxy] = max(0, self._failures.get(proxy, 0) - 1)


# ---------------------------------------------------------------------------
# Dork query generator
# ---------------------------------------------------------------------------
class DorkGenerator:
    """Programmatically generate advanced search dork queries."""

    @staticmethod
    def generate(target: str) -> List[Tuple[str, str]]:
        """
        Returns list of (query, sensitivity_tag) tuples.
        Sensitivity tags: normal, exposed_config, dev_server, leaked_cred
        """
        domain = target.lower().strip()
        dorks: List[Tuple[str, str]] = []

        # --- Subdomain discovery ---
        dorks.append((f"site:{domain} -www", "normal"))
        dorks.append((f"site:*.{domain}", "normal"))
        dorks.append((f"site:{domain} inurl:api", "normal"))
        dorks.append((f"site:{domain} inurl:portal", "normal"))
        dorks.append((f"site:{domain} inurl:admin", "normal"))
        dorks.append((f"site:{domain} inurl:staging", "dev_server"))
        dorks.append((f"site:{domain} inurl:dev", "dev_server"))
        dorks.append((f"site:{domain} inurl:uat", "dev_server"))
        dorks.append((f"site:{domain} inurl:test", "dev_server"))
        dorks.append((f"site:{domain} inurl:sandbox", "dev_server"))
        dorks.append((f"site:{domain} inurl:internal", "dev_server"))
        dorks.append((f"site:{domain} inurl:beta", "dev_server"))

        # --- Exposed configuration files ---
        dorks.append((f"site:{domain} filetype:env", "exposed_config"))
        dorks.append((f"site:{domain} ext:env DB_PASSWORD", "exposed_config"))
        dorks.append((f"site:{domain} filetype:yaml password", "exposed_config"))
        dorks.append((f"site:{domain} filetype:json api_key", "exposed_config"))
        dorks.append((f"site:{domain} filetype:xml password", "exposed_config"))
        dorks.append((f"site:{domain} filetype:ini password", "exposed_config"))
        dorks.append((f"site:{domain} filetype:conf password", "exposed_config"))
        dorks.append((f"site:{domain} inurl:.env", "exposed_config"))
        dorks.append((f"site:{domain} inurl:config.json", "exposed_config"))

        # --- Exposed cryptographic material ---
        dorks.append((f"site:{domain} ext:pem", "leaked_cred"))
        dorks.append((f"site:{domain} ext:key", "leaked_cred"))
        dorks.append((f"site:{domain} ext:p12", "leaked_cred"))
        dorks.append((f"site:{domain} ext:pfx", "leaked_cred"))
        dorks.append((f"site:{domain} filetype:pem certificate", "leaked_cred"))
        dorks.append((f"site:{domain} inurl:privkey", "leaked_cred"))
        dorks.append((f'site:{domain} "BEGIN RSA PRIVATE KEY"', "leaked_cred"))
        dorks.append((f'site:{domain} "BEGIN CERTIFICATE"', "leaked_cred"))

        # --- Infrastructure endpoints ---
        dorks.append((f"site:{domain} inurl:graphql", "normal"))
        dorks.append((f"site:{domain} inurl:swagger", "normal"))
        dorks.append((f"site:{domain} inurl:openapi", "normal"))
        dorks.append((f"site:{domain} inurl:v1 OR inurl:v2 OR inurl:v3", "normal"))
        dorks.append((f"site:{domain} inurl:health OR inurl:status", "normal"))
        dorks.append((f"site:{domain} inurl:login OR inurl:auth OR inurl:sso", "normal"))

        return dorks


# ---------------------------------------------------------------------------
# Search engine scrapers
# ---------------------------------------------------------------------------
class SearchScraper:
    """Scrape search engine result pages with WAF/CAPTCHA resilience."""

    # Result extraction regex patterns per engine
    _GOOGLE_LINK_RE = re.compile(r'href="(/url\?q=|)(https?://[^"&]+)', re.I)
    _BING_LINK_RE = re.compile(r'href="(https?://[^"]+)"', re.I)
    _DDG_LINK_RE = re.compile(r'href="(https?://[^"]+)"', re.I)
    _TITLE_RE = re.compile(r'<h[23][^>]*>(.*?)</h[23]>', re.I | re.S)
    _HOSTNAME_RE = re.compile(
        r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', re.I
    )

    def __init__(
        self,
        proxy_rotator: ProxyRotator,
        semaphore: asyncio.Semaphore,
    ) -> None:
        self._proxy = proxy_rotator
        self._sem = semaphore

    def _headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def _build_url(self, engine: SearchEngine, query: str, start: int = 0) -> str:
        encoded = quote_plus(query)
        if engine == SearchEngine.GOOGLE:
            return f"https://www.google.com/search?q={encoded}&num=20&start={start}&hl=en"
        elif engine == SearchEngine.BING:
            return f"https://www.bing.com/search?q={encoded}&count=20&first={start + 1}"
        else:  # DuckDuckGo
            return f"https://html.duckduckgo.com/html/?q={encoded}"

    def _is_captcha(self, html: str) -> bool:
        lower = html.lower()
        return any(sig in lower for sig in CAPTCHA_SIGNALS)

    def _extract_results(
        self,
        engine: SearchEngine,
        html: str,
        target_domain: str,
        dork_query: str,
        sensitivity: str,
    ) -> List[DorkResult]:
        results: List[DorkResult] = []
        seen_urls: Set[str] = set()

        # Extract all URLs from the page
        if engine == SearchEngine.GOOGLE:
            matches = self._GOOGLE_LINK_RE.findall(html)
            urls = [m[1] if m[1] else m[0] for m in matches]
        else:
            matches = self._BING_LINK_RE.findall(html) if engine == SearchEngine.BING else self._DDG_LINK_RE.findall(html)
            urls = matches

        for url in urls:
            url = url.strip().rstrip("/")
            if not url or url in seen_urls:
                continue

            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower().strip(".")
            if not hostname:
                continue

            # Filter: must be related to target domain
            if target_domain not in hostname:
                continue

            # Skip search engine internal URLs
            if any(skip in hostname for skip in ("google.", "bing.", "duckduckgo.", "microsoft.", "msn.")):
                continue

            seen_urls.add(url)
            results.append(DorkResult(
                url=url,
                hostname=hostname,
                engine=engine.value,
                dork_query=dork_query,
                sensitivity=sensitivity,
            ))

        return results

    async def scrape(
        self,
        session: aiohttp.ClientSession,
        engine: SearchEngine,
        query: str,
        target_domain: str,
        sensitivity: str,
        max_pages: int = 3,
    ) -> Tuple[List[DorkResult], int]:
        """
        Scrape a single dork query across multiple pages.
        Returns (results, captcha_block_count).
        """
        all_results: List[DorkResult] = []
        captcha_blocks = 0

        for page in range(max_pages):
            start = page * 20
            url = self._build_url(engine, query, start)

            for attempt in range(CAPTCHA_RETRY_LIMIT):
                proxy = self._proxy.next()
                async with self._sem:
                    try:
                        async with session.get(
                            url,
                            headers=self._headers(),
                            proxy=proxy,
                            timeout=aiohttp.ClientTimeout(total=SEARCH_TIMEOUT_SEC),
                            ssl=False,
                        ) as resp:
                            if resp.status != 200:
                                if proxy:
                                    self._proxy.mark_failure(proxy)
                                break

                            html = await resp.text()

                            if self._is_captcha(html):
                                captcha_blocks += 1
                                if proxy:
                                    self._proxy.mark_failure(proxy)
                                # Exponential backoff before retry
                                await asyncio.sleep(BACKOFF_BASE ** (attempt + 1) + random.uniform(0.5, 2.0))
                                continue

                            if proxy:
                                self._proxy.mark_success(proxy)

                            results = self._extract_results(engine, html, target_domain, query, sensitivity)
                            all_results.extend(results)
                            break

                    except (asyncio.TimeoutError, aiohttp.ClientError) as exc:
                        logger.debug(f"Search scrape error [{engine.value}]: {exc}")
                        if proxy:
                            self._proxy.mark_failure(proxy)
                        break

            # Polite delay between pages
            await asyncio.sleep(random.uniform(1.5, 3.5))

        return all_results, captcha_blocks


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
class SearchIntelligenceBridge:
    """
    Module 1 entry point.
    Orchestrates dorking across multiple engines, deduplicates results,
    classifies sensitivity, and produces an HNDL-penalty-aware report.
    """

    def __init__(
        self,
        proxy_pool: List[str] | None = None,
        engines: List[SearchEngine] | None = None,
        max_concurrent: int = MAX_CONCURRENT_SEARCHES,
    ) -> None:
        self._proxy_rotator = ProxyRotator(proxy_pool)
        self._engines = engines or [SearchEngine.GOOGLE, SearchEngine.BING, SearchEngine.DUCKDUCKGO]
        self._sem = asyncio.Semaphore(max_concurrent)

    async def execute(self, target_domain: str) -> SearchIntelReport:
        """Run the full search intelligence pipeline."""
        target = target_domain.lower().strip()
        report = SearchIntelReport(target_domain=target)
        start_time = time.perf_counter()

        dorks = DorkGenerator.generate(target)
        scraper = SearchScraper(self._proxy_rotator, self._sem)

        connector = aiohttp.TCPConnector(limit=20, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks: List[asyncio.Task] = []
            for engine in self._engines:
                for query, sensitivity in dorks:
                    tasks.append(
                        asyncio.create_task(
                            scraper.scrape(session, engine, query, target, sensitivity)
                        )
                    )

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.debug(f"Dork task failed: {result}")
                    continue
                dork_results, captcha_count = result
                report.total_queries_executed += 1
                report.captcha_blocks += captcha_count

                for dr in dork_results:
                    report.all_results.append(dr)
                    report.discovered_subdomains.add(dr.hostname)
                    report.discovered_urls.add(dr.url)
                    report.engines_used.add(dr.engine)

                    # Classify into penalty buckets
                    if dr.sensitivity == "exposed_config":
                        report.exposed_env_files.append(dr)
                    elif dr.sensitivity == "dev_server":
                        report.exposed_dev_servers.append(dr)
                    elif dr.sensitivity == "leaked_cred":
                        report.exposed_certs_keys.append(dr)

        report.elapsed_seconds = time.perf_counter() - start_time
        logger.info(
            f"[SEARCH-INTEL] {target}: {len(report.discovered_subdomains)} subdomains, "
            f"{len(report.all_results)} results, penalty={report.total_penalty:.1f}, "
            f"captcha_blocks={report.captcha_blocks}"
        )
        return report
