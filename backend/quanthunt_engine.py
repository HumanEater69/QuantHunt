import asyncio
import aiohttp
import aiodns
import ssl
import hashlib
import random
import string
import json
import socket
import time
import uuid
import re
import logging
from typing import Set, Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, max_concurrent: int = 20):
        self.sem = asyncio.Semaphore(max_concurrent)
        self.lock = asyncio.Lock()
        self.host_backoff: Dict[str, float] = {}

    async def acquire(self, host: str):
        async with self.lock:
            delay = self.host_backoff.get(host, 0)
        if delay:
            await asyncio.sleep(delay + random.random() * 0.5)
        await self.sem.acquire()

    async def release(self, host: str, success: bool):
        async with self.lock:
            if success:
                self.host_backoff[host] = max(0.0, self.host_backoff.get(host, 0) * 0.5)
            else:
                prev = self.host_backoff.get(host, 0.1)
                self.host_backoff[host] = min(30.0, max(prev * 2.0, 0.5))
        self.sem.release()


def random_user_agent() -> str:
    browsers = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ver} Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36',
    ]
    ver = f"{random.randint(80,114)}.0.{random.randint(1000,5000)}." + str(random.randint(10,200))
    return random.choice(browsers).format(ver=ver)


class Orchestrator:
    def __init__(self, concurrency: int = 60, socket_timeout: int = 8):
        self.rate = RateLimiter(max_concurrent=concurrency)
        self.socket_timeout = socket_timeout
        self.visited_hashes: Set[str] = set()

    def mark_visited(self, url: str) -> bool:
        h = hashlib.sha256(url.encode()).hexdigest()
        if h in self.visited_hashes:
            return False
        self.visited_hashes.add(h)
        return True


class PassiveCrawler:
    def __init__(self, orchestrator: Orchestrator, session: aiohttp.ClientSession, max_depth: int = 2):
        self.orch = orchestrator
        self.session = session
        self.max_depth = max_depth
        self.passive_discovered: Set[str] = set()

    async def tls_san_scrape(self, host: str) -> List[str]:
        try:
            await self.orch.rate.acquire(host)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ctx), timeout=self.orch.socket_timeout
            )
            sslobj = writer.get_extra_info('ssl_object')
            cert = sslobj.getpeercert()
            writer.close()
            await writer.wait_closed()
            san = []
            for typ, val in cert.get('subjectAltName', []):
                if typ.lower() == 'dns':
                    san.append(val)
            return san
        except Exception:
            return []
        finally:
            await self.orch.rate.release(host, success=True)

    async def fetch_text(self, url: str) -> Optional[str]:
        headers = {'User-Agent': random_user_agent(), 'Accept': '*/*'}
        host = urlparse(url).hostname or 'default'
        try:
            await self.orch.rate.acquire(host)
            async with self.session.get(url, headers=headers, timeout=self.orch.socket_timeout) as resp:
                if resp.status == 200:
                    return await resp.text()
        except:
            return None
        finally:
            await self.orch.rate.release(host, success=True)

    def extract_hosts_and_resources(self, base: str, text: str) -> Set[str]:
        hosts = set()
        for m in re.findall(r"(?:href|src|url|action|data-url)=[\'\"]([^\'\"]+)[\'\"]", text, flags=re.I):
            if m.startswith('http'):
                try:
                    h = urlparse(m).hostname
                    if h and self._is_valid_hostname(h): hosts.add(h.lower())
                except: continue
            elif m.startswith('//'):
                try:
                    h = m[2:].split('/')[0]
                    if self._is_valid_hostname(h): hosts.add(h.lower())
                except: continue
        
        domain_parts = base.split('.')
        if len(domain_parts) >= 2:
            root_domain = ".".join(domain_parts[-2:])
            pattern = rf"(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{re.escape(root_domain)}"
            for m in re.findall(pattern, text, flags=re.I):
                m = m.lower().rstrip('.')
                if self._is_valid_hostname(m): hosts.add(m)
        return hosts
    
    def _is_valid_hostname(self, host: str) -> bool:
        if not host or len(host) > 253: return False
        if host.startswith('-') or host.endswith('-'): return False
        if any(x in host for x in ['localhost', '127.0.0.1', '192.168', '10.0', '172.16']): return False
        return True

    async def crawl(self, root: str):
        if '://' not in root: root = 'https://' + root
        queue = [(root, 0)]
        base_host = urlparse(root).hostname or root.split('://')[-1].split('/')[0]
        while queue:
            url, depth = queue.pop(0)
            if depth > self.max_depth or not self.orch.mark_visited(url): continue
            text = await self.fetch_text(url)
            if not text: continue
            hosts = self.extract_hosts_and_resources(base_host, text)
            self.passive_discovered.update(hosts)
            
            js_urls = set()
            for m in re.findall(r"[\'\"]([^\'\"]+\.js(?:[\?#][^\'\"]*)?)[\'\"]", text, flags=re.I):
                js_urls.add(urljoin(url, m))
            for j in list(js_urls)[:10]:
                jtxt = await self.fetch_text(j)
                if jtxt:
                    self.passive_discovered.update(self.extract_hosts_and_resources(base_host, jtxt))
            
            for link in re.findall(r"href=[\'\"]([^\'\"]+)[\'\"]", text, flags=re.I):
                full_url = urljoin(url, link)
                parsed = urlparse(full_url)
                if parsed.hostname and (parsed.hostname == base_host or parsed.hostname.endswith('.' + base_host)):
                    if parsed.path != urlparse(url).path:
                        queue.append((full_url, depth + 1))


class Mutator:
    def __init__(self):
        self.common_words = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
            'smtp', 'vpn', 'm', 'shop', 'ftp', 'mail2', 'test', 'dev', 'portal', 
            'api', 'news', 'endpoint', 'ads', 'secure', 'admin', 'cdn', 'pop', 
            'static', 'cloud', 'dev2', 'app', 'docs', 'mobile', 'svn', 'git', 
            'exchange', 'autodiscover', 'owa', 'imap', 'pop3', 'support', 'wiki', 
            'help', 'chat', 'direct', 'mx', 'video', 'search', 'login', 'demo', 
            'beta', 'staging', 'qa', 'intranet', 'gateway', 'auth', 'lb', 'proxy', 
            'irc', 'voice', 'tracking', 'stat', 'reports', 'web', 'manager', 'db', 
            'sql', 'internal', 'crm', 'erp', 'ops', 'jira', 'confluence', 'monitor', 
            'alert', 'zabbix', 'nagios', 'grafana', 'kibana', 'elastic', 'gitlab', 
            'bitbucket', 'jenkins', 'build', 'ci', 'cd', 'deploy', 'uat', 'prod', 
            'sandbox', 'lab', 'backups', 'files', 'storage', 'media', 'img', 
            'assets'
        ]

    def generate(self, target: str) -> Set[str]:
        out = set()
        parts = target.split('.')
        base = ".".join(parts[-2:]) if len(parts) >= 2 else target
        for w in self.common_words:
            out.add(f"{w}.{target}")
            if base != target: out.add(f"{w}.{base}")
        return out


class Resolver:
    def __init__(self, orchestrator: Orchestrator, concurrency: int = 200):
        self.orch = orchestrator
        self.resolver = aiodns.DNSResolver()
        self.lock = asyncio.Semaphore(concurrency)
        self.wildcard_ips: Set[str] = set()
        self.live_dns: Set[str] = set()

    async def resolve_a_record(self, host: str) -> List[str]:
        try:
            async with self.lock:
                res = await asyncio.wait_for(self.resolver.gethostbyname(host, socket.AF_INET), timeout=5)
                return res.addresses
        except:
            return []

    async def detect_wildcard(self, target: str) -> bool:
        samples = [f"{''.join(random.choices(string.ascii_lowercase, k=16))}.{target}" for _ in range(3)]
        io = []
        for s in samples:
            a = await self.resolve_a_record(s)
            if a: io.append(set(a))
        if len(io) == 3:
            common = io[0] & io[1] & io[2]
            if common:
                self.wildcard_ips.update(common)
                return True
        return False

    async def bulk_resolve(self, hosts: Set[str], target_domain: str):
        is_wildcard = await self.detect_wildcard(target_domain)
        async def _check(h: str):
            ips = await self.resolve_a_record(h)
            if ips:
                if is_wildcard:
                    if not set(ips).issubset(self.wildcard_ips): self.live_dns.add(h)
                else: self.live_dns.add(h)
        await asyncio.gather(*[_check(h) for h in hosts])


class TLSProber:
    def __init__(self, orchestrator: Orchestrator):
        self.orch = orchestrator
        self.sem = asyncio.Semaphore(100)

    async def probe_tls(self, host: str) -> Dict[str, Any]:
        res = {"host": host, "tls_version": None, "key_alg": None}
        try:
            async with self.sem:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, 443, ssl=ctx), timeout=5)
                sslobj = writer.get_extra_info('ssl_object')
                res['tls_version'] = sslobj.version()
                writer.close()
                await writer.wait_closed()
        except: pass
        return res


async def run_quanthunt_scan(target_domain: str) -> str:
    target_domain = target_domain.strip().lower().replace('https://', '').replace('http://', '').split('/')[0]
    orch = Orchestrator()
    async with aiohttp.ClientSession() as session:
        crawler = PassiveCrawler(orch, session)
        mutator = Mutator()
        resolver = Resolver(orch)
        prober = TLSProber(orch)
        
        san_task = asyncio.create_task(crawler.tls_san_scrape(target_domain))
        crawl_task = asyncio.create_task(crawler.crawl(target_domain))
        muts = mutator.generate(target_domain)
        
        san = await san_task
        await crawl_task
        
        all_hosts = set(crawler.passive_discovered) | set(san) | muts
        await resolver.bulk_resolve(all_hosts, target_domain)
        
        live = resolver.live_dns
        t_ips = await resolver.resolve_a_record(target_domain)
        if t_ips: live.add(target_domain)
        
        pqc = []
        if live:
            tasks = [prober.probe_tls(h) for h in list(live)[:50]]
            pqc = [r for r in await asyncio.gather(*tasks) if r.get('tls_version')]
            
        return json.dumps({
            'target': target_domain,
            'metrics': {'passive_discovered': len(all_hosts), 'live_dns': len(live), 'live_tls_measured': len(pqc)},
            'pqc_posture_data': pqc
        }, indent=2)
