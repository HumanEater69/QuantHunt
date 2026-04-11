from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import quote

import httpx

try:
    import aiodns  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    aiodns = None

DISCOVERY_CONCURRENCY_LIMIT = 50
DNS_QUERY_TIMEOUT_SEC = 2.2
CRTSH_TIMEOUT_SEC = 10.0
CRTSH_RETRY_TIMEOUTS_SEC: tuple[float, ...] = (6.0, 10.0, 14.0)
CRTSH_MAX_TOTAL_SEC = 28.0
MAX_BRUTEFORCE_WORDS = 2500
HISTORY_TOKEN_LIMIT = 4000
MULTI_RESOLVER_NSLOOKUP_TIMEOUT_SEC = 2.8
AUTHORITATIVE_NS_MAX = 8
MULTI_VANTAGE_TIMEOUT_SEC = 12.0

# Preserve legacy target-specific coverage when historical wordlists were saved
# under an older hostname spelling.
DOMAIN_WORDLIST_ALIASES: dict[str, tuple[str, ...]] = {
    "manipurrural.bank.in": ("manipurral.bank.in",),
}

DEFAULT_WORDLIST: list[str] = [
    "mail",
    "vpn",
    "api",
    "dev",
    "secure",
    "portal",
    "banking",
    "www",
    "auth",
    "login",
    "sso",
    "mfa",
    "gateway",
    "admin",
    "mobile",
    "app",
    "web",
    "payments",
    "pay",
    "cards",
    "loan",
    "support",
    "status",
    "cdn",
    "edge",
    "uat",
    "staging",
    "test",
]

VPN_CANDIDATE_PREFIXES = ["vpn", "ipsec", "remote", "gateway", "securevpn"]

HIGH_VALUE_PREFIXES: list[str] = [
    "www",
    "api",
    "auth",
    "secure",
    "portal",
    "gateway",
    "mail",
    "mail1",
    "vpn",
    "ibanking",
    "netbanking",
    "kioskbanking",
    "hrms",
    "mbs",
    "ckyc",
    "fip",
    "fiu",
]

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

_BOOTSTRAP_TOKEN_CACHE: set[str] = set()
_BOOTSTRAP_CACHE_READY = False
_BOOTSTRAP_CACHE_SOURCE = "runtime"


def _normalize_domain(value: str | None) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _belongs_to_domain(host: str, domain: str) -> bool:
    host_l = _normalize_domain(host)
    domain_l = _normalize_domain(domain)
    return bool(host_l and domain_l and (host_l == domain_l or host_l.endswith(f".{domain_l}")))


def _seed_tokens_from_hosts(hosts: Iterable[str], domain: str) -> set[str]:
    domain_l = _normalize_domain(domain)
    out: set[str] = set()
    for host in hosts:
        h = _normalize_domain(host)
        if not _belongs_to_domain(h, domain_l):
            continue
        if h == domain_l:
            continue
        label = h[: -(len(domain_l) + 1)]
        if not label:
            continue
        left = label.split(".", 1)[0]
        for token in re.split(r"[^a-z0-9-]+", left):
            t = token.strip().lower()
            if t and _LABEL_RE.fullmatch(t):
                out.add(t)
    return out


def _valid_label(token: str) -> bool:
    t = str(token or "").strip().lower()
    return bool(t and _LABEL_RE.fullmatch(t))


def _ordered_unique(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        v = str(value or "").strip().lower()
        if not _valid_label(v) or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _expand_seed_words(seed_words: Iterable[str]) -> list[str]:
    """
    Build stronger DNS candidates from base tokens without exploding cardinality.
    """
    base = _ordered_unique(seed_words)
    expanded: list[str] = list(base)
    seen: set[str] = set(base)

    def add(token: str) -> None:
        t = str(token or "").strip().lower()
        if not _valid_label(t) or t in seen:
            return
        seen.add(t)
        expanded.append(t)

    # deterministic high-value additions first
    for token in HIGH_VALUE_PREFIXES:
        add(token)

    suffixes = ("api", "auth", "portal", "secure", "banking", "gateway")
    for token in list(base):
        # normalize common numeric variants: api1 -> api, login02 -> login
        stripped = re.sub(r"(?:0?[0-9])+$", "", token)
        if stripped and stripped != token:
            add(stripped)

        if token.endswith("bank") and len(token) <= 20:
            add(f"{token}ing")
        if token.endswith("ing") and len(token) > 4:
            add(token[:-3])

        # known banking lexical transforms
        if token == "kiosk":
            add("kioskbanking")
        if token == "ib":
            add("ibanking")
        if token == "net":
            add("netbanking")
        if token == "internet":
            add("internetbanking")
        if token == "ckycr":
            add("ckyc")

        if "-" not in token and 2 <= len(token) <= 18:
            for suffix in suffixes:
                combo = f"{token}{suffix}"
                if len(combo) <= 63:
                    add(combo)

    return expanded[:MAX_BRUTEFORCE_WORDS]


def _word_priority(token: str) -> tuple[int, int, str]:
    t = str(token or "").strip().lower()
    if t in HIGH_VALUE_PREFIXES:
        return (0, HIGH_VALUE_PREFIXES.index(t), t)
    if t in DEFAULT_WORDLIST:
        return (1, DEFAULT_WORDLIST.index(t), t)
    if re.fullmatch(r"[a-z]+", t):
        return (2, len(t), t)
    return (3, len(t), t)


def _rank_words(words: Iterable[str], limit: int | None = None) -> list[str]:
    ordered = sorted(_ordered_unique(words), key=_word_priority)
    max_items = max(32, int(limit or MAX_BRUTEFORCE_WORDS))
    return ordered[:max_items]


def _dedupe_domain_like(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        v = _normalize_domain(value)
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sqlite_paths() -> list[Path]:
    paths: list[Path] = []
    for env_name in ("DATABASE_URL", "BANKING_DATABASE_URL"):
        raw = os.getenv(env_name, "").strip()
        if raw.startswith("sqlite:///"):
            rel = raw[len("sqlite:///") :].strip()
            if rel:
                p = Path(rel)
                if not p.is_absolute():
                    p = _repo_root() / p
                paths.append(p)
    # Safety fallback for local default files.
    paths.extend(
        [
            _repo_root() / "quantumshield_banking.db",
            _repo_root() / "quantumshield_general.db",
        ]
    )

    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        key = key.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _history_suffixes(domain: str) -> list[str]:
    labels = [x for x in _normalize_domain(domain).split(".") if x]
    if len(labels) < 2:
        return [_normalize_domain(domain)]
    out = [_normalize_domain(domain)]
    for idx in range(1, len(labels) - 1):
        out.append(".".join(labels[idx:]))
    # Domain suffixes contain dots; do not run through label validator.
    return _dedupe_domain_like(out)


def _load_historical_inventory_tokens(domain: str, row_limit: int = HISTORY_TOKEN_LIMIT) -> set[str]:
    """
    Mine previously seen host labels from local scanner DBs (sibling domains included).
    This is critical when CT is slow/unavailable and short labels like fip/fiu/mbs are needed.
    """
    domain_l = _normalize_domain(domain)
    if not domain_l:
        return set()

    tokens: set[str] = set()
    suffixes = _history_suffixes(domain_l)
    limit_each = max(200, int(row_limit))

    for db_path in _sqlite_paths():
        if not db_path.exists() or not db_path.is_file():
            continue
        try:
            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()
        except Exception:
            continue

        try:
            for suffix in suffixes:
                like_pattern = f"%.{suffix}"
                with contextlib.suppress(Exception):
                    rows = cur.execute(
                        """
                        SELECT hostname FROM assets
                        WHERE lower(hostname)=lower(?)
                           OR lower(hostname) LIKE lower(?)
                        LIMIT ?
                        """,
                        (suffix, like_pattern, limit_each),
                    ).fetchall()
                    for (hostname,) in rows:
                        host = _normalize_domain(str(hostname or ""))
                        if not host:
                            continue
                        left = host.split(".", 1)[0]
                        if _valid_label(left):
                            tokens.add(left)
                        for part in re.split(r"[^a-z0-9-]+", left):
                            if _valid_label(part):
                                tokens.add(part.strip().lower())
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    return tokens


def _extract_hosts_from_blob(text: str, domain: str) -> set[str]:
    hosts: set[str] = set()
    domain_l = _normalize_domain(domain)
    if not text or not domain_l:
        return hosts

    pattern = re.compile(
        rf"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{re.escape(domain_l)}",
        re.IGNORECASE,
    )
    for match in pattern.findall(text):
        host = _normalize_domain(str(match).replace("*.", ""))
        if host and _belongs_to_domain(host, domain_l):
            hosts.add(host)
    return hosts


def _parse_crtsh_rows(raw: str, domain: str) -> set[str]:
    domain_l = _normalize_domain(domain)
    if not raw:
        return set()

    rows: list[dict] = []
    with contextlib.suppress(Exception):
        payload = json.loads(raw)
        if isinstance(payload, list):
            rows = [x for x in payload if isinstance(x, dict)]

    # crt.sh occasionally returns pseudo-NDJSON, parse line-by-line as fallback.
    if not rows:
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            with contextlib.suppress(Exception):
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)

    discovered: set[str] = set()
    for row in rows:
        for key in ("name_value", "common_name"):
            value = str(row.get(key, "") or "")
            if not value:
                continue
            for name in value.splitlines():
                host = _normalize_domain(name.replace("*.", ""))
                if host and _belongs_to_domain(host, domain_l):
                    discovered.add(host)

    # Last-resort recovery from malformed payloads or HTML/error pages.
    discovered.update(_extract_hosts_from_blob(raw, domain_l))
    return discovered


def _parse_dns_resolvers(explicit: Sequence[str] | None) -> list[str]:
    if explicit:
        return [str(x).strip() for x in explicit if str(x).strip()]
    env_raw = os.getenv("SCAN_DNS_RESOLVERS", "").strip()
    if not env_raw:
        return []
    return [x.strip() for x in env_raw.split(",") if x.strip()]


def _bool_env(name: str, default: bool = True) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _default_public_resolvers() -> list[str]:
    out = _parse_dns_resolvers(None)
    for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"):
        if ip not in out:
            out.append(ip)
    return out


def _run_nslookup_sync(args: list[str], timeout: float) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout),
            check=False,
        )
        return f"{proc.stdout}\n{proc.stderr}"
    except Exception:
        return ""


def _parse_nslookup_answer_ips(output: str) -> set[str]:
    text = str(output or "")
    ips: set[str] = set()
    in_answer = False
    for raw in text.splitlines():
        line = raw.strip()
        lower = line.lower()
        if not line:
            continue
        if lower.startswith("name:"):
            in_answer = True
            continue
        if not in_answer:
            continue
        if lower.startswith("address:") or lower.startswith("addresses:"):
            rhs = line.split(":", 1)[1].strip()
            for token in re.split(r"[,\s]+", rhs):
                tok = token.strip()
                if _is_ip_address(tok):
                    ips.add(tok)
        elif lower.startswith("aliases:"):
            continue
        elif "=" in line:
            # leave NS records to dedicated parser
            continue
        else:
            for token in re.split(r"[,\s]+", line):
                tok = token.strip()
                if _is_ip_address(tok):
                    ips.add(tok)
    return ips


def _resolve_with_nslookup_server_sync(host: str, server: str, timeout: float = MULTI_RESOLVER_NSLOOKUP_TIMEOUT_SEC) -> set[str]:
    host_l = _normalize_domain(host)
    server_l = str(server or "").strip()
    if not host_l or not server_l:
        return set()
    out = _run_nslookup_sync(["nslookup", host_l, server_l], timeout=timeout)
    return _parse_nslookup_answer_ips(out)


def _parse_ns_hosts_from_nslookup(output: str) -> set[str]:
    hosts: set[str] = set()
    text = str(output or "")
    for raw in text.splitlines():
        line = raw.strip()
        lower = line.lower()
        if "nameserver" in lower and "=" in line:
            rhs = line.split("=", 1)[1].strip().rstrip(".")
            host = _normalize_domain(rhs)
            if host and not _is_ip_address(host):
                hosts.add(host)
        elif lower.startswith("ns") and "=" in line:
            rhs = line.split("=", 1)[1].strip().rstrip(".")
            host = _normalize_domain(rhs)
            if host and not _is_ip_address(host):
                hosts.add(host)
    return hosts


def _lookup_authoritative_ns_hosts(domain: str, resolver_ips: Sequence[str]) -> set[str]:
    domain_l = _normalize_domain(domain)
    if not domain_l:
        return set()
    suffixes = [domain_l]
    labels = [x for x in domain_l.split(".") if x]
    if len(labels) > 2:
        suffixes.append(".".join(labels[1:]))
    hosts: set[str] = set()
    for suffix in suffixes:
        # system resolver first
        out = _run_nslookup_sync(["nslookup", "-type=NS", suffix], timeout=3.0)
        hosts.update(_parse_ns_hosts_from_nslookup(out))
        for resolver in resolver_ips:
            out = _run_nslookup_sync(["nslookup", "-type=NS", suffix, resolver], timeout=3.0)
            hosts.update(_parse_ns_hosts_from_nslookup(out))
    return hosts


def _lookup_authoritative_ns_ips(domain: str, resolver_ips: Sequence[str]) -> list[str]:
    ns_hosts = _lookup_authoritative_ns_hosts(domain, resolver_ips)
    ips: list[str] = []
    seen: set[str] = set()
    for ns_host in sorted(ns_hosts):
        try:
            infos = socket.getaddrinfo(ns_host, None, type=socket.SOCK_STREAM)
        except Exception:
            continue
        for family, _type, _proto, _canon, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
                continue
            ip = str(sockaddr[0]).strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
            if len(ips) >= AUTHORITATIVE_NS_MAX:
                return ips
    return ips


def _multi_vantage_endpoints() -> list[str]:
    raw = os.getenv("SCAN_MULTI_VANTAGE_ENDPOINTS", "").strip()
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        endpoint = part.strip()
        key = endpoint.lower()
        if endpoint and key not in seen:
            seen.add(key)
            out.append(endpoint)
    return out


def _extract_hosts_from_vantage_payload(payload: object, domain: str) -> set[str]:
    domain_l = _normalize_domain(domain)
    out: set[str] = set()
    if payload is None:
        return out
    if isinstance(payload, list):
        for item in payload:
            out.update(_extract_hosts_from_vantage_payload(item, domain_l))
        return out
    if isinstance(payload, dict):
        for key in ("assets", "hosts", "subdomains", "results"):
            if key in payload:
                out.update(_extract_hosts_from_vantage_payload(payload.get(key), domain_l))
        for key in ("host", "hostname", "fqdn", "domain", "asset"):
            value = payload.get(key)
            host = _normalize_domain(str(value or ""))
            if host and _belongs_to_domain(host, domain_l):
                out.add(host)
        return out
    host = _normalize_domain(str(payload))
    if host and _belongs_to_domain(host, domain_l):
        out.add(host)
    return out


async def _discover_from_multi_vantage(domain: str) -> set[str]:
    if not _bool_env("SCAN_MULTI_VANTAGE_ENABLED", default=False):
        return set()
    endpoints = _multi_vantage_endpoints()
    if not endpoints:
        return set()
    timeout = float(os.getenv("SCAN_MULTI_VANTAGE_TIMEOUT_SEC", str(MULTI_VANTAGE_TIMEOUT_SEC)))
    found: set[str] = set()
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)), follow_redirects=True) as client:
        for endpoint in endpoints:
            try:
                response = await client.get(endpoint, params={"domain": domain}, headers={"User-Agent": "QuantumShield/3.0"})
                if response.status_code >= 400:
                    continue
                payload = response.json()
                found.update(_extract_hosts_from_vantage_payload(payload, domain))
            except Exception:
                continue
    return found


def _candidate_wordlist_paths(domain: str) -> list[Path]:
    domain_l = _normalize_domain(domain)
    labels = [x for x in domain_l.split(".") if x]
    names: list[str] = [".".join(labels[idx:]) for idx in range(0, max(len(labels) - 1, 1))]
    for alias in DOMAIN_WORDLIST_ALIASES.get(domain_l, ()):
        alias_l = _normalize_domain(alias)
        if not alias_l:
            continue
        alias_labels = [x for x in alias_l.split(".") if x]
        names.extend(".".join(alias_labels[idx:]) for idx in range(0, max(len(alias_labels) - 1, 1)))
    names = _dedupe_domain_like(names)

    roots = [Path(__file__).resolve().parent / "wordlists"]
    override_root = os.getenv("SCAN_DOMAIN_WORDLIST_DIR", "").strip()
    if override_root:
        roots.insert(0, Path(override_root))

    paths: list[Path] = []
    for root in roots:
        for name in names:
            paths.append(root / f"{name}.txt")
    return paths


def _load_wordlist(domain: str, explicit_words: Sequence[str] | None = None) -> list[str]:
    words: list[str] = list(DEFAULT_WORDLIST)

    if explicit_words:
        for entry in explicit_words:
            token = str(entry).strip().lower()
            if token and _LABEL_RE.fullmatch(token):
                words.append(token)

    env_words = os.getenv("SCAN_DNS_WORDLIST", "").strip()
    if env_words:
        for entry in env_words.split(","):
            token = entry.strip().lower()
            if token and _LABEL_RE.fullmatch(token):
                words.append(token)

    env_file = os.getenv("SCAN_DNS_WORDLIST_FILE", "").strip()
    if env_file:
        path = Path(env_file)
        if path.exists() and path.is_file():
            with contextlib.suppress(Exception):
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    token = line.strip().lower()
                    if token and not token.startswith("#") and _LABEL_RE.fullmatch(token):
                        words.append(token)

    for path in _candidate_wordlist_paths(domain):
        if not path.exists() or not path.is_file():
            continue
        with contextlib.suppress(Exception):
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                token = line.strip().lower()
                if token and not token.startswith("#") and _LABEL_RE.fullmatch(token):
                    words.append(token)

    words.extend(get_bootstrap_dns_tokens())
    words.extend(_load_historical_inventory_tokens(domain))
    expanded = _expand_seed_words(words)
    return _rank_words(expanded, limit=MAX_BRUTEFORCE_WORDS)


class _AsyncResolver:
    """Resolve hostnames using system + public resolvers + authoritative NS union."""

    def __init__(
        self,
        nameservers: Sequence[str] | None = None,
        domain: str | None = None,
    ) -> None:
        self._resolver = None
        self._union_mode = _bool_env("SCAN_DNS_MULTI_RESOLVER_MODE", default=True)
        self._strict_union_mode = _bool_env("SCAN_DNS_STRICT_UNION", default=False)
        base_resolvers = [str(x).strip() for x in (nameservers or []) if str(x).strip()]
        if self._union_mode:
            for ip in _default_public_resolvers():
                if ip not in base_resolvers:
                    base_resolvers.append(ip)
        self._authoritative_resolvers: list[str] = []
        if self._union_mode and domain:
            with contextlib.suppress(Exception):
                self._authoritative_resolvers = _lookup_authoritative_ns_ips(domain, base_resolvers)
        self._resolver_targets = []
        seen_targets: set[str] = set()
        for resolver in [*base_resolvers, *self._authoritative_resolvers]:
            key = str(resolver or "").strip().lower()
            if not key or key in seen_targets:
                continue
            seen_targets.add(key)
            self._resolver_targets.append(str(resolver).strip())
        max_servers = max(2, int(os.getenv("SCAN_DNS_NSLOOKUP_RESOLVER_LIMIT", "6")))
        self._resolver_targets = self._resolver_targets[:max_servers]

        if aiodns is not None:
            with contextlib.suppress(Exception):
                if self._resolver_targets:
                    self._resolver = aiodns.DNSResolver(timeout=DNS_QUERY_TIMEOUT_SEC, nameservers=list(self._resolver_targets))
                else:
                    self._resolver = aiodns.DNSResolver(timeout=DNS_QUERY_TIMEOUT_SEC)

    async def resolve(self, host: str) -> set[str]:
        host_l = _normalize_domain(host)
        if not host_l:
            return set()

        addresses: set[str] = set()

        # 1) system resolver
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host_l, None, type=socket.SOCK_STREAM),
                timeout=DNS_QUERY_TIMEOUT_SEC,
            )
            for family, _type, _proto, _canon, sockaddr in infos:
                if family in (socket.AF_INET, socket.AF_INET6) and sockaddr:
                    addresses.add(str(sockaddr[0]))
        except Exception:
            pass

        # 2) async DNS client with configured resolver set (includes 1.1.1.1/8.8.8.8/auth NS where possible)
        if self._resolver is not None:
            for rrtype in ("A", "AAAA"):
                try:
                    query = self._resolver.query(host_l, rrtype)
                    records = await query if asyncio.iscoroutine(query) else await asyncio.wrap_future(query)
                    for record in records or []:
                        addr = str(getattr(record, "host", "") or getattr(record, "address", "") or "").strip()
                        if addr:
                            addresses.add(addr)
                except Exception:
                    continue

        # 3) explicit nslookup per resolver target for union coverage
        if self._union_mode and self._resolver_targets and (self._strict_union_mode or not addresses):
            for resolver_ip in self._resolver_targets:
                try:
                    ns_ips = await asyncio.to_thread(
                        _resolve_with_nslookup_server_sync,
                        host_l,
                        resolver_ip,
                        MULTI_RESOLVER_NSLOOKUP_TIMEOUT_SEC,
                    )
                except Exception:
                    ns_ips = set()
                if ns_ips:
                    addresses.update(ns_ips)
                    if not self._strict_union_mode:
                        break

        return addresses

    def resolver_targets(self) -> list[str]:
        return list(self._resolver_targets)

    def authoritative_resolver_ips(self) -> list[str]:
        return list(self._authoritative_resolvers)


async def _resolve_candidates_live(
    candidates: Iterable[str],
    resolver: _AsyncResolver,
) -> set[str]:
    sem = asyncio.Semaphore(DISCOVERY_CONCURRENCY_LIMIT)
    discovered: set[str] = set()

    async def _probe(host: str) -> None:
        host_l = _normalize_domain(host)
        if not host_l:
            return
        async with sem:
            addrs = await resolver.resolve(host_l)
            if addrs:
                discovered.add(host_l)

    await asyncio.gather(*(_probe(host) for host in sorted({_normalize_domain(x) for x in candidates if x})))
    return discovered


async def discover_from_crtsh(domain: str, timeout: float = CRTSH_TIMEOUT_SEC) -> set[str]:
    """
    Collect subdomains from crt.sh with retry and payload fallbacks.
    """
    domain_l = _normalize_domain(domain)
    if not domain_l:
        return set()

    json_urls = [
        f"https://crt.sh/?q=%25.{quote(domain_l)}&output=json",
        f"https://crt.sh/?Identity=%25.{quote(domain_l)}&output=json",
        f"https://crt.sh/?q={quote(domain_l)}&output=json",
    ]
    html_urls = [
        f"https://crt.sh/?q=%25.{quote(domain_l)}",
        f"https://crt.sh/?Identity=%25.{quote(domain_l)}",
        f"https://crt.sh/?q={quote(domain_l)}",
    ]
    headers = {"User-Agent": "QuantumShield/3.0", "Accept": "application/json,text/plain,text/html,*/*"}

    best_effort: set[str] = set()
    attempt_timeouts = [max(timeout, t) for t in CRTSH_RETRY_TIMEOUTS_SEC]
    started = asyncio.get_running_loop().time()

    for attempt, req_timeout in enumerate(attempt_timeouts, start=1):
        if (asyncio.get_running_loop().time() - started) > CRTSH_MAX_TOTAL_SEC:
            break

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(req_timeout, connect=min(req_timeout, 5.0)),
            follow_redirects=True,
        ) as client:
            # Pull multiple crt.sh query forms in parallel per attempt to avoid single endpoint bias.
            json_responses = await asyncio.gather(
                *(client.get(url, headers=headers) for url in json_urls),
                return_exceptions=True,
            )
            for response in json_responses:
                if isinstance(response, Exception):
                    continue
                if int(getattr(response, "status_code", 0)) >= 500:
                    continue
                raw = str(getattr(response, "text", "") or "").strip()
                if not raw:
                    continue
                best_effort.update(_parse_crtsh_rows(raw, domain_l))

            # Fallback for crt.sh degraded JSON responses: parse hostnames from HTML body.
            html_responses = await asyncio.gather(
                *(client.get(url, headers=headers) for url in html_urls),
                return_exceptions=True,
            )
            for response in html_responses:
                if isinstance(response, Exception):
                    continue
                if int(getattr(response, "status_code", 0)) >= 500:
                    continue
                raw = str(getattr(response, "text", "") or "").strip()
                if not raw:
                    continue
                best_effort.update(_extract_hosts_from_blob(raw, domain_l))

        # Once CT yields enough hosts, continue with DNS rounds rather than over-querying crt.sh.
        if len(best_effort) >= 3:
            break

        if attempt < len(attempt_timeouts):
            await asyncio.sleep(0.35 * attempt)

    return best_effort


async def discover_from_dns_bruteforce(
    domain: str,
    wordlist: list[str] | None = None,
    dns_resolvers: list[str] | None = None,
    dns_doh_endpoints: list[str] | None = None,
    dns_enable_doh: bool | None = None,
    resolver: _AsyncResolver | None = None,
    max_candidates: int | None = None,
) -> set[str]:
    """Brute-force subdomains asynchronously and keep only live DNS assets."""
    del dns_doh_endpoints, dns_enable_doh  # kept for API compatibility

    domain_l = _normalize_domain(domain)
    if not domain_l:
        return set()

    max_words = max(64, int(os.getenv("SCAN_DNS_MAX_CANDIDATES", "1000")))
    if max_candidates is not None:
        max_words = max(64, int(max_candidates))
    if wordlist is None:
        words = _rank_words(_expand_seed_words(_load_wordlist(domain_l)), limit=MAX_BRUTEFORCE_WORDS)
    else:
        focused = _ordered_unique({*wordlist, *HIGH_VALUE_PREFIXES})
        words = _rank_words(focused, limit=MAX_BRUTEFORCE_WORDS)
    words = words[:max_words]
    candidates = {domain_l, f"www.{domain_l}"}
    candidates.update({f"{token}.{domain_l}" for token in words})

    live_resolver = resolver or _AsyncResolver(_parse_dns_resolvers(dns_resolvers), domain=domain_l)
    return await _resolve_candidates_live(candidates, live_resolver)


async def _discover_vpn_signals_async(domain: str, resolver: _AsyncResolver) -> dict[str, dict[str, bool]]:
    candidates = {f"{prefix}.{domain}" for prefix in VPN_CANDIDATE_PREFIXES}
    live = await _resolve_candidates_live(candidates, resolver)
    return {host: {"udp_500": False, "udp_4500": False, "sstp": False} for host in live}


async def discover_deep_assets_async(
    domain: str,
    initial_seed_words: Iterable[str] | None = None,
    dns_resolvers: list[str] | None = None,
    dns_doh_endpoints: list[str] | None = None,
    dns_enable_doh: bool | None = None,
    max_rounds: int | None = None,
) -> set[str]:
    """Compatibility wrapper that performs one strong CT+DNS merge pass."""
    del max_rounds
    assets, _ = await discover_assets_async(
        domain,
        include_vpn_probes=False,
        wordlist=list(initial_seed_words or []),
        dns_resolvers=dns_resolvers,
        dns_doh_endpoints=dns_doh_endpoints,
        dns_enable_doh=dns_enable_doh,
    )
    return set(assets)


async def discover_assets_async(
    domain: str,
    include_vpn_probes: bool = True,
    wordlist: list[str] | None = None,
    dns_resolvers: list[str] | None = None,
    dns_doh_endpoints: list[str] | None = None,
    dns_enable_doh: bool | None = None,
    return_report: bool = False,
) -> tuple[list[str], dict[str, dict[str, bool]]] | tuple[list[str], dict[str, dict[str, bool]], dict[str, object]]:
    """
    Phase 1: deep asset discovery.

    1) CT log scraping (crt.sh) for registered names.
    2) Async DNS brute-force (aiodns/getaddrinfo) for hidden names.
    3) Merge + deduplicate + DNS-validate for live assets.
    """
    del dns_doh_endpoints, dns_enable_doh  # kept for API compatibility

    domain_l = _normalize_domain(domain)
    if not domain_l:
        empty_report = {
            "passive_discovered": [],
            "live_dns": [],
            "resolver_targets": [],
            "authoritative_ns_resolvers": [],
            "ct_passive": [],
            "multi_vantage_passive": [],
        }
        if return_report:
            return [], {}, empty_report
        return [], {}

    bootstrap_historical_dns_cache()
    resolver = _AsyncResolver(_parse_dns_resolvers(dns_resolvers), domain=domain_l)

    ct_hosts = await discover_from_crtsh(domain_l)
    vantage_hosts = await _discover_from_multi_vantage(domain_l)
    passive_discovered = {domain_l, *ct_hosts, *vantage_hosts}

    # Always validate passive sources because stale CT/vantage entries are common.
    live_ct_hosts = await _resolve_candidates_live(ct_hosts, resolver)
    live_vantage_hosts = await _resolve_candidates_live(vantage_hosts, resolver)

    ct_seed_words = _seed_tokens_from_hosts(passive_discovered, domain_l)
    history_tokens = _load_historical_inventory_tokens(domain_l)
    explicit_words = set(wordlist or [])

    wave_1_limit = max(160, int(os.getenv("SCAN_DNS_WAVE1_WORD_LIMIT", "260")))
    wave_2_limit = max(140, int(os.getenv("SCAN_DNS_WAVE2_WORD_LIMIT", "220")))
    wave_3_limit = max(120, int(os.getenv("SCAN_DNS_WAVE3_WORD_LIMIT", "180")))

    initial_words = _rank_words(
        _expand_seed_words({*explicit_words, *ct_seed_words, *history_tokens, *get_bootstrap_dns_tokens()}),
        limit=wave_1_limit,
    )[:wave_1_limit]

    # Wave 1: broad brute-force from CT + inventory + user-provided seeds.
    brute_wave_1 = await discover_from_dns_bruteforce(
        domain_l,
        wordlist=initial_words,
        dns_resolvers=dns_resolvers,
        resolver=resolver,
        max_candidates=wave_1_limit,
    )

    # Wave 2: recursively learn labels from newly live hosts and probe deeper.
    learned_tokens_wave_2 = _seed_tokens_from_hosts({*live_ct_hosts, *live_vantage_hosts, *brute_wave_1}, domain_l)
    wave_2_words = _rank_words(
        _expand_seed_words({*initial_words, *learned_tokens_wave_2, *history_tokens}),
        limit=wave_2_limit,
    )[:wave_2_limit]
    brute_wave_2 = await discover_from_dns_bruteforce(
        domain_l,
        wordlist=wave_2_words,
        dns_resolvers=dns_resolvers,
        resolver=resolver,
        max_candidates=wave_2_limit,
    )

    # Wave 3: focus on emergent host prefixes that often expose hidden internal-facing edges.
    learned_tokens_wave_3 = _seed_tokens_from_hosts({*brute_wave_1, *brute_wave_2}, domain_l)
    wave_3_words = _rank_words(
        _expand_seed_words({*wave_2_words, *learned_tokens_wave_3, *history_tokens}),
        limit=wave_3_limit,
    )[:wave_3_limit]
    brute_wave_3 = await discover_from_dns_bruteforce(
        domain_l,
        wordlist=wave_3_words,
        dns_resolvers=dns_resolvers,
        resolver=resolver,
        max_candidates=wave_3_limit,
    )

    assets = sorted(
        {
            domain_l,
            *live_ct_hosts,
            *live_vantage_hosts,
            *brute_wave_1,
            *brute_wave_2,
            *brute_wave_3,
        }
    )
    learn_bootstrap_dns_tokens(assets)

    vpn_signals: dict[str, dict[str, bool]] = {}
    if include_vpn_probes:
        vpn_signals = await _discover_vpn_signals_async(domain_l, resolver)
        assets = sorted({*assets, *vpn_signals.keys()})

    report = {
        "passive_discovered": sorted(passive_discovered),
        "live_dns": sorted(assets),
        "resolver_targets": resolver.resolver_targets(),
        "authoritative_ns_resolvers": resolver.authoritative_resolver_ips(),
        "ct_passive": sorted(ct_hosts),
        "multi_vantage_passive": sorted(vantage_hosts),
    }

    if return_report:
        return assets, vpn_signals, report
    return assets, vpn_signals


def bootstrap_historical_dns_cache(force_refresh: bool = False) -> dict[str, object]:
    """Compatibility cache hook used at service startup."""
    global _BOOTSTRAP_CACHE_READY, _BOOTSTRAP_CACHE_SOURCE

    if _BOOTSTRAP_CACHE_READY and not force_refresh:
        return {"ready": True, "source": _BOOTSTRAP_CACHE_SOURCE, "tokens": len(_BOOTSTRAP_TOKEN_CACHE)}

    if force_refresh:
        _BOOTSTRAP_TOKEN_CACHE.clear()

    env_tokens = os.getenv("SCAN_BOOTSTRAP_WORDS", "").strip()
    if env_tokens:
        for token in env_tokens.split(","):
            t = token.strip().lower()
            if t and _LABEL_RE.fullmatch(t):
                _BOOTSTRAP_TOKEN_CACHE.add(t)
        _BOOTSTRAP_CACHE_SOURCE = "env"
    else:
        _BOOTSTRAP_CACHE_SOURCE = "runtime"

    _BOOTSTRAP_CACHE_READY = True
    return {"ready": True, "source": _BOOTSTRAP_CACHE_SOURCE, "tokens": len(_BOOTSTRAP_TOKEN_CACHE)}


def get_bootstrap_dns_tokens() -> set[str]:
    if not _BOOTSTRAP_CACHE_READY:
        bootstrap_historical_dns_cache()
    return set(_BOOTSTRAP_TOKEN_CACHE)


def learn_bootstrap_dns_tokens(hosts: Iterable[str]) -> int:
    domain_like_hosts = {_normalize_domain(h) for h in hosts if _normalize_domain(h)}
    learned: set[str] = set()
    for host in domain_like_hosts:
        if "." not in host:
            continue
        left = host.split(".", 1)[0]
        for token in re.split(r"[^a-z0-9-]+", left):
            t = token.strip().lower()
            if t and _LABEL_RE.fullmatch(t):
                learned.add(t)

    before = len(_BOOTSTRAP_TOKEN_CACHE)
    _BOOTSTRAP_TOKEN_CACHE.update(learned)
    return len(_BOOTSTRAP_TOKEN_CACHE) - before


def discover_active_vpn_signals(domain: str) -> dict[str, dict[str, bool]]:
    domain_l = _normalize_domain(domain)
    if not domain_l:
        return {}

    async def _runner() -> dict[str, dict[str, bool]]:
        resolver = _AsyncResolver(_parse_dns_resolvers(None), domain=domain_l)
        return await _discover_vpn_signals_async(domain_l, resolver)

    return asyncio.run(_runner())


def discover_active_vpn_surfaces(domain: str) -> set[str]:
    return set(discover_active_vpn_signals(domain).keys())


def discover_assets(domain: str) -> list[str]:
    assets, _ = asyncio.run(discover_assets_async(domain))
    return assets


def discover_assets_with_vpn_signals(
    domain: str,
    include_vpn_probes: bool = True,
) -> tuple[list[str], dict[str, dict[str, bool]]]:
    return asyncio.run(discover_assets_async(domain, include_vpn_probes=include_vpn_probes))


def generate_candidate_assets(domain: str, limit: int = 120) -> list[str]:
    """Generate likely assets even when DNS visibility is restricted."""
    domain_l = _normalize_domain(domain)
    if not domain_l:
        return []

    words = _rank_words(_expand_seed_words(_load_wordlist(domain_l)), limit=max(120, int(limit or 120) * 5))
    candidates = [domain_l] + [f"{token}.{domain_l}" for token in words]

    deduped: list[str] = []
    seen: set[str] = set()
    for host in candidates:
        h = _normalize_domain(host)
        if h and h not in seen:
            seen.add(h)
            deduped.append(h)

    return deduped[: max(1, int(limit or 120))]
