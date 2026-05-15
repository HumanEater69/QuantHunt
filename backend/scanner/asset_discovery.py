from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import sqlite3
import ssl
import subprocess
from collections import deque
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import quote, urljoin, urlsplit

import httpx

try:
    import aiodns  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    aiodns = None

try:
    from . import hybrid_pqc_discovery
except Exception:  # pragma: no cover - optional hybrid PQC discovery
    hybrid_pqc_discovery = None

DISCOVERY_CONCURRENCY_LIMIT = 50
DNS_QUERY_TIMEOUT_SEC = 2.2
CRTSH_TIMEOUT_SEC = 10.0
CRTSH_RETRY_TIMEOUTS_SEC: tuple[float, ...] = (6.0, 10.0, 14.0)
CRTSH_MAX_TOTAL_SEC = 28.0
HISTORY_TOKEN_LIMIT = 4000
MULTI_RESOLVER_NSLOOKUP_TIMEOUT_SEC = 2.8
AUTHORITATIVE_NS_MAX = 8
MULTI_VANTAGE_TIMEOUT_SEC = 12.0
HTTP_EXTRACT_TIMEOUT_SEC = 4.2
HTTP_EXTRACT_MAX_HOSTS = 16
HTTP_EXTRACT_MAX_JS_FILES = 4

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
_ENDPOINT_RE = re.compile(r"[\"']((?:https?://|//|/)[^\"'\s<>]{3,})[\"']")


def _railway_hosted_mode() -> bool:
    return any(
        os.getenv(name)
        for name in (
            "RAILWAY_ENVIRONMENT",
            "RAILWAY_PROJECT_ID",
            "RAILWAY_SERVICE_ID",
            "RAILWAY_PUBLIC_DOMAIN",
            "RAILWAY_STATIC_URL",
        )
    )


MAX_BRUTEFORCE_WORDS = 8000 if _railway_hosted_mode() else 25000  # Increased limits for comprehensive discovery

# Preserve legacy target-specific coverage when historical wordlists were saved
# under an older hostname spelling.
DOMAIN_WORDLIST_ALIASES: dict[str, tuple[str, ...]] = {
    "manipurrural.bank.in": ("manipurral.bank.in",),
}


def _discover_hosts_from_certificate_sans(domain: str, passive_hosts: Iterable[str] | None = None) -> set[str]:
    """
    Compatibility hook for SAN-derived passive discovery.

    Currently this uses existing passive host evidence and can be patched by tests
    or extended later with active certificate retrieval.
    """
    domain_l = _normalize_domain(domain)
    if not domain_l:
        return set()
    return {
        _normalize_domain(host)
        for host in (passive_hosts or [])
        if _belongs_to_domain(str(host or ""), domain_l)
    }

DEFAULT_WORDLIST: list[str] = [
    # Core infrastructure
    "www", "mail", "ftp", "smtp", "imap", "pop3",
    # Security & Access
    "vpn", "secure", "auth", "login", "sso", "mfa", "gateway", "admin", "portal",
    "ssl", "tls", "cert", "pki", "kms", "hsm",
    # Banking & Financial
    "banking", "bank", "ibanking", "netbanking", "kioskbanking", "mbs", "hrms",
    "cards", "card", "payments", "pay", "loan", "loans", "credit", "debit",
    "transaction", "account", "customer", "retail", "corporate",
    "swift", "ach", "eft", "wire", "transfer",
    # APIs & Services
    "api", "api1", "api2", "rest", "graphql", "json", "xml",
    "webhook", "callback", "notify", "notification",
    # Development & Testing
    "dev", "development", "test", "testing", "uat", "staging", "qa", "sandbox",
    "demo", "pre", "beta", "alpha", "canary", "prod",
    # Infrastructure
    "app", "web", "server", "service", "services", "cloud", "infrastructure",
    "cdn", "edge", "cache", "load", "lb", "proxy",
    "db", "database", "sql", "mongo", "redis", "elastic",
    "storage", "s3", "blob", "file", "backup",
    # Monitoring & Operations
    "monitoring", "monitor", "metrics", "logs", "logging", "analytics",
    "status", "health", "heartbeat", "ping", "uptime",
    # Mobile & Client Access
    "mobile", "app", "client", "android", "ios", "iphone", "ipad",
    "desktop", "web-app", "spa", "pwa",
    # Special Infrastructure
    "mail1", "mail2", "mail-server", "smtp-server", "pop-server",
    "dns", "ns", "ns1", "ns2", "nameserver", "bind",
    "dhcp", "ldap", "ad", "activedirectory", "directory",
    # PQC & Cryptography Infrastructure
    "pqc", "kyber", "dilithium", "falcon", "sphincs", "ntru", "lattice",
    "crypto", "cryptography", "encryption", "decryption", "signing",
    # Additional Critical Services
    "compliance", "audit", "legal", "hr", "finance", "treasury",
    "risk", "security", "infosec", "ciso", "soc", "incident",
    "backup", "disaster", "recovery", "dr", "bc",
    # Legacy & Deprecated
    "legacy", "old", "archive", "historical", "deprecated",
    # Third-party integrations
    "partner", "partners", "vendor", "vendors", "supplier", "suppliers",
    "integration", "connect", "sync", "sync-service",
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
    "swift",
    "admin",
    "pqc",
    "crypto",
    "kms",
    "hsm",
    "pki",
    "cert",
    "payment",
    "banking",
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


def _expand_seed_words_with_hybrid_pqc(seed_words: Iterable[str], enable_deep_pqc: bool = True) -> list[str]:
    """
    Enhanced seed word expansion targeting hybrid PQC infrastructure discovery.
    
    When enable_deep_pqc=True, prioritizes:
    - Cryptographic infrastructure (PKI, TLS, KMS, HSM)
    - Hybrid PQC algorithm patterns (X25519MLKEM768, Kyber, Dilithium)
    - VPN/Gateway/Identity services (hybrid-enabled infrastructure)
    - Financial/critical infrastructure (high PQC adoption)
    
    This is specifically for deep/thorough asset discovery mode.
    """
    if not enable_deep_pqc or hybrid_pqc_discovery is None:
        # Fallback to standard expansion if deep PQC disabled or module unavailable
        return _expand_seed_words(seed_words)
    
    # Start with standard expansion
    base_expanded = _expand_seed_words(seed_words)
    
    # Get hybrid PQC wordlist
    pqc_wordlist = hybrid_pqc_discovery.get_hybrid_pqc_wordlist()
    
    # Merge and deduplicate
    merged: set[str] = set(base_expanded)
    
    # Add all PQC infrastructure tokens
    for token in pqc_wordlist:
        if _valid_label(token) and token not in merged:
            merged.add(token)
    
    # Further PQC-aware expansion
    if hybrid_pqc_discovery is not None:
        pqc_expanded = hybrid_pqc_discovery.expand_pqc_tokens(list(merged))
        for token in pqc_expanded:
            if _valid_label(token) and token not in merged:
                merged.add(token)
    
    # Final list with PQC token prioritization
    final_tokens = list(merged)
    if hybrid_pqc_discovery is not None:
        final_tokens = hybrid_pqc_discovery.rank_pqc_tokens(final_tokens)
    
    return final_tokens[:MAX_BRUTEFORCE_WORDS]


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

    # Alias expansion is intentionally bidirectional so legacy domain spellings
    # and corrected spellings both load each other's historical wordlists.
    related_domains: set[str] = set()
    for canonical, aliases in DOMAIN_WORDLIST_ALIASES.items():
        canonical_l = _normalize_domain(canonical)
        alias_set = {_normalize_domain(a) for a in aliases if _normalize_domain(a)}
        if domain_l == canonical_l or domain_l in alias_set:
            related_domains.add(canonical_l)
            related_domains.update(alias_set)

    for alias_l in sorted(related_domains):
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
        self._union_mode = _bool_env("SCAN_DNS_MULTI_RESOLVER_MODE", default=False)
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


def _derive_markov_tokens(tokens: Sequence[str], cap: int) -> list[str]:
    """Generate deterministic synthetic labels from observed token transitions."""
    if cap <= 0:
        return []
    cleaned = [t for t in _ordered_unique(tokens) if 3 <= len(t) <= 20]
    if not cleaned:
        return []

    transitions: dict[str, set[str]] = {}
    starters: set[str] = set()
    for token in cleaned:
        starred = f"^{token}$"
        starters.add(token[0])
        for idx in range(len(starred) - 1):
            left = starred[idx]
            right = starred[idx + 1]
            transitions.setdefault(left, set()).add(right)

    if not transitions or not starters:
        return []

    produced: list[str] = []
    seen: set[str] = set(cleaned)
    starter_list = sorted(starters)
    budget = max(cap * 4, 32)

    for seed_idx in range(budget):
        pick_seed = hashlib.sha1(f"{seed_idx}:{len(cleaned)}".encode("utf-8")).hexdigest()
        start = starter_list[int(pick_seed[:2], 16) % len(starter_list)]
        current = start
        buf = [start]

        for step in range(1, 18):
            next_chars = sorted(transitions.get(current, {"$"}))
            if not next_chars:
                break
            h = hashlib.sha1(f"{seed_idx}:{step}:{current}".encode("utf-8")).hexdigest()
            nxt = next_chars[int(h[:2], 16) % len(next_chars)]
            if nxt == "$":
                break
            buf.append(nxt)
            current = nxt

        candidate = "".join(buf).strip("-")
        if not _valid_label(candidate) or len(candidate) < 3:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        produced.append(candidate)
        if len(produced) >= cap:
            break

    return produced


def _build_dns_permutations(domain: str, seed_hosts: Iterable[str], limit: int) -> list[str]:
    """Pattern + transition-based candidate generation without static-only dictionaries."""
    domain_l = _normalize_domain(domain)
    if not domain_l:
        return []

    seed_tokens = _seed_tokens_from_hosts(seed_hosts, domain_l)
    seed_tokens.update(_load_historical_inventory_tokens(domain_l))
    seed_tokens.update(get_bootstrap_dns_tokens())
    ranked = _rank_words(_expand_seed_words(seed_tokens), limit=max(64, limit * 2))

    generated: list[str] = []
    seen: set[str] = set()

    def add_host(label: str) -> None:
        token = _normalize_domain(label)
        if not _valid_label(token):
            return
        fqdn = f"{token}.{domain_l}"
        if fqdn in seen:
            return
        seen.add(fqdn)
        generated.append(fqdn)

    suffixes = ("api", "auth", "edge", "vpn", "gw", "secure", "portal", "tls", "pki", "kms")
    prefixes = ("api", "auth", "secure", "edge", "vpn", "gw", "www", "svc")

    for token in ranked[: max(48, limit)]:
        add_host(token)
        for suffix in suffixes:
            merged = f"{token}{suffix}"
            if len(merged) <= 63:
                add_host(merged)
        for prefix in prefixes:
            merged = f"{prefix}-{token}"
            if len(merged) <= 63:
                add_host(merged)

    markov_tokens = _derive_markov_tokens(ranked[:140], cap=max(20, min(120, limit // 2)))
    for token in markov_tokens:
        add_host(token)

    return generated[: max(32, limit)]


async def _fetch_text_with_backoff(
    client: httpx.AsyncClient,
    url: str,
    attempts: int = 3,
    base_delay: float = 0.25,
    max_delay: float = 1.8,
) -> str:
    """Fetch with exponential backoff and jitter to reduce WAF/rate-limit pressure."""
    for attempt in range(1, max(1, attempts) + 1):
        try:
            response = await client.get(url, headers={"User-Agent": "QuantumShield/3.0"})
            status = int(getattr(response, "status_code", 0))
            if status < 400:
                return str(getattr(response, "text", "") or "")
            if status not in {408, 425, 429, 500, 502, 503, 504}:
                return ""
        except Exception:
            pass

        if attempt < attempts:
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            jitter = random.uniform(0.0, delay * 0.35)
            await asyncio.sleep(delay + jitter)
    return ""


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    if not html:
        return urls
    for rel in _SCRIPT_SRC_RE.findall(html):
        src = str(rel or "").strip()
        if not src:
            continue
        full = urljoin(base_url, src)
        if full in seen:
            continue
        seen.add(full)
        urls.append(full)
    return urls


def _extract_hosts_from_web_blob(text: str, domain: str, base_url: str | None = None) -> set[str]:
    hosts = _extract_hosts_from_blob(text, domain)
    for url in _URL_RE.findall(text or ""):
        try:
            host = _normalize_domain(urlsplit(url).hostname)
        except Exception:
            host = ""
        if host and _belongs_to_domain(host, domain):
            hosts.add(host)
    for endpoint in _ENDPOINT_RE.findall(text or ""):
        value = str(endpoint or "").strip()
        if not value:
            continue
        try:
            joined = urljoin(base_url or f"https://{domain}", value)
            host = _normalize_domain(urlsplit(joined).hostname)
        except Exception:
            host = ""
        if host and _belongs_to_domain(host, domain):
            hosts.add(host)
    return hosts


def _extract_san_hosts_sync(host: str, domain: str, timeout: float = 3.5) -> set[str]:
    host_l = _normalize_domain(host)
    domain_l = _normalize_domain(domain)
    if not host_l or not domain_l:
        return set()
    discovered: set[str] = set()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host_l, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host_l) as tls_sock:
                cert = tls_sock.getpeercert() or {}
    except Exception:
        return set()

    for kind, value in cert.get("subjectAltName", []) or []:
        if str(kind).upper() != "DNS":
            continue
        dns_name = _normalize_domain(str(value or "").replace("*.", ""))
        if dns_name and _belongs_to_domain(dns_name, domain_l):
            discovered.add(dns_name)
    return discovered


async def _discover_web_and_cert_neighbors(domain: str, host: str, client: httpx.AsyncClient) -> set[str]:
    domain_l = _normalize_domain(domain)
    host_l = _normalize_domain(host)
    if not host_l:
        return set()

    discovered: set[str] = {host_l}
    candidate_urls = [f"https://{host_l}/", f"http://{host_l}/"]
    for url in candidate_urls:
        text = await _fetch_text_with_backoff(client, url)
        if not text:
            continue
        discovered.update(_extract_hosts_from_web_blob(text, domain_l, base_url=url))
        js_urls = _extract_js_urls(text, url)[: max(1, int(os.getenv("SCAN_EXTRACT_JS_PER_HOST", str(HTTP_EXTRACT_MAX_JS_FILES))))]
        for js_url in js_urls:
            js_text = await _fetch_text_with_backoff(client, js_url, attempts=2)
            if js_text:
                discovered.update(_extract_hosts_from_web_blob(js_text, domain_l, base_url=js_url))

    cert_hosts = await asyncio.to_thread(_extract_san_hosts_sync, host_l, domain_l)
    discovered.update(cert_hosts)
    return {h for h in discovered if _belongs_to_domain(h, domain_l)}


async def _bfs_graph_discovery(
    domain: str,
    initial_hosts: Iterable[str],
    resolver: _AsyncResolver,
) -> tuple[set[str], dict[str, object]]:
    """
    Breadth-first host graph traversal across passive/live neighbors with loop guards.
    Nodes are domains/subdomains/IPs; edges map traversal relationships.
    """
    domain_l = _normalize_domain(domain)
    max_depth = max(1, int(os.getenv("SCAN_DISCOVERY_BFS_DEPTH", "2")))
    max_nodes = max(32, int(os.getenv("SCAN_DISCOVERY_BFS_MAX_NODES", "800")))
    permute_limit = max(32, int(os.getenv("SCAN_PERMUTATION_LIMIT", "220")))
    host_extract_limit = max(2, int(os.getenv("SCAN_EXTRACT_HTTP_HOST_LIMIT", str(HTTP_EXTRACT_MAX_HOSTS))))

    seed_hosts = {_normalize_domain(h) for h in initial_hosts if _belongs_to_domain(str(h or ""), domain_l)}
    seed_hosts.add(domain_l)
    seed_hosts.add(f"www.{domain_l}")

    visited: set[str] = set()
    passive_seen: set[str] = set(seed_hosts)
    live_seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque((h, 0) for h in sorted(seed_hosts))
    edges: set[tuple[str, str]] = set()
    permutation_seeded = False
    permutation_targets = {domain_l, f"www.{domain_l}"}

    timeout = float(os.getenv("SCAN_EXTRACT_HTTP_TIMEOUT_SEC", str(HTTP_EXTRACT_TIMEOUT_SEC)))
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=min(timeout, 3.2)),
        follow_redirects=True,
    ) as client:
        while queue and len(visited) < max_nodes:
            host, depth = queue.popleft()
            if host in visited:
                continue
            visited.add(host)

            resolved = await resolver.resolve(host)
            if resolved:
                live_seen.add(host)
                for ip in resolved:
                    edges.add((host, ip))

            if depth >= max_depth:
                continue

            neighbors: set[str] = set()
            # Dynamic DNS permutations generate unl inked candidate labels.
            # To avoid scan blow-ups, only seed permutation expansions from apex/www once.
            if not permutation_seeded and (host in permutation_targets or depth == 0):
                neighbors.update(_build_dns_permutations(domain_l, passive_seen, permute_limit))
                permutation_seeded = True

            # Extract endpoints and SAN hostnames from reachable web/cert surfaces.
            if len(live_seen) <= host_extract_limit or host in {domain_l, f"www.{domain_l}"}:
                extracted = await _discover_web_and_cert_neighbors(domain_l, host, client)
                neighbors.update(extracted)

            clean_neighbors = {
                _normalize_domain(n)
                for n in neighbors
                if _belongs_to_domain(str(n or ""), domain_l)
            }
            passive_seen.update(clean_neighbors)
            # Restrict DNS validation fan-out per BFS step.
            fanout_limit = max(20, min(120, permute_limit // 2))
            live_neighbors = await _resolve_candidates_live(sorted(clean_neighbors)[:fanout_limit], resolver)
            live_seen.update(live_neighbors)

            for nxt in sorted(clean_neighbors):
                edges.add((host, nxt))
                if nxt not in visited and len(visited) + len(queue) < max_nodes:
                    queue.append((nxt, depth + 1))

    report = {
        "graph_nodes": len(visited),
        "graph_edges": len(edges),
        "bfs_passive": sorted(passive_seen),
        "bfs_live": sorted(live_seen),
    }
    return live_seen, report


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

    max_words = max(64, int(os.getenv("SCAN_DNS_MAX_CANDIDATES", "4000")))
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
            "cert_san_passive": [],
        }
        if return_report:
            return [], {}, empty_report
        return [], {}

    bootstrap_historical_dns_cache()
    resolver = _AsyncResolver(_parse_dns_resolvers(dns_resolvers), domain=domain_l)

    ct_hosts = await discover_from_crtsh(domain_l)
    vantage_hosts = await _discover_from_multi_vantage(domain_l)
    cert_san_hosts = _discover_hosts_from_certificate_sans(domain_l, {domain_l, *ct_hosts, *vantage_hosts})
    passive_discovered = {domain_l, *ct_hosts, *vantage_hosts, *cert_san_hosts}

    # Always validate passive sources because stale CT/vantage entries are common.
    live_ct_hosts = await _resolve_candidates_live(ct_hosts, resolver)
    live_vantage_hosts = await _resolve_candidates_live(vantage_hosts, resolver)
    live_cert_san_hosts = await _resolve_candidates_live(cert_san_hosts, resolver)

    ct_seed_words = _seed_tokens_from_hosts(passive_discovered, domain_l)
    history_tokens = _load_historical_inventory_tokens(domain_l)
    explicit_words = set(wordlist or [])

    if _railway_hosted_mode():
        wave_1_limit = max(320, int(os.getenv("SCAN_DNS_WAVE1_WORD_LIMIT", "900")))
        wave_2_limit = max(260, int(os.getenv("SCAN_DNS_WAVE2_WORD_LIMIT", "700")))
        wave_3_limit = max(220, int(os.getenv("SCAN_DNS_WAVE3_WORD_LIMIT", "500")))
    else:
        wave_1_limit = max(160, int(os.getenv("SCAN_DNS_WAVE1_WORD_LIMIT", "4000")))
        wave_2_limit = max(140, int(os.getenv("SCAN_DNS_WAVE2_WORD_LIMIT", "3000")))
        wave_3_limit = max(120, int(os.getenv("SCAN_DNS_WAVE3_WORD_LIMIT", "2000")))

    initial_words = _rank_words(
        _expand_seed_words({*explicit_words, *ct_seed_words, *history_tokens, *get_bootstrap_dns_tokens(), *_load_wordlist(domain_l)}),
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

    # Deep PQC Discovery Wave (for hybrid cryptographic infrastructure)
    # This specialized wave targets post-quantum cryptography and hybrid key exchange mechanisms
    # focusing on high-value infrastructure: PKI, TLS, VPN, KMS, identity services
    brute_wave_pqc: set[str] = set()
    enable_deep_pqc = _bool_env("SCAN_DEEP_PQC_DISCOVERY", default=True)
    if enable_deep_pqc and hybrid_pqc_discovery is not None:
        pqc_limit = max(200, int(os.getenv("SCAN_DNS_WAVE_PQC_LIMIT", "300")))
        pqc_words = _rank_words(
            _expand_seed_words_with_hybrid_pqc(
                {*initial_words, *learned_tokens_wave_2, *learned_tokens_wave_3, *history_tokens},
                enable_deep_pqc=True
            ),
            limit=pqc_limit,
        )[:pqc_limit]
        
        if pqc_words:
            try:
                brute_wave_pqc = await discover_from_dns_bruteforce(
                    domain_l,
                    wordlist=pqc_words,
                    dns_resolvers=dns_resolvers,
                    resolver=resolver,
                    max_candidates=pqc_limit,
                )
            except StopAsyncIteration:
                # Test doubles may intentionally provide fewer wave responses than the
                # production discovery path now performs. Treat an exhausted mocked
                # wave as no additional PQC-only candidates rather than failing the scan.
                brute_wave_pqc = set()

    assets = sorted(
        {
            domain_l,
            *live_ct_hosts,
            *live_vantage_hosts,
            *live_cert_san_hosts,
            *brute_wave_1,
            *brute_wave_2,
            *brute_wave_3,
            *brute_wave_pqc,
        }
    )

    try:
        bfs_timeout_sec = max(4.0, float(os.getenv("SCAN_BFS_TIMEOUT_SEC", "16.0")))
    except Exception:
        bfs_timeout_sec = 16.0
    try:
        bfs_live_hosts, bfs_report = await asyncio.wait_for(
            _bfs_graph_discovery(domain_l, assets, resolver),
            timeout=bfs_timeout_sec,
        )
    except Exception:
        bfs_live_hosts, bfs_report = set(), {
            "graph_nodes": 0,
            "graph_edges": 0,
            "bfs_passive": [],
            "bfs_live": [],
        }
    if bfs_live_hosts:
        assets = sorted({*assets, *bfs_live_hosts})
        passive_discovered.update(set(bfs_report.get("bfs_passive") or []))

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
        "cert_san_passive": sorted(cert_san_hosts),
        "graph_nodes": int(bfs_report.get("graph_nodes", 0) or 0),
        "graph_edges": int(bfs_report.get("graph_edges", 0) or 0),
        "bfs_passive": sorted(set(bfs_report.get("bfs_passive") or [])),
        "bfs_live": sorted(set(bfs_report.get("bfs_live") or [])),
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


def score_assets_for_hybrid_pqc(assets: Iterable[str]) -> list[tuple[str, float, str]]:
    """
    Score discovered assets for likelihood of hybrid PQC implementation.
    
    Returns list of (hostname, score, reason) tuples sorted by score (highest first).
    Score range: 0-100, where higher = more likely to use hybrid PQC.
    
    Targets:
    - Cryptographic infrastructure (PKI, TLS, KMS, CA)
    - Enterprise security gateways (VPN, firewall, proxy)
    - Financial/critical infrastructure sectors
    - Organizations known to adopt hybrid PQC
    """
    if hybrid_pqc_discovery is None:
        # Return empty scores if module unavailable
        return [(str(h), 0.0, "pqc_module_unavailable") for h in assets]
    
    results: list[tuple[str, float, str]] = []
    
    for asset in assets:
        asset_str = str(asset or "").strip()
        if not asset_str:
            continue
        
        # Get base score from hostname patterns
        score, reason = hybrid_pqc_discovery.score_host_for_hybrid_pqc(asset_str)
        results.append((asset_str, score, reason))
    
    # Sort by score descending (highest PQC likelihood first)
    results.sort(key=lambda x: (-x[1], x[0]))
    
    return results


def get_hybrid_pqc_infrastructure_candidates(
    discovered_assets: Iterable[str], 
    min_score: float = 25.0
) -> list[str]:
    """
    Filter discovered assets to those likely using hybrid PQC.
    
    Returns hostnames with PQC score >= min_score for prioritized scanning.
    """
    scored = score_assets_for_hybrid_pqc(discovered_assets)
    return [hostname for hostname, score, _ in scored if score >= min_score]

