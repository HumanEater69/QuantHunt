from __future__ import annotations

import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import urllib.request

COMMON_SUBDOMAINS = [
    "api",
    "www",
    "mail",
    "vpn",
    "admin",
    "mobile",
    "gateway",
    "netbanking",
    "uat",
    "dev",
]

VPN_CANDIDATE_PREFIXES = [
    "vpn",
    "ipsec",
    "ike",
    "sstp",
    "remote",
    "securevpn",
    "gateway",
]

_IKEV1_HEADER_PROBE = (
    b"\x00\x00\x00\x00\x00\x00\x00\x01"
    + b"\x00\x00\x00\x00\x00\x00\x00\x00"
    + b"\x00\x10\x02\x00"
    + b"\x00\x00\x00\x00"
    + b"\x00\x00\x00\x1c"
)

_IKE_NATT_HEADER_PROBE = b"\x00\x00\x00\x00" + _IKEV1_HEADER_PROBE

def _adaptive_subdomain_candidates(domain: str) -> list[str]:
    labels = [x for x in domain.lower().split(".") if x]
    orgish = {x for x in labels[:-1] if len(x) >= 3}
    generated: set[str] = set(COMMON_SUBDOMAINS)
    for token in orgish:
        generated.add(f"{token}-api")
        generated.add(f"{token}-gateway")
        generated.add(f"{token}-vpn")
        generated.add(f"api-{token}")
        generated.add(f"secure-{token}")
    return sorted(generated)

def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False

def _udp_probe(host: str, port: int, payload: bytes, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (host, port))
            data, _ = sock.recvfrom(2048)
            return bool(data)
    except OSError:
        return False

def _is_sstp_endpoint(host: str, timeout: float = 1.4) -> bool:
    req = (
        "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 18446744073709551615\r\n"
        "\r\n"
    ).encode("ascii")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(req)
                data = tls_sock.recv(1024)
                if not data:
                    return False
                text = data.decode("latin1", errors="ignore").upper()
                return "SSTP" in text or "SRA_" in text
    except OSError:
        return False

def discover_active_vpn_surfaces(domain: str) -> set[str]:
    return set(discover_active_vpn_signals(domain).keys())

def discover_active_vpn_signals(domain: str) -> dict[str, dict[str, bool]]:
    base = domain.lower().strip()
    candidates = {base}
    candidates.update({f"{prefix}.{base}" for prefix in VPN_CANDIDATE_PREFIXES})

    active: dict[str, dict[str, bool]] = {}

    def _probe_host(host: str) -> tuple[str, dict[str, bool] | None]:
        if not _resolves(host):
            return host, None
        ike500 = _udp_probe(host, 500, _IKEV1_HEADER_PROBE)
        ike4500 = _udp_probe(host, 4500, _IKE_NATT_HEADER_PROBE)
        sstp = _is_sstp_endpoint(host)
        if ike500 or ike4500 or sstp:
            return host, {"udp_500": ike500, "udp_4500": ike4500, "sstp": sstp}
        return host, None

    hosts = sorted(candidates)
    workers = max(4, min(16, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_probe_host, host) for host in hosts]
        for fut in as_completed(futures):
            host, signals = fut.result()
            if signals:
                active[host] = signals
    return active

def discover_from_crtsh(domain: str, timeout: float = 8.0) -> set[str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield/1.0"})
    assets: set[str] = set()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    for row in data:
        value = str(row.get("name_value", "")).strip().lower()
        for part in value.splitlines():
            part = part.replace("*.", "").strip()
            if part and part.endswith(domain):
                assets.add(part)
    return assets

def discover_from_dns_bruteforce(domain: str) -> set[str]:
    assets: set[str] = set()
    hosts = [f"{prefix}.{domain}".lower() for prefix in _adaptive_subdomain_candidates(domain)]

    def _resolve_host(host: str) -> str | None:
        try:
            socket.gethostbyname(host)
            return host
        except OSError:
            return None

    workers = max(6, min(24, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_resolve_host, host) for host in hosts]
        for fut in as_completed(futures):
            hit = fut.result()
            if hit:
                assets.add(hit)
    return assets

def discover_assets(domain: str) -> list[str]:
    assets, _ = discover_assets_with_vpn_signals(domain)
    return assets

def discover_assets_with_vpn_signals(domain: str) -> tuple[list[str], dict[str, dict[str, bool]]]:
    assets: set[str] = {domain.lower()}
    try:
        assets.update(discover_from_crtsh(domain))
    except Exception:
        pass
    assets.update(discover_from_dns_bruteforce(domain))

    vpn_signals = discover_active_vpn_signals(domain)
    assets.update(vpn_signals.keys())
    return sorted(assets), vpn_signals
