from __future__ import annotations

import base64
import json
import os
import re
import socket
import urllib.request

from ..models import APIInfo

def _api_ports_from_env() -> list[int]:
    raw = os.getenv("SCAN_API_PORTS", "443,8443,8080")
    out: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            value = int(token)
        except ValueError:
            continue
        if 1 <= value <= 65535:
            out.append(value)
    return out or [443, 8443, 8080]

API_PORTS = _api_ports_from_env()

def _float_env(name: str, default: float, minimum: float = 0.1) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        return default

def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def _extract_jwt_algs(text: str) -> list[str]:
    algs: set[str] = set()
    token_pattern = re.compile(r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")
    for token in token_pattern.findall(text):
        try:
            header_b64 = token.split(".")[0]
            padding = "=" * (-len(header_b64) % 4)
            payload = base64.urlsafe_b64decode(header_b64 + padding)
            obj = json.loads(payload.decode("utf-8", errors="ignore"))
            alg = obj.get("alg")
            if alg:
                algs.add(str(alg))
        except Exception:
            continue
    return sorted(algs)

def analyze_api(host: str, timeout: float | None = None) -> APIInfo:
    if timeout is None:
        timeout = _float_env("SCAN_API_TIMEOUT_SEC", 1.8, minimum=0.2)
    port_timeout = _float_env("SCAN_API_PORT_TIMEOUT_SEC", 0.45, minimum=0.1)
    info = APIInfo(host=host)
    info.api_ports_open = [p for p in API_PORTS if _port_open(host, p, timeout=port_timeout)]

    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": "QuantumShield/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read(4096).decode("utf-8", errors="ignore")
                info.jwt_algorithms.extend(_extract_jwt_algs(text))
                headers = {k: v for k, v in resp.headers.items()}
                for h in ("Strict-Transport-Security", "X-Content-Type-Options"):
                    if h in headers:
                        info.security_headers[h] = headers[h]
                for h in ("Server", "X-Powered-By"):
                    if h in headers:
                        info.framework_hints[h] = headers[h]
            break
        except Exception:
            continue

    info.jwt_algorithms = sorted(set(info.jwt_algorithms))
    return info
