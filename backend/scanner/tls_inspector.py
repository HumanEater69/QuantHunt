from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from typing import Any

import httpx

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    x509 = None
    rsa = None
    ec = None
    ed25519 = None
    ed448 = None

from ..models import TLSInfo
from .cipher_database import get_cipher_metadata
from .cipher_parser import parse_cipher_suite

TLS_PROBE_CONCURRENCY_LIMIT = 50
SERVICE_PROBE_PORTS: tuple[int, ...] = (25, 465, 587, 993, 995, 8443, 9443)
IMPLICIT_TLS_PORTS: set[int] = {465, 993, 995, 8443, 9443}
SMTP_STARTTLS_PORTS: set[int] = {25, 587}
TLS_CONNECT_ATTEMPTS = 4

_SEM_BY_LOOP: dict[int, asyncio.Semaphore] = {}


def _get_probe_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    key = id(loop)
    sem = _SEM_BY_LOOP.get(key)
    if sem is None:
        sem = asyncio.Semaphore(TLS_PROBE_CONCURRENCY_LIMIT)
        _SEM_BY_LOOP[key] = sem
    return sem


def _normalize_sig_algo(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = str(value).strip().upper().replace(" ", "")
    if not cleaned:
        return None
    if "RSA-PSS" in cleaned or "RSAPSS" in cleaned:
        return "RSA-PSS"
    if "ECDSA" in cleaned:
        return "ECDSA"
    if "ED25519" in cleaned:
        return "Ed25519"
    if "ED448" in cleaned:
        return "Ed448"
    if "RSA" in cleaned:
        return "RSA"
    if any(token in cleaned for token in ("MLDSA", "ML-DSA", "DILITHIUM")):
        return "ML-DSA"
    if any(token in cleaned for token in ("SLHDSA", "SLH-DSA", "SPHINCS")):
        return "SLH-DSA"
    return cleaned


def _name_tuple_to_str(name_tuple: tuple[tuple[str, str], ...] | None) -> str | None:
    if not name_tuple:
        return None
    parts: list[str] = []
    for pair in name_tuple:
        if not pair:
            continue
        key, value = pair[0]
        parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def _extract_group_signals(openssl_text: str) -> tuple[str | None, list[str]]:
    text = str(openssl_text or "")
    group_name: str | None = None
    group_ids: list[str] = []

    for line in text.splitlines():
        s = line.strip()
        lower = s.lower()
        if "server temp key:" in lower:
            group_name = s.split(":", 1)[1].split(",", 1)[0].strip().upper()
        elif "negotiated tls1.3 group:" in lower:
            group_name = s.split(":", 1)[1].split(",", 1)[0].strip().upper()
        elif lower.startswith("group:") and not group_name:
            group_name = s.split(":", 1)[1].split(",", 1)[0].strip().upper()

    for match in re.findall(r"0x[0-9a-fA-F]{4}", text):
        up = match.upper()
        if up not in group_ids:
            group_ids.append(up)

    blob = text.upper()
    known_hybrid = (
        "X25519MLKEM768",
        "X25519_MLKEM768",
        "SECP256R1MLKEM768",
        "SECP384R1MLKEM1024",
        "X25519KYBER768DRAFT00",
        "ML-KEM",
        "KYBER",
    )
    if any(token in blob for token in known_hybrid) and not group_name:
        if "X25519MLKEM768" in blob or "X25519_MLKEM768" in blob:
            group_name = "X25519MLKEM768"
        elif "SECP256R1MLKEM768" in blob:
            group_name = "SECP256R1MLKEM768"
        elif "SECP384R1MLKEM1024" in blob:
            group_name = "SECP384R1MLKEM1024"
        elif "X25519KYBER768DRAFT00" in blob:
            group_name = "X25519KYBER768DRAFT00"
        elif "ML-KEM" in blob or "KYBER" in blob:
            group_name = "ML-KEM"

    return group_name, group_ids


def _build_cipher_analysis_rows(ciphers: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for suite in ciphers:
        parsed = parse_cipher_suite(suite)
        rows.append(
            {
                "suite": parsed.get("suite", suite),
                "key_exchange": parsed.get("key_exchange", "unknown"),
                "authentication": parsed.get("authentication", "unknown"),
                "bulk_cipher": parsed.get("bulk_cipher", "unknown"),
                "mode": parsed.get("mode", "unknown"),
                "hash": parsed.get("hash", "unknown"),
                "forward_secrecy": bool(parsed.get("forward_secrecy", False)),
                "pqc_signal": bool(parsed.get("pqc_signal", False)),
                "security_level": str(parsed.get("security_level", "unknown")),
            }
        )
    return rows


def _attach_cipher_context(info: TLSInfo) -> None:
    parsed = parse_cipher_suite(info.cipher_suite)
    info.cipher_components = parsed
    info.cipher_metadata = get_cipher_metadata(info.cipher_suite)

    info.key_exchange_algorithm = str(parsed.get("key_exchange") or "").strip() or None

    if info.key_exchange_group:
        group_upper = info.key_exchange_group.upper()
        if any(token in group_upper for token in ("MLKEM", "ML-KEM", "KYBER")):
            info.key_encapsulation_mechanism = "ML-KEM" if "ML" in group_upper else "KYBER"
            info.key_exchange_family = "hybrid-pqc-classical" if any(
                token in group_upper for token in ("X25519", "SECP256R1", "SECP384R1", "P-256", "P-384")
            ) else "pqc"
        elif info.key_exchange_algorithm:
            info.key_exchange_family = "classical"
    elif info.key_exchange_algorithm:
        info.key_exchange_family = "classical"


def _build_context(permissive: bool = False) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_COMPRESSION
    with contextlib.suppress(Exception):
        context.set_alpn_protocols(["h2", "http/1.1"])
    if permissive:
        with contextlib.suppress(Exception):
            context.set_ciphers("DEFAULT:@SECLEVEL=1")
    return context


def _classify_failure(message: str | None) -> tuple[str, str]:
    msg = str(message or "").strip()
    lower = msg.lower()
    if not lower:
        return "probe_failed", "TLS probe failed"

    if any(term in lower for term in ("name or service not known", "nodename nor servname", "getaddrinfo", "dns")):
        return "dns_resolution", "Unreachable (DNS Resolution Failed)"
    if any(term in lower for term in ("connection refused", "actively refused", "10061")):
        return "service_closed", "Port open check failed (Service Closed/Refused)"
    if any(term in lower for term in ("eof occurred", "unexpected eof", "http request", "plain http", "first record")):
        return "tls_handshake_failed", "TLS handshake failed (possible WAF/CDN protocol gate)"
    if any(
        term in lower
        for term in (
            "network is unreachable",
            "no route to host",
            "host is down",
            "timed out",
            "timeout",
            "firewall",
            "waf",
            "access denied",
            "administratively prohibited",
            "10051",
            "10060",
            "10065",
        )
    ):
        return "network_blocked", "Unreachable (Network Blocked)"
    if any(term in lower for term in ("connection reset", "forcibly closed", "10054")):
        return "connection_reset", "Connection reset during TLS handshake"
    if any(
        term in lower
        for term in (
            "tlsv1 alert",
            "handshake failure",
            "wrong version number",
            "version too low",
            "unsupported protocol",
            "no shared cipher",
            "certificate required",
            "sslv3 alert",
        )
    ):
        return "tls_handshake_failed", "TLS handshake failed (remote endpoint reachable)"
    return "probe_failed", msg


def _tcp_connectivity_probe(host: str, port: int, timeout: float) -> tuple[str, str | None]:
    try:
        with socket.create_connection((host, port), timeout=max(0.6, timeout)):
            return "reachable", None
    except socket.gaierror as exc:
        return "dns_resolution", str(exc)
    except TimeoutError as exc:
        return "network_blocked", str(exc)
    except OSError as exc:
        msg = str(exc).lower()
        if any(term in msg for term in ("refused", "actively refused", "10061")):
            return "service_closed", str(exc)
        if any(term in msg for term in ("timeout", "timed out", "10060", "10051", "10065", "no route", "unreachable")):
            return "network_blocked", str(exc)
        return "probe_failed", str(exc)


def _refine_failure_status(
    host: str,
    port: int,
    timeout: float,
    initial_status: str,
    initial_error: str,
) -> tuple[str, str]:
    tcp_status, _ = _tcp_connectivity_probe(host, port, timeout)
    if tcp_status == "reachable":
        if initial_status in {"network_blocked", "dns_resolution", "service_closed"}:
            return "scanner_probe_miss", "Scanner TLS miss (TCP reachable, handshake did not complete)"
        return initial_status, initial_error
    if tcp_status == "dns_resolution":
        return "dns_resolution", "Unreachable (DNS Resolution Failed)"
    if tcp_status == "service_closed":
        return "service_closed", "Port open check failed (Service Closed/Refused)"
    if tcp_status == "network_blocked":
        return "network_blocked", "Unreachable (Network Blocked)"
    return initial_status, initial_error


async def _probe_hsts(host: str, timeout: float) -> bool:
    try:
        timeout_cfg = httpx.Timeout(max(1.0, timeout), connect=min(3.0, timeout))
        async with httpx.AsyncClient(timeout=timeout_cfg, verify=False, follow_redirects=True) as client:
            response = await client.get(f"https://{host}", headers={"User-Agent": "QuantumShield/3.0"})
            return "strict-transport-security" in {k.lower() for k in response.headers.keys()}
    except Exception:
        return False


async def _python_tls_handshake(
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
) -> dict[str, Any]:
    host_l = str(host or "").strip().lower().rstrip(".")
    if not host_l:
        raise RuntimeError("empty host")

    loop = asyncio.get_running_loop()
    resolved = await asyncio.wait_for(
        loop.getaddrinfo(host_l, port, type=socket.SOCK_STREAM),
        timeout=max(1.0, timeout),
    )

    unique_targets: list[tuple[socket.AddressFamily, tuple[str, int]]] = []
    seen: set[tuple[str, int]] = set()
    for family, _socktype, _proto, _canonname, sockaddr in resolved:
        if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
            continue
        addr_ip = str(sockaddr[0]).strip()
        if not addr_ip:
            continue
        key = (addr_ip, int(port))
        if key in seen:
            continue
        seen.add(key)
        unique_targets.append((family, (addr_ip, int(port))))

    if not unique_targets:
        raise RuntimeError("No resolved addresses available for TLS probe")

    # Prefer IPv4 first because some enterprise targets publish non-routable IPv6.
    unique_targets.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)

    last_error: str | None = None
    for _family, (target_ip, target_port) in unique_targets[:TLS_CONNECT_ATTEMPTS]:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    target_ip,
                    target_port,
                    ssl=context,
                    server_hostname=host_l,  # mandatory SNI for CDN/WAF routed hosts
                    ssl_handshake_timeout=timeout,
                ),
                timeout=max(timeout + 0.8, timeout),
            )
            del reader

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                raise RuntimeError("TLS socket did not expose SSL object")

            cert = ssl_obj.getpeercert() if ssl_obj else None
            der_cert = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None

            out: dict[str, Any] = {
                "tls_version": ssl_obj.version() if ssl_obj else None,
                "cipher_suite": (ssl_obj.cipher() or (None, None, None))[0],
                "cert": cert if isinstance(cert, dict) else None,
                "der_cert": der_cert if isinstance(der_cert, (bytes, bytearray)) else None,
                "ocsp_stapling": False,
                "connected_ip": target_ip,
            }

            with contextlib.suppress(Exception):
                ocsp = getattr(ssl_obj, "ocsp_response", None)
                if callable(ocsp):
                    ocsp = ocsp()
                out["ocsp_stapling"] = bool(ocsp)

            return out
        except Exception as exc:
            last_error = f"{target_ip}: {exc}"
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    raise RuntimeError(last_error or "TLS handshake failed on all resolved addresses")


def _extract_cert_sig_algo_and_bits_from_der_sync(der_cert: bytes | None) -> tuple[str | None, int | None]:
    if not der_cert:
        return None, None

    # Fast path: parse locally via cryptography to avoid dependency on openssl CLI availability.
    if x509 is not None:
        with contextlib.suppress(Exception):
            cert = x509.load_der_x509_certificate(der_cert)
            sig_name = str(getattr(cert.signature_algorithm_oid, "_name", "") or "").strip()
            sig_algo = _normalize_sig_algo(sig_name)

            bits: int | None = None
            public_key = cert.public_key()
            if rsa is not None and isinstance(public_key, rsa.RSAPublicKey):
                bits = int(public_key.key_size)
            elif ec is not None and isinstance(public_key, ec.EllipticCurvePublicKey):
                bits = int(public_key.key_size)
            elif ed25519 is not None and isinstance(public_key, ed25519.Ed25519PublicKey):
                bits = 256
            elif ed448 is not None and isinstance(public_key, ed448.Ed448PublicKey):
                bits = 456

            if sig_algo or bits:
                return sig_algo, bits

    sig_algo: str | None = None
    key_bits: int | None = None

    try:
        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".der") as tmp:
            tmp.write(der_cert)
            der_path = tmp.name

        try:
            proc = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-in", der_path, "-noout", "-text"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
        finally:
            with contextlib.suppress(Exception):
                os.unlink(der_path)

        if proc.returncode != 0:
            return None, None

        for line in (proc.stdout or "").splitlines():
            s = line.strip()
            lower = s.lower()
            if lower.startswith("signature algorithm:") and sig_algo is None:
                sig_algo = _normalize_sig_algo(s.split(":", 1)[1].strip())
            if key_bits is None:
                m = re.search(r"public-key:\s*\((\d+)\s*bit\)", lower)
                if m:
                    key_bits = int(m.group(1))
                else:
                    m2 = re.search(r"rsa public-key:\s*\((\d+)\s*bit\)", lower)
                    if m2:
                        key_bits = int(m2.group(1))
    except Exception:
        return None, None

    return sig_algo, key_bits


def _run_openssl_s_client_sync(host: str, port: int, timeout: float, extra_args: list[str]) -> str:
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-brief",
        *extra_args,
    ]
    proc = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=max(1.0, timeout),
        check=False,
    )
    return f"{proc.stdout}\n{proc.stderr}"


def _parse_openssl_probe(text: str) -> dict[str, Any]:
    version: str | None = None
    cipher_suite: str | None = None
    signature_algo: str | None = None

    for line in text.splitlines():
        s = line.strip()
        lower = s.lower()

        if lower.startswith("protocol") and ":" in s and version is None:
            version = s.split(":", 1)[1].strip()
        elif lower.startswith("ciphersuite:") and cipher_suite is None:
            cipher_suite = s.split(":", 1)[1].strip()
        elif lower.startswith("cipher") and ":" in s and cipher_suite is None:
            cipher_suite = s.split(":", 1)[1].strip()
        elif lower.startswith("peer signature type:"):
            signature_algo = _normalize_sig_algo(s.split(":", 1)[1].strip())
        elif lower.startswith("signature type:") and signature_algo is None:
            signature_algo = _normalize_sig_algo(s.split(":", 1)[1].strip())

    group_name, group_ids = _extract_group_signals(text)

    return {
        "tls_version": version,
        "cipher_suite": cipher_suite,
        "signature_algorithm": signature_algo,
        "key_exchange_group": group_name,
        "named_group_ids": group_ids,
    }


def _probe_with_openssl_sync(host: str, port: int, timeout: float) -> dict[str, Any]:
    if not shutil.which("openssl"):
        return {}
    probes = [
        ["-tls1_3"],
        ["-tls1_2"],
        [],
    ]

    best: dict[str, Any] = {}
    for args in probes:
        try:
            text = _run_openssl_s_client_sync(host, port, timeout, args)
        except Exception:
            continue

        parsed = _parse_openssl_probe(text)
        if not best:
            best = parsed

        if parsed.get("tls_version") or parsed.get("cipher_suite"):
            return parsed
        if parsed.get("key_exchange_group") or parsed.get("signature_algorithm"):
            best = parsed

    return best


def _tcp_connect_sync(host: str, port: int, timeout: float) -> tuple[bool, str | None]:
    try:
        with socket.create_connection((host, port), timeout=max(0.6, timeout)):
            return True, None
    except Exception as exc:
        return False, str(exc)


def _smtp_starttls_probe_sync(host: str, port: int, timeout: float) -> dict[str, Any]:
    import smtplib

    result: dict[str, Any] = {
        "port": port,
        "protocol": "smtp-starttls",
        "reachable": False,
        "tls_measured": False,
        "tls_version": None,
        "cipher_suite": None,
        "error": None,
    }
    try:
        with smtplib.SMTP(host=host, port=port, timeout=max(1.0, timeout)) as smtp:
            smtp.ehlo_or_helo_if_needed()
            result["reachable"] = True
            if not smtp.has_extn("starttls"):
                result["error"] = "STARTTLS not offered"
                return result
            smtp.starttls(context=_build_context(False))
            smtp.ehlo_or_helo_if_needed()
            sock = smtp.sock
            if sock is None:
                result["error"] = "STARTTLS completed but TLS socket unavailable"
                return result
            tls_version = sock.version() if hasattr(sock, "version") else None
            cipher = sock.cipher() if hasattr(sock, "cipher") else None
            result["tls_version"] = tls_version
            result["cipher_suite"] = (cipher[0] if cipher else None)
            result["tls_measured"] = bool(result["tls_version"] or result["cipher_suite"])
            return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


async def _probe_implicit_tls_port_async(host: str, port: int, timeout: float) -> dict[str, Any]:
    result: dict[str, Any] = {
        "port": port,
        "protocol": "tls",
        "reachable": False,
        "tls_measured": False,
        "tls_version": None,
        "cipher_suite": None,
        "error": None,
    }
    reachable, reach_err = await asyncio.to_thread(_tcp_connect_sync, host, port, timeout)
    result["reachable"] = reachable
    if not reachable:
        result["error"] = reach_err
        return result

    last_error: str | None = None
    for permissive in (False, True):
        try:
            handshake = await _python_tls_handshake(host, port, timeout, _build_context(permissive=permissive))
            result["tls_version"] = handshake.get("tls_version")
            result["cipher_suite"] = handshake.get("cipher_suite")
            result["tls_measured"] = bool(result["tls_version"] or result["cipher_suite"])
            if result["tls_measured"]:
                return result
        except Exception as exc:
            last_error = str(exc)
    result["error"] = last_error or "TLS handshake failed"
    return result


async def probe_service_ports_async(
    host: str,
    timeout: float = 3.5,
    ports: list[int] | None = None,
) -> list[dict[str, Any]]:
    """
    Service-aware probing for assets where 443 handshake is unavailable.
    Checks implicit TLS and STARTTLS-capable ports and records reachability.
    """
    host_l = str(host or "").strip().lower().rstrip(".")
    if not host_l:
        return []

    target_ports = ports or list(SERVICE_PROBE_PORTS)
    probe_sem = asyncio.Semaphore(max(2, min(8, len(target_ports))))

    async def _probe(port: int) -> dict[str, Any]:
        async with probe_sem:
            if port in SMTP_STARTTLS_PORTS:
                return await asyncio.to_thread(_smtp_starttls_probe_sync, host_l, port, timeout)
            if port in IMPLICIT_TLS_PORTS:
                return await _probe_implicit_tls_port_async(host_l, port, timeout)

            reachable, err = await asyncio.to_thread(_tcp_connect_sync, host_l, port, timeout)
            return {
                "port": port,
                "protocol": "tcp",
                "reachable": reachable,
                "tls_measured": False,
                "tls_version": None,
                "cipher_suite": None,
                "error": err,
            }

    return await asyncio.gather(*(_probe(int(port)) for port in target_ports))


async def inspect_tls_async(host: str, port: int = 443, timeout: float | None = None) -> TLSInfo:
    """
    Phase 2: robust per-asset TLS/PQC extraction.

    Extracts TLS version, cipher suite, KEX/KEM group, and signature algorithm.
    Always sends SNI via server_hostname to avoid CDN/WAF handshake misses.
    """
    if timeout is None:
        try:
            timeout = max(0.75, float(os.getenv("SCAN_TLS_TIMEOUT_SEC", "4.0")))
        except ValueError:
            timeout = 4.0

    host_l = str(host or "").strip().lower().rstrip(".")
    info = TLSInfo(host=host_l, port=port)

    cert_obj: dict[str, Any] | None = None
    der_cert: bytes | None = None

    sem = _get_probe_semaphore()
    async with sem:
        last_error: str | None = None
        handshake: dict[str, Any] | None = None
        started = time.perf_counter()

        # Try default handshake first, then permissive context for strict legacy endpoints.
        for permissive in (False, True):
            try:
                handshake = await _python_tls_handshake(host_l, port, timeout, _build_context(permissive=permissive))
                break
            except Exception as exc:
                last_error = str(exc)

        if handshake:
            info.tls_version = handshake.get("tls_version")
            info.cipher_suite = handshake.get("cipher_suite")
            if info.cipher_suite:
                info.accepted_ciphers = [info.cipher_suite]
                info.supported_cipher_suites = [info.cipher_suite]
                info.supported_cipher_analysis = _build_cipher_analysis_rows([info.cipher_suite])

            cert_obj = handshake.get("cert") if isinstance(handshake.get("cert"), dict) else None
            der_candidate = handshake.get("der_cert")
            der_cert = der_candidate if isinstance(der_candidate, (bytes, bytearray)) else None

            if cert_obj:
                info.cert_subject = _name_tuple_to_str(cert_obj.get("subject"))
                info.cert_issuer = _name_tuple_to_str(cert_obj.get("issuer"))
                info.cert_not_before = cert_obj.get("notBefore")
                info.cert_not_after = cert_obj.get("notAfter")

            info.ocsp_stapling = bool(handshake.get("ocsp_stapling"))
        else:
            status, scan_error = _classify_failure(last_error)
            status, scan_error = await asyncio.to_thread(
                _refine_failure_status,
                host_l,
                port,
                timeout,
                status,
                scan_error,
            )
            info.network_status = status
            info.scan_error = scan_error

        # OpenSSL probe is used as a detail enhancer (group/sig) and as a fallback when Python SSL misses.
        openssl_details = await asyncio.to_thread(_probe_with_openssl_sync, host_l, port, max(timeout, 4.0))
        if openssl_details:
            info.tls_version = info.tls_version or openssl_details.get("tls_version")
            info.cipher_suite = info.cipher_suite or openssl_details.get("cipher_suite")
            if info.cipher_suite and not info.accepted_ciphers:
                info.accepted_ciphers = [info.cipher_suite]
                info.supported_cipher_suites = [info.cipher_suite]
                info.supported_cipher_analysis = _build_cipher_analysis_rows([info.cipher_suite])

            info.key_exchange_group = info.key_exchange_group or openssl_details.get("key_exchange_group")
            if openssl_details.get("named_group_ids"):
                existing = {x.upper() for x in info.named_group_ids}
                for group_id in openssl_details.get("named_group_ids") or []:
                    gid = str(group_id).upper()
                    if gid not in existing:
                        info.named_group_ids.append(gid)
                        existing.add(gid)

            if not info.signature_algorithm:
                info.signature_algorithm = _normalize_sig_algo(openssl_details.get("signature_algorithm"))

        # Parse cert signature algorithm and key size from certificate DER when Python dict lacks them.
        if cert_obj:
            raw_sig = cert_obj.get("signatureAlgorithm") or cert_obj.get("signature_algorithm")
            info.cert_sig_algo = _normalize_sig_algo(raw_sig if isinstance(raw_sig, str) else None)
            for key in ("bits", "publicKeyBits", "public_key_bits", "key_size"):
                value = cert_obj.get(key)
                try:
                    bits = int(value)
                    if bits > 0:
                        info.cert_public_key_bits = bits
                        break
                except Exception:
                    continue

        if der_cert and (not info.cert_sig_algo or not info.cert_public_key_bits):
            cert_sig, cert_bits = await asyncio.to_thread(_extract_cert_sig_algo_and_bits_from_der_sync, der_cert)
            info.cert_sig_algo = info.cert_sig_algo or cert_sig
            info.cert_public_key_bits = info.cert_public_key_bits or cert_bits

        if not info.signature_algorithm:
            info.signature_algorithm = info.cert_sig_algo

        _attach_cipher_context(info)

        # If TLS evidence exists, do not keep an unreachable status.
        if info.tls_version or info.cipher_suite:
            info.scan_error = None
            info.network_status = None

            if info.key_exchange_group:
                group_upper = info.key_exchange_group.upper()
                if any(token in group_upper for token in ("MLKEM", "ML-KEM", "KYBER")):
                    info.key_encapsulation_mechanism = info.key_exchange_group

            info.hsts_present = await _probe_hsts(host_l, timeout)

        if not info.tls_version and not info.cipher_suite and not info.scan_error:
            info.scan_error = "TLS probe failed without cryptographic evidence"
            info.network_status = info.network_status or "probe_failed"

        if info.scan_error and "unknown" in str(info.scan_error).lower():
            info.scan_error = "Unreachable (Network Blocked)" if info.network_status == "network_blocked" else info.scan_error

        elapsed = time.perf_counter() - started
        if elapsed > max(2.5, timeout * 1.5) and not info.tls_version and not info.cipher_suite and not info.scan_error:
            info.scan_error = "Unreachable (Network Blocked)"
            info.network_status = info.network_status or "network_blocked"

        return info


def inspect_tls(host: str, port: int = 443, timeout: float | None = None) -> TLSInfo:
    return asyncio.run(inspect_tls_async(host, port=port, timeout=timeout))
