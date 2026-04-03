from __future__ import annotations

import os
import re
import socket
import ssl
import subprocess
import tempfile
import urllib.request

from ..models import TLSInfo
from .cipher_database import TLS13_CIPHER_SUITES, get_cipher_metadata
from .cipher_parser import parse_cipher_suite


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
        elif "group:" in lower and not group_name:
            group_name = s.split(":", 1)[1].split(",", 1)[0].strip().upper()

    for match in re.findall(r"0x[0-9a-fA-F]{4}", text):
        upper = match.upper()
        if upper not in group_ids:
            group_ids.append(upper)

    name_blob = text.upper()
    if any(
        x in name_blob
        for x in (
            "X25519MLKEM768",
            "X25519_MLKEM768",
            "ML-KEM",
            "KYBER",
            "SECP256R1MLKEM768",
            "SECP384R1MLKEM1024",
            "X25519KYBER768DRAFT00",
        )
    ):
        if not group_name:
            if "X25519MLKEM768" in name_blob or "X25519_MLKEM768" in name_blob:
                group_name = "X25519MLKEM768"
            elif "SECP256R1MLKEM768" in name_blob:
                group_name = "SECP256R1MLKEM768"
            elif "SECP384R1MLKEM1024" in name_blob:
                group_name = "SECP384R1MLKEM1024"
            elif "X25519KYBER768DRAFT00" in name_blob:
                group_name = "X25519KYBER768DRAFT00"
            elif "ML-KEM" in name_blob or "KYBER" in name_blob:
                group_name = "ML-KEM"

    return group_name, group_ids


def _probe_tls_with_openssl(host: str, port: int, timeout: float) -> tuple[str | None, str | None, str | None, list[str]]:
    for flag, version in (("-tls1_3", "TLSv1.3"), ("-tls1_2", "TLSv1.2")):
        try:
            proc = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-connect",
                    f"{host}:{port}",
                    "-servername",
                    host,
                    "-brief",
                    flag,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max(1.0, timeout),
                check=False,
            )
            text = f"{proc.stdout}\n{proc.stderr}"
            if proc.returncode != 0 and "Protocol" not in text and "Ciphersuite" not in text:
                continue
            cipher = None
            for line in text.splitlines():
                s = line.strip()
                if s.lower().startswith("ciphersuite:"):
                    cipher = s.split(":", 1)[1].strip()
                    break
            group_name, group_ids = _extract_group_signals(text)
            return version, cipher, group_name, group_ids
        except Exception:
            continue
    return None, None, None, []


def _attach_cipher_context(info: TLSInfo) -> None:
    parsed = parse_cipher_suite(info.cipher_suite)
    info.cipher_components = parsed
    info.cipher_metadata = get_cipher_metadata(info.cipher_suite)


def _probe_supported_tls12_ciphers(
    host: str,
    port: int,
    timeout: float,
    max_probes: int,
) -> list[str]:
    if max_probes <= 0:
        return []
    supported: list[str] = []
    try:
        base_ctx = ssl.create_default_context()
        candidates = []
        for c in base_ctx.get_ciphers():
            name = str(c.get("name") or "").strip()
            if not name or name.startswith("TLS_"):
                continue
            candidates.append(name)
        seen: set[str] = set()
        for name in candidates:
            if name in seen:
                continue
            seen.add(name)
            if len(seen) > max_probes:
                break
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if hasattr(ssl, "TLSVersion"):
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                ctx.set_ciphers(name)
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as secure_sock:
                        ciph = secure_sock.cipher()
                        if ciph and ciph[0] not in supported:
                            supported.append(ciph[0])
            except Exception:
                continue
    except Exception:
        return []
    return supported


def _probe_supported_tls13_ciphers(
    host: str,
    port: int,
    timeout: float,
    max_probes: int,
) -> list[str]:
    if max_probes <= 0:
        return []
    supported: list[str] = []
    for suite in TLS13_CIPHER_SUITES[:max_probes]:
        try:
            proc = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-connect",
                    f"{host}:{port}",
                    "-servername",
                    host,
                    "-tls1_3",
                    "-brief",
                    "-ciphersuites",
                    suite,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max(1.0, timeout),
                check=False,
            )
            text = f"{proc.stdout}\n{proc.stderr}".upper()
            if proc.returncode == 0 and suite.upper() in text:
                supported.append(suite)
        except Exception:
            continue
    return supported


def _probe_hybrid_group_with_openssl(host: str, port: int, timeout: float) -> tuple[str | None, list[str]]:
    candidates = [
        ("X25519MLKEM768", "0X11EC"),
        ("SECP256R1MLKEM768", "0X11EB"),
        ("SECP384R1MLKEM1024", "0X11ED"),
        ("X25519KYBER768DRAFT00", "0X6399"),
    ]
    for group_name, group_id in candidates:
        try:
            proc = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-connect",
                    f"{host}:{port}",
                    "-servername",
                    host,
                    "-tls1_3",
                    "-brief",
                    "-groups",
                    group_name,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max(4.0, timeout),
                check=False,
            )
            text = f"{proc.stdout}\n{proc.stderr}"
            upper = text.upper()
            if (
                proc.returncode != 0
                and "NEGOTIATED TLS1.3 GROUP" not in upper
                and "CIPHERSUITE:" not in upper
                and "CONNECTION ESTABLISHED" not in upper
            ):
                continue
            parsed_group, parsed_ids = _extract_group_signals(text)
            blob = upper
            if any(
                x in blob
                for x in (
                    "MLKEM",
                    "ML-KEM",
                    "KYBER",
                    "X25519MLKEM",
                    "SECP256R1MLKEM",
                    "SECP384R1MLKEM",
                    "X25519KYBER768DRAFT00",
                )
            ):
                ids = [group_id]
                for pid in parsed_ids:
                    up = str(pid).upper()
                    if up not in ids:
                        ids.append(up)
                return (parsed_group or group_name), ids
        except Exception:
            continue
    return None, []


def _build_cipher_analysis_rows(ciphers: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
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

def _name_tuple_to_str(name_tuple: tuple[tuple[str, str], ...] | None) -> str | None:
    if not name_tuple:
        return None
    return ", ".join(f"{k}={v}" for pair in name_tuple for k, v in [pair])

def _normalize_sig_algo(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = "".join(ch for ch in value.strip() if ch.isalnum())
    return cleaned.upper() if cleaned else None

def _extract_cert_sig_algo(cert: dict | None, der_cert: bytes | None) -> str | None:
    if cert:
        for key in ("signatureAlgorithm", "signature_algorithm", "sigAlg", "sigalg"):
            value = cert.get(key)
            normalized = _normalize_sig_algo(value if isinstance(value, str) else None)
            if normalized:
                return normalized

    if not der_cert:
        return None

    try:
        pem = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem", encoding="utf-8") as tmp:
            tmp.write(pem)
            tmp_path = tmp.name
        try:
            decoded = ssl._ssl._test_decode_cert(tmp_path)
        finally:
            os.unlink(tmp_path)
        if isinstance(decoded, dict):
            value = decoded.get("signatureAlgorithm") or decoded.get("signature_algorithm")
            normalized = _normalize_sig_algo(value if isinstance(value, str) else None)
            if normalized:
                return normalized
    except Exception:
        pass

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
            os.unlink(der_path)
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines():
                s = line.strip()
                if s.lower().startswith("signature algorithm:"):
                    algo = s.split(":", 1)[1].strip()
                    normalized = _normalize_sig_algo(algo)
                    if normalized:
                        return normalized
    except Exception:
        pass

    return None


def _extract_cert_public_key_bits(cert: dict | None, der_cert: bytes | None) -> int | None:
    if cert:
        for key in ("bits", "publicKeyBits", "public_key_bits", "key_size"):
            value = cert.get(key)
            try:
                bits = int(value)
                if bits > 0:
                    return bits
            except Exception:
                continue

    if not der_cert:
        return None

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
            os.unlink(der_path)
        if proc.returncode == 0 and proc.stdout:
            for line in proc.stdout.splitlines():
                s = line.strip().lower()
                m = re.search(r"public-key:\s*\((\d+)\s*bit\)", s)
                if m:
                    return int(m.group(1))
                m2 = re.search(r"rsa public-key:\s*\((\d+)\s*bit\)", s)
                if m2:
                    return int(m2.group(1))
    except Exception:
        pass

    return None

def inspect_tls(host: str, port: int = 443, timeout: float | None = None) -> TLSInfo:
    if timeout is None:
        try:
            timeout = max(0.2, float(os.getenv("SCAN_TLS_TIMEOUT_SEC", "3.5")))
        except ValueError:
            timeout = 3.5
    info = TLSInfo(host=host, port=port)
    enumerate_ciphers = os.getenv("SCAN_ENUMERATE_CIPHERS", "false").lower() == "true"
    cipher_probe_max = max(4, int(os.getenv("SCAN_CIPHER_PROBE_MAX", "16")))
    probe_timeout = max(0.5, float(os.getenv("SCAN_CIPHER_PROBE_TIMEOUT_SEC", "1.3")))
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                info.tls_version = secure_sock.version()
                cipher = secure_sock.cipher()
                if cipher:
                    info.cipher_suite = cipher[0]
                    info.accepted_ciphers = [cipher[0]]
                cert = secure_sock.getpeercert()
                der_cert = secure_sock.getpeercert(binary_form=True)
                if cert:
                    info.cert_subject = _name_tuple_to_str(cert.get("subject"))
                    info.cert_issuer = _name_tuple_to_str(cert.get("issuer"))
                    info.cert_not_before = cert.get("notBefore")
                    info.cert_not_after = cert.get("notAfter")
                info.cert_sig_algo = _extract_cert_sig_algo(cert, der_cert)
                info.cert_public_key_bits = _extract_cert_public_key_bits(cert, der_cert)
                try:
                    ocsp = getattr(secure_sock, "ocsp_response", None)
                    if callable(ocsp):
                        ocsp = ocsp()
                    info.ocsp_stapling = bool(ocsp)
                except Exception:
                    info.ocsp_stapling = False
    except Exception as ex:
        info.scan_error = str(ex)
        fallback_version, fallback_cipher, fallback_group, fallback_group_ids = _probe_tls_with_openssl(host, port, timeout)
        if fallback_version:
            info.tls_version = fallback_version
        if fallback_cipher:
            info.cipher_suite = fallback_cipher
            info.accepted_ciphers = [fallback_cipher]
        if fallback_group:
            info.key_exchange_group = fallback_group
        if fallback_group_ids:
            info.named_group_ids = fallback_group_ids
        _attach_cipher_context(info)
        return info

    _attach_cipher_context(info)

    if enumerate_ciphers:
        tls13_probe = max(2, min(6, cipher_probe_max // 2))
        tls12_probe = max(2, cipher_probe_max - tls13_probe)
        supported = []
        supported.extend(_probe_supported_tls13_ciphers(host, port, probe_timeout, tls13_probe))
        supported.extend(_probe_supported_tls12_ciphers(host, port, probe_timeout, tls12_probe))
        if info.cipher_suite:
            supported.append(info.cipher_suite)
        deduped = sorted({s for s in supported if s})
        info.supported_cipher_suites = deduped
        info.accepted_ciphers = deduped if deduped else info.accepted_ciphers
        info.supported_cipher_analysis = _build_cipher_analysis_rows(deduped)

    try:
        _, _, openssl_group, openssl_group_ids = _probe_tls_with_openssl(host, port, probe_timeout)
        if openssl_group and not info.key_exchange_group:
            info.key_exchange_group = openssl_group
        if openssl_group_ids:
            seen_ids = {x.upper() for x in info.named_group_ids}
            for gid in openssl_group_ids:
                ugid = str(gid).upper()
                if ugid not in seen_ids:
                    info.named_group_ids.append(ugid)
                    seen_ids.add(ugid)

        hybrid_group, hybrid_ids = _probe_hybrid_group_with_openssl(host, port, max(timeout, probe_timeout))
        if hybrid_group:
            info.key_exchange_group = hybrid_group
        if hybrid_ids:
            seen_ids = {x.upper() for x in info.named_group_ids}
            for gid in hybrid_ids:
                ugid = str(gid).upper()
                if ugid not in seen_ids:
                    info.named_group_ids.append(ugid)
                    seen_ids.add(ugid)
    except Exception:
        pass

    try:
        req = urllib.request.Request(f"https://{host}", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            info.hsts_present = "strict-transport-security" in headers
    except Exception:
        pass

    return info
