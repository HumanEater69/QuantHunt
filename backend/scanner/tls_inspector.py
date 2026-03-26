from __future__ import annotations

import os
import socket
import ssl
import subprocess
import tempfile
import urllib.request

from ..models import TLSInfo


def _probe_tls_with_openssl(host: str, port: int, timeout: float) -> tuple[str | None, str | None]:
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
            return version, cipher
        except Exception:
            continue
    return None, None

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

def inspect_tls(host: str, port: int = 443, timeout: float | None = None) -> TLSInfo:
    if timeout is None:
        try:
            timeout = max(0.2, float(os.getenv("SCAN_TLS_TIMEOUT_SEC", "3.5")))
        except ValueError:
            timeout = 3.5
    info = TLSInfo(host=host, port=port)
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
                try:
                    ocsp = getattr(secure_sock, "ocsp_response", None)
                    if callable(ocsp):
                        ocsp = ocsp()
                    info.ocsp_stapling = bool(ocsp)
                except Exception:
                    info.ocsp_stapling = False
    except Exception as ex:
        info.scan_error = str(ex)
        fallback_version, fallback_cipher = _probe_tls_with_openssl(host, port, timeout)
        if fallback_version:
            info.tls_version = fallback_version
        if fallback_cipher:
            info.cipher_suite = fallback_cipher
            info.accepted_ciphers = [fallback_cipher]
        return info

    try:
        req = urllib.request.Request(f"https://{host}", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            info.hsts_present = "strict-transport-security" in headers
    except Exception:
        pass

    return info
