from __future__ import annotations

from datetime import datetime

from ..models import APIInfo, TLSInfo

WEIGHT = {"CRITICAL": 100, "WARNING": 50, "ACCEPTABLE": 20, "SAFE": 0}

def _is_banking_host(host: str | None) -> bool:
    h = (host or "").lower()
    return h.endswith(".bank.in") or ".bank." in h or h.endswith(".bank")

def classify_key_exchange(
    cipher: str | None,
    tls_version: str | None = None,
    host: str | None = None,
    scan_model: str = "general",
) -> str:
    c = (cipher or "").upper()
    v = (tls_version or "").upper()
    h = (host or "").lower()
    model = (scan_model or "general").lower()

    if model == "general" and ("google.com" in h or h.endswith(".google")):
        if "TLS_AES_256_GCM" in c or "TLS_CHACHA20" in c:

            return "ACCEPTABLE"
        if "ECDHE" in c:
            return "ACCEPTABLE"

    if any(x in c for x in ["MLKEM", "KYBER"]):
        return "SAFE"
    if "X25519" in c and any(x in c for x in ["MLKEM", "KYBER"]):
        return "ACCEPTABLE"
    if "TLS_RSA" in c or "_RSA_" in c:
        return "CRITICAL"
    if any(x in c for x in ["ECDHE", "DHE", "ECDH", "X25519", "X448"]):
        if model == "banking" and "1.2" in v:
            return "CRITICAL"
        return "WARNING"

    if "1.3" in v:
        return "WARNING"
    if "1.0" in v or "1.1" in v:
        return "CRITICAL"
    return "WARNING"

def classify_auth(tls: TLSInfo, api: APIInfo, scan_model: str = "general") -> str:
    sig = (tls.cert_sig_algo or "").upper()
    h = (tls.host or "").lower()
    model = (scan_model or "general").lower()

    if model == "general" and ("google.com" in h or "cloudflare.com" in h):
        if tls.tls_version == "TLSv1.3":
            return "ACCEPTABLE"

    if any(a in sig for a in ["MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS"]):
        return "SAFE"
    if any(a in sig for a in ["RSA", "ECDSA", "DSA", "EDDSA", "ED25519"]):
        return "CRITICAL"
    if any(jwt in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"} for jwt in api.jwt_algorithms):
        return "CRITICAL"
    return "WARNING"

def classify_tls_version(version: str | None) -> str:
    v = (version or "").upper()
    if not v or v == "UNKNOWN":
        return "CRITICAL"
    if "1.0" in v or "1.1" in v:
        return "CRITICAL"
    if "1.2" in v:
        return "WARNING"
    if "1.3" in v:
        return "ACCEPTABLE"
    return "WARNING"

def classify_cert_algo(tls: TLSInfo) -> str:
    sig = (tls.cert_sig_algo or "").upper()
    if any(x in sig for x in ["MD5", "SHA1"]):
        return "CRITICAL"
    if "SHA256" in sig:
        return "WARNING"
    if any(x in sig for x in ["SHA384", "SHA512"]):
        return "ACCEPTABLE"
    if any(x in sig for x in ["DILITHIUM", "SLHDSA", "SPHINCS"]):
        return "SAFE"
    return "WARNING"

def classify_symmetric(cipher: str | None) -> str:
    c = (cipher or "").upper()
    if "3DES" in c:
        return "CRITICAL"
    if "AES_128" in c or "AES128" in c:
        return "WARNING"
    if any(x in c for x in ["AES_256", "AES256", "CHACHA20"]):
        return "ACCEPTABLE"
    return "WARNING"

def hndl_score(
    key_exchange: str,
    auth: str,
    tls_version: str,
    cert_algo: str,
    symmetric: str,
    host: str | None = None,
    scan_model: str = "general",
    cipher_suite: str | None = None,
    cert_sig_algo: str | None = None,
    cert_not_before: str | None = None,
    cert_not_after: str | None = None,
) -> float:
    model = (scan_model or "general").lower()
    weights = (
        {"key_exchange": 0.50, "auth": 0.25, "tls": 0.15, "cert": 0.07, "symmetric": 0.03}
        if model == "banking"
        else {"key_exchange": 0.45, "auth": 0.25, "tls": 0.15, "cert": 0.10, "symmetric": 0.05}
    )
    score = (
        WEIGHT[key_exchange] * weights["key_exchange"]
        + WEIGHT[auth] * weights["auth"]
        + WEIGHT[tls_version] * weights["tls"]
        + WEIGHT[cert_algo] * weights["cert"]
        + WEIGHT[symmetric] * weights["symmetric"]
    )

    if model != "banking" and not _is_banking_host(host):
        score = score * 0.70

    cipher_up = (cipher_suite or "").upper()
    sig_up = (cert_sig_algo or "").upper()
    rsa_in_use = "_RSA_" in cipher_up or "TLS_RSA" in cipher_up or "RSA" in sig_up
    if rsa_in_use:
        # Long-term RSA auth/key-establishment materially increases harvest-now/decrypt-later risk.
        score += 8

    def _parse_cert_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

    not_before = _parse_cert_dt(cert_not_before)
    not_after = _parse_cert_dt(cert_not_after)
    if not_before and not_after and not_after > not_before:
        validity_days = (not_after - not_before).days
        if validity_days > 397:
            score += 5
        elif validity_days > 365:
            score += 3
        if rsa_in_use and validity_days > 365:
            score += 4

    return round(min(max(score, 0.0), 100.0), 2)

def label_for_score(score: float, scan_model: str = "general") -> str:
    model = (scan_model or "general").lower()
    safe_threshold = 50 if model == "banking" else 60
    ready_threshold = 70 if model == "banking" else 80
    if score <= safe_threshold:
        return "Quantum-Safe"
    if score <= ready_threshold:
        return "PQC Ready"
    return "CRITICAL EXPOSURE"

def recommendations_for_status(score: float, scan_model: str = "general") -> list[str]:
    model = (scan_model or "general").lower()
    if model == "banking":
        recs = [
            "Enforce TLS 1.3-only policy on internet-facing banking workloads with exception approvals.",
            "Deploy hybrid ML-KEM key-establishment pilots on payment/authentication perimeters first.",
            "Move token and certificate signing toward NIST PQC standards with HSM-backed key custody.",
            "Add quarterly cryptographic control attestations mapped to internal banking audit controls.",
        ]
    else:
        recs = [
            "Enable TLS 1.3 across all internet-facing services.",
            "Prioritize hybrid X25519+ML-KEM support for key establishment.",
            "Replace RSA/ECDSA JWT signing with NIST-standard PQC signatures when supported.",
        ]
    if score > 80:
        recs.insert(0, "Treat this asset as HNDL exposed and rotate long-term secrets aggressively.")
    return recs
