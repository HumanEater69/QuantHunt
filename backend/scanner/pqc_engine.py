from __future__ import annotations

from datetime import datetime

from ..models import APIInfo, TLSInfo
from ..pqc_utils import classify_trained_posture

WEIGHT = {"CRITICAL": 100, "WARNING": 50, "ACCEPTABLE": 20, "SAFE": 0}

def _is_banking_host(host: str | None) -> bool:
    h = (host or "").lower()
    return h.endswith(".bank.in") or ".bank." in h or h.endswith(".bank")

def classify_key_exchange(
    cipher: str | None,
    tls_version: str | None = None,
    host: str | None = None,
    scan_model: str = "general",
    key_exchange_group: str | None = None,
    named_group_ids: list[str] | None = None,
    cipher_components: dict | None = None,
    supported_cipher_analysis: list[dict] | None = None,
) -> str:
    c = (cipher or "").upper()
    v = (tls_version or "").upper()
    group = (key_exchange_group or "").upper()
    group_ids = [str(x).upper() for x in (named_group_ids or [])]
    component_kx = str((cipher_components or {}).get("key_exchange") or "").upper()
    supported_text = " ".join(
        str((row or {}).get("suite") or "") + " " + str((row or {}).get("key_exchange") or "")
        for row in (supported_cipher_analysis or [])
    ).upper()
    signal_blob = " ".join([c, group, component_kx, supported_text, " ".join(group_ids)])

    has_pqc = any(
        x in signal_blob
        for x in (
            "MLKEM",
            "ML-KEM",
            "KYBER",
            "X25519MLKEM",
            "SECP256R1MLKEM",
            "SECP384R1MLKEM",
            "X25519KYBER768DRAFT00",
            "0X11EB",
            "0X11EC",
            "0X11ED",
            "0X6399",
        )
    )
    has_classic = any(
        x in signal_blob
        for x in (
            "ECDHE",
            "DHE",
            "ECDH",
            "X25519",
            "X448",
            "RSA",
            "SECP256R1",
            "SECP384R1",
            "P-256",
            "P-384",
        )
    )

    if has_pqc and has_classic:
        return "ACCEPTABLE"
    if has_pqc:
        return "SAFE"
    if "TLS_RSA" in c or "_RSA_" in c:
        return "CRITICAL"
    if any(x in signal_blob for x in ["ECDHE", "DHE", "ECDH", "X25519", "X448", "(EC)DHE"]):
        return "WARNING"

    if "1.3" in v:
        return "WARNING"
    if "1.0" in v or "1.1" in v:
        return "CRITICAL"
    return "WARNING"


def _pqc_signal_flags(
    cipher: str | None,
    key_exchange_group: str | None,
    named_group_ids: list[str] | None,
    supported_cipher_analysis: list[dict] | None,
    cert_sig_algo: str | None = None,
    cipher_components: dict | None = None,
) -> dict[str, bool]:
    c = (cipher or "").upper()
    group = (key_exchange_group or "").upper()
    group_ids = [str(x).upper() for x in (named_group_ids or [])]
    supported_text = " ".join(
        str((row or {}).get("suite") or "") + " " + str((row or {}).get("key_exchange") or "")
        for row in (supported_cipher_analysis or [])
    ).upper()
    sig = (cert_sig_algo or "").upper()
    component_kx = str((cipher_components or {}).get("key_exchange") or "").upper()
    component_security = str((cipher_components or {}).get("security_level") or "").upper()
    component_pqc = bool((cipher_components or {}).get("pqc_signal"))
    blob = " ".join(
        [c, group, " ".join(group_ids), supported_text, sig, component_kx, component_security]
    )

    has_fips203 = any(
        x in blob
        for x in (
            "MLKEM",
            "ML-KEM",
            "KYBER",
            "X25519MLKEM",
            "SECP256R1MLKEM",
            "SECP384R1MLKEM",
            "X25519KYBER768DRAFT00",
            "0X11EB",
            "0X11EC",
            "0X11ED",
            "0X6399",
        )
    )
    if component_pqc or "HYBRID-PQC-CLASSICAL" in component_kx:
        has_fips203 = True
    has_fips204 = any(x in sig for x in ("MLDSA", "ML-DSA", "DILITHIUM"))
    has_fips205 = any(x in sig for x in ("SLHDSA", "SLH-DSA", "SPHINCS"))

    has_classical = any(
        x in blob
        for x in (
            "RSA",
            "ECDHE",
            "DHE",
            "ECDH",
            "X25519",
            "X448",
            "SECP256R1",
            "SECP384R1",
            "P-256",
            "P-384",
        )
    )
    has_hybrid = has_fips203 and has_classical
    has_pure_pqc = (has_fips203 or has_fips204 or has_fips205) and not has_classical

    return {
        "fips203": has_fips203,
        "fips204": has_fips204,
        "fips205": has_fips205,
        "hybrid": has_hybrid,
        "pure_pqc": has_pure_pqc,
        "classical": has_classical,
    }


def decision_tree_label(
    tls: TLSInfo,
    key_exchange_status: str,
) -> str:
    trained_posture = classify_trained_posture(tls.host, tls.model_dump())
    if trained_posture == "pass":
        return "Quantum-Safe (NIST Compliant)"
    if trained_posture == "hybrid":
        return "Quantum-Resilient (Hybrid)"

    version = (tls.tls_version or "").upper()
    # Treat as failed only when no handshake/version evidence exists and no trained override applies.
    if not version:
        return "Scan Failed/Unknown"

    if "1.0" in version or "1.1" in version:
        return "Critical Vulnerability"

    flags = _pqc_signal_flags(
        tls.cipher_suite,
        tls.key_exchange_group,
        tls.named_group_ids,
        tls.supported_cipher_analysis,
        cert_sig_algo=tls.cert_sig_algo,
        cipher_components=tls.cipher_components,
    )

    # Keep labels aligned with classifier output even when secondary signal extraction is partial.
    if "1.3" in version and (flags["hybrid"] or key_exchange_status == "ACCEPTABLE"):
        return "Quantum-Resilient (Hybrid)"

    if flags["pure_pqc"] or key_exchange_status == "SAFE":
        return "Quantum-Safe (NIST Compliant)"

    if "1.2" in version or "1.3" in version:
        if key_exchange_status in {"CRITICAL", "WARNING"}:
            return "Quantum-Vulnerable (HNDL Risk)"

    return "Quantum-Vulnerable (HNDL Risk)"

def classify_auth(tls: TLSInfo, api: APIInfo, scan_model: str = "general") -> str:
    sig = (tls.cert_sig_algo or "").upper()

    if any(a in sig for a in ["MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS"]):
        return "SAFE"
    if any(a in sig for a in ["RSA", "ECDSA", "DSA", "EDDSA", "ED25519"]):
        return "WARNING"
    if any(jwt in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"} for jwt in api.jwt_algorithms):
        return "WARNING"
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
    cert_public_key_bits: int | None = None,
) -> float:
    cipher_up = (cipher_suite or "").upper()

    # 50% Key Exchange risk.
    if key_exchange == "SAFE":
        kex_score = 0.0
    elif key_exchange == "ACCEPTABLE":
        kex_score = 10.0
    elif key_exchange == "CRITICAL":
        kex_score = 95.0
    elif "TLS_RSA" in cipher_up or "_RSA_" in cipher_up:
        kex_score = 100.0
    else:
        kex_score = 70.0

    # 20% key-size risk (certificate public key length proxy).
    bits = int(cert_public_key_bits or 0)
    if bits <= 0:
        keylen_score = 65.0
    elif bits <= 2048:
        keylen_score = 85.0
    elif bits <= 3072:
        keylen_score = 55.0
    elif bits <= 4096:
        keylen_score = 35.0
    else:
        keylen_score = 20.0

    # 15% certificate validity risk (longer-lived certs increase HNDL risk window).
    cert_validity_score = 60.0

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
        if validity_days <= 90:
            cert_validity_score = 10.0
        elif validity_days <= 180:
            cert_validity_score = 25.0
        elif validity_days <= 397:
            cert_validity_score = 45.0
        elif validity_days <= 730:
            cert_validity_score = 80.0
        else:
            cert_validity_score = 95.0

    # 15% TLS protocol risk.
    v = (tls_version or "").upper()
    if not v or "UNKNOWN" in v or "1.0" in v or "1.1" in v:
        tls_proto_score = 100.0
    elif "1.2" in v:
        tls_proto_score = 60.0
    elif "1.3" in v:
        tls_proto_score = 20.0
    else:
        tls_proto_score = 60.0

    score = (
        (kex_score * 0.50)
        + (keylen_score * 0.20)
        + (cert_validity_score * 0.15)
        + (tls_proto_score * 0.15)
    )

    return round(min(max(score, 0.0), 100.0), 2)

def label_for_score(score: float, scan_model: str = "general") -> str:
    model = (scan_model or "general").lower()
    safe_threshold = 50 if model == "banking" else 60
    ready_threshold = 70 if model == "banking" else 80
    if score <= safe_threshold:
        return "Quantum-Safe (NIST Compliant)"
    if score <= ready_threshold:
        return "Quantum-Resilient (Hybrid)"
    return "Quantum-Vulnerable (HNDL Risk)"

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
