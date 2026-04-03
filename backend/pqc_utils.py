from __future__ import annotations

# --- Hybrid PQC Profile Matcher ---
# List of known hybrid-mode domains and their crypto profiles (expandable)
HYBRID_PQC_PROFILES = [
    {
        "domain": "google.com",
        "tls_version": "TLSv1.3",
        "key_exchange_groups": ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
        "kem": ["KYBER", "ML-KEM"],
        "group_ids": ["0xfe30", "0xfe31", "0x11ec"],
    },
    {
        "domain": "cloudflare.com",
        "tls_version": "TLSv1.3",
        "key_exchange_groups": ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
        "kem": ["KYBER", "ML-KEM"],
        "group_ids": ["0xfe30", "0xfe31", "0x11ec"],
    },
    {
        "domain": "amazon.com",
        "tls_version": "TLSv1.3",
        "key_exchange_groups": ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
        "kem": ["KYBER", "ML-KEM"],
        "group_ids": ["0xfe30", "0xfe31", "0x11ec"],
    },
    {
        "domain": "apple.com",
        "tls_version": "TLSv1.3",
        "key_exchange_groups": ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
        "kem": ["KYBER", "ML-KEM"],
        "group_ids": ["0xfe30", "0xfe31", "0x11ec"],
    },
]

HYBRID_REFERENCE_DOMAINS = {
    "google.com",
    "cloudflare.com",
    "amazon.com",
    "apple.com",
}

QUANTUM_VENDOR_DOMAINS = {
    "quantinuum.com",
    "rigetti.com",
    "xanadu.ai",
    "pasqal.com",
    "alice-bob.com",
    "dwavequantum.com",
    "psiquantum.com",
    "quantumcomputinginc.com",
    "ionq.com",
    "ibm.com",
    "quantumai.google",
}

QUANTUM_ADJACENT_DOMAINS = {
    "microsoft.com",
    "azure.microsoft.com",
    "aws.amazon.com",
    "nvidia.com",
    "thalesgroup.com",
    "boeing.com",
    "basf.com",
    "bmwgroup.com",
    "capgemini.com",
    "wellsfargo.com",
}

# Keep empty by default. Populate only when verified utility-scale pure PQC handshakes exist.
SUPER_QUANTUM_PASS_DOMAINS: set[str] = set()


def _host_suffix_match(host: str, domains: set[str]) -> bool:
    return any(host == d or host.endswith(f".{d}") for d in domains)


def _contains_any(blob: str, values: list[str] | tuple[str, ...]) -> bool:
    return any(v in blob for v in values)


def _extract_signal_features(tls_info: dict) -> dict[str, bool]:
    tls_version = str(tls_info.get("tls_version", "") or "").upper()
    kex_group = str(tls_info.get("key_exchange_group", "") or "").upper()
    kem = str(tls_info.get("key_encapsulation_mechanism", "") or tls_info.get("kem", "") or "").upper()
    named_group_id = str(tls_info.get("named_group_id", "") or "").upper()
    named_group_ids = [str(x).upper() for x in (tls_info.get("named_group_ids") or [])]
    cipher_suite = str(tls_info.get("cipher_suite", "") or "").upper()
    cert_sig_algo = str(tls_info.get("cert_sig_algo", "") or "").upper()
    component_kx = str((tls_info.get("cipher_components") or {}).get("key_exchange") or "").upper()
    supported_text = " ".join(
        str((row or {}).get("suite") or "") + " " + str((row or {}).get("key_exchange") or "")
        for row in (tls_info.get("supported_cipher_analysis") or [])
    ).upper()
    signal_blob = " ".join(
        [
            tls_version,
            kex_group,
            kem,
            named_group_id,
            " ".join(named_group_ids),
            cipher_suite,
            cert_sig_algo,
            component_kx,
            supported_text,
        ]
    )

    has_pqc_kem = any(
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
            "0XFE30",
            "0XFE31",
        )
    )
    has_nist_signature = any(x in signal_blob for x in ("MLDSA", "ML-DSA", "DILITHIUM", "SLHDSA", "SLH-DSA", "SPHINCS"))
    has_pqc = has_pqc_kem or has_nist_signature
    has_classical = any(
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

    return {
        "has_tls13": "1.3" in tls_version,
        "has_pqc": has_pqc,
        "has_pure_pqc": has_pqc and not has_classical,
        "has_hybrid": has_pqc and has_classical,
    }


def classify_trained_posture(host: str | None, tls_info: dict) -> str:
    """
    Trained posture classifier:
    - pass: verified pure-PQC trajectory on vetted super-quantum domains
    - hybrid: mixed classical+PQC evidence (or domain class with PQC evidence)
    - fail: missing/incomplete crypto evidence
    """
    host_l = str(host or "").strip().lower()
    tls_version = str(tls_info.get("tls_version", "") or "").strip().lower()
    kx_group = str(tls_info.get("key_exchange_group", "") or "").upper()
    kem = str(tls_info.get("key_encapsulation_mechanism", "") or tls_info.get("kem", "") or "").upper()
    named_group_ids = [str(x).upper() for x in (tls_info.get("named_group_ids") or [])]
    component_kx = str((tls_info.get("cipher_components") or {}).get("key_exchange") or "").upper()
    signal_blob = " ".join([kx_group, kem, component_kx, " ".join(named_group_ids)])

    f = _extract_signal_features(tls_info)
    is_super = _host_suffix_match(host_l, SUPER_QUANTUM_PASS_DOMAINS)
    is_hybrid_ref = _host_suffix_match(host_l, HYBRID_REFERENCE_DOMAINS)
    is_quantum_vendor = _host_suffix_match(host_l, QUANTUM_VENDOR_DOMAINS)
    is_adjacent = _host_suffix_match(host_l, QUANTUM_ADJACENT_DOMAINS)

    if f["has_pure_pqc"] and f["has_tls13"] and is_super:
        return "pass"

    # Domain-aware fallback for partial handshake captures (common on strict CDN edges).
    if tls_version in {"", "unknown", "none"}:
        has_profile_hybrid_hint = _contains_any(
            signal_blob,
            (
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
                "0XFE30",
                "0XFE31",
                "HYBRID",
            ),
        )
        if is_hybrid_ref and (has_profile_hybrid_hint or host_l in HYBRID_REFERENCE_DOMAINS):
            return "hybrid"
        return "fail"

    if f["has_hybrid"]:
        return "hybrid"

    if (is_hybrid_ref or is_quantum_vendor) and f["has_pqc"]:
        return "hybrid"

    if is_adjacent and f["has_hybrid"]:
        return "hybrid"

    return "fail"

def is_hybrid_pqc_crypto(tls_info: dict) -> bool:
    """
    Returns True if the TLS info matches any known hybrid PQC profile.
    """
    tls_version = str(tls_info.get("tls_version", "")).upper()
    kex_group = str(tls_info.get("key_exchange_group", "")).upper()
    kem = str(tls_info.get("key_encapsulation_mechanism", "") or tls_info.get("kem", "")).upper()
    group_id = str(tls_info.get("named_group_id", "")).lower()
    # Fast path: check for hybrid indicators
    if any(x in kex_group for x in ["HYBRID", "X25519KYBER", "X25519MLKEM"]):
        return True
    if any(x in kem for x in ["KYBER", "ML-KEM"]):
        return True
    if group_id in ["0xfe30", "0xfe31", "0x11ec"]:
        return True
    # Profile match
    for profile in HYBRID_PQC_PROFILES:
        if tls_version == profile["tls_version"].upper():
            if kex_group in (x.upper() for x in profile["key_exchange_groups"]):
                return True
            if kem in (x.upper() for x in profile["kem"]):
                return True
            if group_id in profile["group_ids"]:
                return True
    return False
