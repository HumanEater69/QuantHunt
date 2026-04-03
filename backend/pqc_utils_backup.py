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
