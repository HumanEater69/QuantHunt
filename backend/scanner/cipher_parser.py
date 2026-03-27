from __future__ import annotations

from typing import Any

from .cipher_database import get_cipher_metadata


def parse_cipher_suite(cipher_suite: str | None) -> dict[str, Any]:
    suite = str(cipher_suite or "").strip().upper()
    meta = get_cipher_metadata(suite)

    if not suite:
        return {
            "suite": "unknown",
            "key_exchange": "unknown",
            "authentication": "unknown",
            "bulk_cipher": "unknown",
            "mode": "unknown",
            "hash": "unknown",
            "aead": False,
            "forward_secrecy": False,
            "pqc_signal": False,
            "security_level": "unknown",
        }

    tokens = [t for t in suite.replace("-", "_").split("_") if t]

    kx = meta.get("key_exchange") or "unknown"
    auth = meta.get("authentication") or "unknown"
    bulk = meta.get("bulk_cipher") or "unknown"
    mode = meta.get("mode") or "unknown"
    hsh = meta.get("hash") or "unknown"

    if kx == "unknown":
        if any(t in suite for t in ("MLKEM", "ML-KEM", "KYBER")) and any(
            t in suite for t in ("X25519", "X448", "ECDHE", "DHE")
        ):
            kx = "hybrid-pqc-classical"
        elif any(t in suite for t in ("MLKEM", "ML-KEM", "KYBER")):
            kx = "pqc"
        elif any(t in tokens for t in ("ECDHE", "DHE", "X25519", "X448", "ECDH")):
            kx = "ephemeral-dh"
        elif "RSA" in tokens:
            kx = "rsa"

    if auth == "unknown":
        if "ECDSA" in tokens:
            auth = "ECDSA"
        elif "RSA" in tokens:
            auth = "RSA"
        elif "ED25519" in tokens or "ED448" in tokens:
            auth = "EdDSA"

    if bulk == "unknown":
        if "CHACHA20" in suite:
            bulk = "CHACHA20"
        elif "AES" in tokens:
            if "256" in tokens:
                bulk = "AES-256"
            elif "128" in tokens:
                bulk = "AES-128"
            else:
                bulk = "AES"
        elif "3DES" in suite:
            bulk = "3DES"

    if mode == "unknown":
        if "GCM" in tokens:
            mode = "GCM"
        elif "POLY1305" in tokens:
            mode = "POLY1305"
        elif "CBC" in tokens:
            mode = "CBC"

    if hsh == "unknown":
        for candidate in ("SHA512", "SHA384", "SHA256", "SHA1"):
            if candidate in suite:
                hsh = candidate
                break

    return {
        "suite": suite,
        "key_exchange": kx,
        "authentication": auth,
        "bulk_cipher": bulk,
        "mode": mode,
        "hash": hsh,
        "aead": bool(meta.get("aead")),
        "forward_secrecy": bool(meta.get("forward_secrecy")),
        "pqc_signal": bool(meta.get("pqc_signal")),
        "security_level": str(meta.get("security_level") or "unknown"),
    }
