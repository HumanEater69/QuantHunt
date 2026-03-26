from __future__ import annotations

from typing import Any

from ..models import AssetFinding
from .pqc_engine import label_for_score

def build_cbom(domain: str, findings: list[AssetFinding]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for f in findings:
        cipher = f.tls.cipher_suite or ""
        cert_sig = f.tls.cert_sig_algo or ""
        cipher_up = cipher.upper()
        cert_sig_up = cert_sig.upper()
        fips203 = any(x in cipher_up for x in ["ML-KEM", "MLKEM", "KYBER"])
        fips204 = any(x in cert_sig_up for x in ["ML-DSA", "MLDSA", "DILITHIUM"])
        fips205 = any(x in cert_sig_up for x in ["SLH-DSA", "SLHDSA", "SPHINCS"])
        components.append(
            {
                "type": "cryptographic-asset",
                "name": f.asset,
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "tls",
                        "version": f.tls.tls_version or "unknown",
                        "cipherSuites": f.tls.accepted_ciphers or ([f.tls.cipher_suite] if f.tls.cipher_suite else []),
                        "ikev2TransformTypes": [{"type": "keyExchange", "id": f.tls.cipher_suite or "unknown"}],
                    },
                },
                "properties": [
                    {
                        "name": "quantum-safe",
                        "value": str(label_for_score(float(f.hndl_risk_score)) == "Quantum-Safe").lower(),
                    },
                    {"name": "hndl-risk-score", "value": str(f.hndl_risk_score)},
                    {"name": "nist-fips-203-signal-detected", "value": str(fips203).lower()},
                    {"name": "nist-fips-204-signal-detected", "value": str(fips204).lower()},
                    {"name": "nist-fips-205-signal-detected", "value": str(fips205).lower()},
                    {"name": "pqc-detection-mode", "value": "heuristic-observation"},
                    {
                        "name": "pqc-detection-note",
                        "value": "Derived from observable TLS/certificate metadata; this is not formal cryptographic certification.",
                    },
                    {"name": "nist-pqc-ref", "value": "FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)"},
                    {"name": "label", "value": f.label},
                ],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"name": domain, "type": "platform"}},
        "components": components,
    }
