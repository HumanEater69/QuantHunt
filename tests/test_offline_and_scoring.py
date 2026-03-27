import os
import unittest

from backend.main import (
    _certificate_eligibility,
    _extract_tld,
    _offline_chain_reply,
    _vpn_block_reasons,
    _vpn_signal_score,
)
from backend.models import APIInfo, AssetFinding, TLSInfo
from backend.reporting import readiness_label
from backend.scanner.cbom_generator import build_cbom
from backend.scanner.cipher_parser import parse_cipher_suite
from backend.scanner.pqc_engine import classify_key_exchange, classify_tls_version, hndl_score, label_for_score

CTX = """Source=backend
1. pnbindia.in score=71 assets=10
2. sbi.co.in score=59 assets=12
3. hdfcbank.com score=42 assets=11
4. axisbank.com score=75 assets=9
"""

class RiskModelTests(unittest.TestCase):
    def test_label_thresholds_align_to_srs(self) -> None:
        self.assertEqual(label_for_score(60), "Quantum-Safe")
        self.assertEqual(label_for_score(60.01), "PQC Ready")
        self.assertEqual(label_for_score(80), "PQC Ready")
        self.assertEqual(label_for_score(80.01), "CRITICAL EXPOSURE")

    def test_reporting_label_matches_engine_label(self) -> None:
        for score in [0, 25, 60, 71, 80, 95]:
            self.assertEqual(readiness_label(score), label_for_score(score))

    def test_key_exchange_tls13_not_auto_critical(self) -> None:
        self.assertEqual(classify_key_exchange("TLS_AES_256_GCM_SHA384", "TLSv1.3"), "WARNING")
        self.assertEqual(classify_key_exchange("TLS_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2"), "CRITICAL")

    def test_unknown_tls_is_critical(self) -> None:
        self.assertEqual(classify_tls_version(None), "CRITICAL")
        self.assertEqual(classify_tls_version("unknown"), "CRITICAL")

    def test_hndl_penalizes_long_lived_rsa(self) -> None:
        base = hndl_score("WARNING", "WARNING", "WARNING", "WARNING", "WARNING", scan_model="general")
        rsa_long_lived = hndl_score(
            "WARNING",
            "WARNING",
            "WARNING",
            "WARNING",
            "WARNING",
            scan_model="general",
            cipher_suite="TLS_RSA_WITH_AES_256_GCM_SHA384",
            cert_sig_algo="sha256WithRSAEncryption",
            cert_not_before="Jan 01 00:00:00 2024 GMT",
            cert_not_after="Jan 01 00:00:00 2028 GMT",
        )
        self.assertGreater(rsa_long_lived, base)


class CbomLogicTests(unittest.TestCase):
    def test_cipher_parser_decomposes_suite(self) -> None:
        parsed = parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        self.assertIn(parsed["key_exchange"], {"ECDHE", "ephemeral-dh"})
        self.assertEqual(parsed["bulk_cipher"], "AES-256")
        self.assertEqual(parsed["mode"], "GCM")
        self.assertEqual(parsed["hash"], "SHA384")

    def test_cbom_quantum_safe_depends_on_nist_signal(self) -> None:
        finding = AssetFinding(
            asset="example.com",
            tls=TLSInfo(host="example.com", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384"),
            api=APIInfo(host="example.com"),
            key_exchange_status="WARNING",
            auth_status="WARNING",
            tls_status="ACCEPTABLE",
            cert_algo_status="WARNING",
            symmetric_status="ACCEPTABLE",
            hndl_risk_score=20,
            label="Quantum-Safe",
            recommendations=[],
        )
        cbom = build_cbom("example.com", [finding])
        props = {p["name"]: p["value"] for p in cbom["components"][0]["properties"]}
        self.assertEqual(props["quantum-safe"], "false")
        self.assertEqual(props["label"], "Classic-Secure")

    def test_cbom_includes_key_exchange_granularity(self) -> None:
        finding = AssetFinding(
            asset="hybrid.example",
            tls=TLSInfo(
                host="hybrid.example",
                tls_version="TLSv1.3",
                cipher_suite="TLS_X25519_MLKEM768_AES_256_GCM_SHA384",
                supported_cipher_suites=[
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_X25519_MLKEM768_AES_256_GCM_SHA384",
                ],
                cipher_components={
                    "key_exchange": "hybrid-pqc-classical",
                    "authentication": "certificate-signature",
                    "bulk_cipher": "AES-256",
                    "mode": "GCM",
                    "hash": "SHA384",
                    "aead": True,
                    "forward_secrecy": True,
                    "pqc_signal": True,
                    "security_level": "pqc-capable",
                },
                supported_cipher_analysis=[
                    {
                        "suite": "TLS_AES_128_GCM_SHA256",
                        "key_exchange": "(EC)DHE",
                        "authentication": "certificate-signature",
                        "bulk_cipher": "AES-128",
                        "mode": "GCM",
                        "hash": "SHA256",
                        "forward_secrecy": True,
                        "pqc_signal": False,
                        "security_level": "strong",
                    }
                ],
            ),
            api=APIInfo(host="hybrid.example"),
            key_exchange_status="SAFE",
            auth_status="WARNING",
            tls_status="ACCEPTABLE",
            cert_algo_status="WARNING",
            symmetric_status="ACCEPTABLE",
            hndl_risk_score=15,
            label="Quantum-Safe",
            recommendations=[],
        )
        cbom = build_cbom("hybrid.example", [finding])
        component = cbom["components"][0]
        proto = component["cryptoProperties"]["protocolProperties"]
        self.assertIn("keyExchangeAlgorithm", proto)
        self.assertIn("primaryCipherSuite", proto)
        self.assertIn("negotiatedCipherAnalysis", proto)
        self.assertIn("supportedCipherAnalyses", proto)
        props = {p["name"]: p["value"] for p in component["properties"]}
        self.assertEqual(props["cipher-pqc-signal"], "true")
        self.assertEqual(props["supported-cipher-suite-count"], "2")


class CertificationEligibilityTests(unittest.TestCase):
    def test_fails_without_pqc_signal(self) -> None:
        scan = {
            "findings": [
                {
                    "asset": "example.com",
                    "hndl_risk_score": 40,
                    "key_exchange_status": "SAFE",
                    "auth_status": "SAFE",
                    "tls_status": "SAFE",
                    "cert_algo_status": "SAFE",
                    "symmetric_status": "SAFE",
                    "tls": {"tls_version": "TLSv1.3", "scan_error": ""},
                }
            ],
            "cbom": {
                "components": [
                    {
                        "properties": [
                            {"name": "nist-fips-203-signal-detected", "value": "false"},
                            {"name": "nist-fips-204-signal-detected", "value": "false"},
                            {"name": "nist-fips-205-signal-detected", "value": "false"},
                        ]
                    }
                ]
            },
        }
        prior = os.environ.get("CERT_STRICTNESS_PERCENT")
        try:
            os.environ["CERT_STRICTNESS_PERCENT"] = "100"
            ok, reasons, _ = _certificate_eligibility(scan)
        finally:
            if prior is None:
                os.environ.pop("CERT_STRICTNESS_PERCENT", None)
            else:
                os.environ["CERT_STRICTNESS_PERCENT"] = prior
        self.assertFalse(ok)
        self.assertTrue(any("No NIST PQC signal" in r for r in reasons))

    def test_relaxed_mode_allows_missing_pqc_signal(self) -> None:
        scan = {
            "findings": [
                {
                    "asset": "example.com",
                    "hndl_risk_score": 40,
                    "key_exchange_status": "SAFE",
                    "auth_status": "SAFE",
                    "tls_status": "SAFE",
                    "cert_algo_status": "SAFE",
                    "symmetric_status": "SAFE",
                    "tls": {"tls_version": "TLSv1.3", "scan_error": ""},
                }
            ],
            "cbom": {
                "components": [
                    {
                        "properties": [
                            {"name": "nist-fips-203-signal-detected", "value": "false"},
                            {"name": "nist-fips-204-signal-detected", "value": "false"},
                            {"name": "nist-fips-205-signal-detected", "value": "false"},
                        ]
                    }
                ]
            },
        }
        prior = os.environ.get("CERT_STRICTNESS_PERCENT")
        try:
            os.environ["CERT_STRICTNESS_PERCENT"] = "40"
            ok, reasons, _ = _certificate_eligibility(scan)
        finally:
            if prior is None:
                os.environ.pop("CERT_STRICTNESS_PERCENT", None)
            else:
                os.environ["CERT_STRICTNESS_PERCENT"] = prior
        self.assertTrue(ok)
        self.assertEqual(reasons, [])

    def test_fails_on_unknown_tls_and_critical(self) -> None:
        scan = {
            "findings": [
                {
                    "asset": "bad.example",
                    "hndl_risk_score": 72,
                    "key_exchange_status": "CRITICAL",
                    "auth_status": "WARNING",
                    "tls": {"tls_version": "unknown", "scan_error": "timeout"},
                }
            ],
            "cbom": {
                "components": [
                    {
                        "properties": [
                            {"name": "nist-fips-203-signal-detected", "value": "true"},
                        ]
                    }
                ]
            },
        }
        ok, reasons, _ = _certificate_eligibility(scan)
        self.assertFalse(ok)
        self.assertTrue(any("TLS handshake/version could not be validated" in r for r in reasons))
        self.assertTrue(any("Critical cryptographic posture" in r for r in reasons))

class OfflineAssistantIntentTests(unittest.TestCase):
    def test_top3_risky_intent(self) -> None:
        reply, intent = _offline_chain_reply("top 3 risky banks", CTX)
        self.assertEqual(intent, "top_3_risky")
        self.assertIn("1. axisbank.com", reply)

    def test_top3_safest_intent(self) -> None:
        reply, intent = _offline_chain_reply("top 3 safest banks", CTX)
        self.assertEqual(intent, "top_3_safest")
        self.assertIn("1. hdfcbank.com", reply)

    def test_pqc_limits_intent(self) -> None:
        _, intent = _offline_chain_reply("pqc detection limits", CTX)
        self.assertEqual(intent, "pqc_limits")

    def test_chain_clarity_intent(self) -> None:
        reply, intent = _offline_chain_reply("explain chain block meaning", CTX)
        self.assertEqual(intent, "chain_clarity")
        self.assertIn("tamper-evident hash chain", reply)

    def test_certificate_criteria_intent(self) -> None:
        reply, intent = _offline_chain_reply("certificate criteria", CTX)
        self.assertEqual(intent, "certificate_criteria")
        self.assertIn("average HNDL <= 70", reply)

    def test_testing_intent(self) -> None:
        _, intent = _offline_chain_reply("testing coverage", CTX)
        self.assertEqual(intent, "testing")

    def test_limitations_intent(self) -> None:
        _, intent = _offline_chain_reply("known limitations", CTX)
        self.assertEqual(intent, "limitations")

class VpnGuardHelperTests(unittest.TestCase):
    def test_extract_tld(self) -> None:
        self.assertEqual(_extract_tld("edge-01.myvpn.proxy"), "proxy")
        self.assertEqual(_extract_tld("sample.org"), "org")
        self.assertEqual(_extract_tld(""), "")

    def test_vpn_block_reason_contains_proxy(self) -> None:
        reasons = _vpn_block_reasons(proxy=True, hosting=False, reverse_host="node1.example.com")
        self.assertTrue(any("proxy" in r.lower() for r in reasons))

    def test_vpn_signal_score_high_for_proxy_provider(self) -> None:
        score, reasons = _vpn_signal_score(
            {
                "proxy": True,
                "hosting": False,
                "mobile": False,
                "reverse": "",
                "as": "",
                "asname": "",
                "org": "",
                "isp": "",
            }
        )
        self.assertGreaterEqual(score, 90)
        self.assertTrue(any("provider flagged proxy/vpn" in r.lower() for r in reasons))

    def test_vpn_signal_score_uses_reverse_keyword_and_network_signature(self) -> None:
        score, reasons = _vpn_signal_score(
            {
                "proxy": False,
                "hosting": False,
                "mobile": False,
                "reverse": "edge.mullvad.net",
                "as": "AS9009 M247 Europe",
                "asname": "M247",
                "org": "M247 Ltd",
                "isp": "M247",
            }
        )
        self.assertGreaterEqual(score, 60)
        self.assertTrue(any("reverse dns contains" in r.lower() for r in reasons))
        self.assertTrue(any("network signature contains" in r.lower() for r in reasons))

    def test_vpn_signal_score_reduces_on_mobile_without_other_signals(self) -> None:
        score, reasons = _vpn_signal_score(
            {
                "proxy": False,
                "hosting": False,
                "mobile": True,
                "reverse": "phone.carrier.example",
                "as": "",
                "asname": "",
                "org": "",
                "isp": "Carrier ISP",
            }
        )
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

if __name__ == "__main__":
    unittest.main()
