from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from quanthunt.discover import pqc_probe
from quanthunt.models import PQCStatus


class PQCProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_openssl_pass_detects_hybrid_group(self) -> None:
        openssl_output = """CONNECTED(00000003)
Protocol version: TLSv1.3
Server Temp Key: X25519MLKEM768, 255 bits
"""
        with (
            mock.patch.object(pqc_probe, "_openssl_version", return_value=(3, 4, 0)),
            mock.patch.object(
                pqc_probe,
                "_run_openssl_probe",
                return_value=(openssl_output, "X25519MLKEM768", "TLSv1.3", None),
            ),
            mock.patch.object(pqc_probe, "_resolve_hostname", return_value="1.2.3.4"),
        ):
            result = await pqc_probe.probe_pqc("api.example.com")

        self.assertEqual(result.status, PQCStatus.PASS)
        self.assertEqual(result.detection_method, "openssl")
        self.assertEqual(result.negotiated_group, "X25519MLKEM768")
        self.assertEqual(result.tls_version, "TLSv1.3")
        self.assertEqual(result.raw_openssl_output, openssl_output)

    async def test_classical_cdn_endpoint_is_hybrid(self) -> None:
        openssl_output = """CONNECTED(00000003)
Protocol version: TLSv1.3
Server Temp Key: X25519, 253 bits
"""
        with (
            mock.patch.object(pqc_probe, "_openssl_version", return_value=(3, 4, 0)),
            mock.patch.object(
                pqc_probe,
                "_run_openssl_probe",
                return_value=(openssl_output, "X25519", "TLSv1.3", None),
            ),
            mock.patch.object(pqc_probe, "_resolve_hostname", return_value="104.21.0.1"),
            mock.patch.object(pqc_probe, "_cdn_probe", return_value=("Cloudflare", ["CF-Ray", "server:cloudflare"])),
            mock.patch.object(pqc_probe, "_reverse_dns", return_value="edge.cloudflare.net"),
            mock.patch.object(pqc_probe, "_asn_org", return_value="Cloudflare, Inc."),
        ):
            result = await pqc_probe.probe_pqc("cdn.example.com")

        self.assertEqual(result.status, PQCStatus.HYBRID)
        self.assertEqual(result.provider, "Cloudflare")
        self.assertEqual(result.cdn_headers_detected, ["CF-Ray", "server:cloudflare"])
        self.assertEqual(result.asn_org, "Cloudflare, Inc.")

    async def test_tls12_classical_endpoint_fails(self) -> None:
        with (
            mock.patch.object(pqc_probe, "_openssl_version", return_value=(3, 4, 0)),
            mock.patch.object(
                pqc_probe,
                "_run_openssl_probe",
                return_value=("Protocol version: TLSv1.2\nServer Temp Key: X25519\n", "X25519", "TLSv1.2", None),
            ),
            mock.patch.object(pqc_probe, "_resolve_hostname", return_value="198.51.100.10"),
        ):
            result = await pqc_probe.probe_pqc("legacy.example.com")

        self.assertEqual(result.status, PQCStatus.FAIL)
        self.assertEqual(result.tls_version, "TLSv1.2")

    async def test_python_ssl_fallback_when_openssl_is_old(self) -> None:
        with (
            mock.patch.object(pqc_probe, "_openssl_version", return_value=(3, 2, 0)),
            mock.patch.object(pqc_probe, "_python_ssl_probe", return_value=("TLSv1.3", "TLS_AES_128_GCM_SHA256", None)),
            mock.patch.object(pqc_probe, "_resolve_hostname", return_value="203.0.113.8"),
            mock.patch.object(pqc_probe, "_cdn_probe", return_value=(None, [])),
            mock.patch.object(pqc_probe, "_reverse_dns", return_value=None),
            mock.patch.object(pqc_probe, "_asn_org", return_value=None),
        ):
            result = await pqc_probe.probe_pqc("fallback.example.com")

        self.assertEqual(result.detection_method, "python_ssl")
        self.assertEqual(result.status, PQCStatus.FAIL)
        self.assertEqual(result.negotiated_group, "TLS_AES_128_GCM_SHA256")

    async def test_bulk_probe_preserves_input_order(self) -> None:
        async def fake_probe(hostname: str, port: int = 443, timeout: int = 10, openssl_binary: str = "openssl"):
            await asyncio.sleep(0.01 if hostname.endswith("2") else 0.02)
            return pqc_probe.PQCResult(hostname=hostname, port=port, status=PQCStatus.FAIL, detection_method="fallback")

        with mock.patch.object(pqc_probe, "probe_pqc", side_effect=fake_probe):
            results = await pqc_probe.bulk_probe_pqc(["host1.example", "host2.example"], concurrency=2, timeout=1)

        self.assertEqual([item.hostname for item in results], ["host1.example", "host2.example"])
        self.assertTrue(all(item.status == PQCStatus.FAIL for item in results))


if __name__ == "__main__":
    unittest.main()
