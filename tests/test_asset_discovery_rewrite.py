import unittest
from unittest import mock

from backend.scanner import asset_discovery
from backend.main import _coverage_source_breakdown


class _FakeResolver:
    def __init__(self, *_args, **_kwargs):
        pass

    def resolver_targets(self):
        return ["1.1.1.1"]

    def authoritative_resolver_ips(self):
        return ["8.8.8.8"]


class AssetDiscoveryRewriteTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_merges_all_sources(self) -> None:
        with (
            mock.patch.object(asset_discovery, "_AsyncResolver", _FakeResolver),
            mock.patch.object(asset_discovery, "bootstrap_historical_dns_cache", return_value={"ready": True}),
            mock.patch.object(asset_discovery, "discover_from_crtsh", return_value={"api.example.com"}),
            mock.patch.object(asset_discovery, "_discover_from_multi_vantage", return_value={"portal.example.com"}),
            mock.patch.object(
                asset_discovery,
                "discover_from_dns_bruteforce",
                side_effect=[
                    {"vpn.example.com"},
                    {"mail.example.com"},
                    {"auth.example.com"},
                ],
            ),
            mock.patch.object(
                asset_discovery,
                "_resolve_candidates_live",
                side_effect=lambda hosts, _resolver: set(hosts),
            ),
            mock.patch.object(
                asset_discovery,
                "_discover_hosts_from_certificate_sans",
                return_value={"secure.example.com"},
            ),
        ):
            assets, _vpn, report = await asset_discovery.discover_assets_async("example.com", return_report=True)

        self.assertIn("example.com", assets)
        self.assertIn("api.example.com", assets)
        self.assertIn("portal.example.com", assets)
        self.assertIn("vpn.example.com", assets)
        self.assertIn("mail.example.com", assets)
        self.assertIn("auth.example.com", assets)
        self.assertIn("secure.example.com", assets)

        self.assertIn("secure.example.com", report["cert_san_passive"])
        self.assertIn("api.example.com", report["ct_passive"])
        self.assertIn("portal.example.com", report["multi_vantage_passive"])

    def test_wordlist_aliases_are_bidirectional_for_manipur_domain(self) -> None:
        manipurrural_paths = [str(p).replace("\\", "/") for p in asset_discovery._candidate_wordlist_paths("manipurrural.bank.in")]
        manipurral_paths = [str(p).replace("\\", "/") for p in asset_discovery._candidate_wordlist_paths("manipurral.bank.in")]

        self.assertTrue(any("manipurrural.bank.in.txt" in p for p in manipurrural_paths))
        self.assertTrue(any("manipurral.bank.in.txt" in p for p in manipurrural_paths))

        self.assertTrue(any("manipurrural.bank.in.txt" in p for p in manipurral_paths))
        self.assertTrue(any("manipurral.bank.in.txt" in p for p in manipurral_paths))

    def test_coverage_source_breakdown_prioritizes_san_then_ct_then_bruteforce(self) -> None:
        detail = {
            "report_buckets": {
                "ct_passive": ["api.example.com", "shared.example.com"],
                "multi_vantage_passive": ["portal.example.com"],
                "cert_san_passive": ["secure.example.com", "shared.example.com"],
            }
        }
        discovered_hosts = {
            "api.example.com",
            "portal.example.com",
            "secure.example.com",
            "vpn.example.com",
        }

        breakdown = _coverage_source_breakdown(detail, discovered_hosts)

        self.assertEqual(breakdown["source_precedence"], ["san", "ct", "multi_vantage", "brute_force"])
        self.assertEqual(breakdown["san"]["hosts"], ["secure.example.com", "shared.example.com"])
        self.assertEqual(breakdown["ct"]["hosts"], ["api.example.com", "shared.example.com"])
        self.assertEqual(breakdown["multi_vantage"]["hosts"], ["portal.example.com"])
        self.assertEqual(breakdown["brute_force"]["hosts"], ["vpn.example.com"])


if __name__ == "__main__":
    unittest.main()
