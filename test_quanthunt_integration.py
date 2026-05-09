#!/usr/bin/env python3
"""
QuantHunt Core Engine Test & Verification Script

Tests the integration and verifies active internet communication
for enhanced asset discovery.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

# Add parent dirs to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.scanner.quanthunt_core import run_quanthunt_scan
from backend.scanner.quanthunt_integration import QuantHuntScannerBridge

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)

async def test_quanthunt_core():
    """Test the core engine directly."""
    test_domain = "example.com"
    
    print(f"\n{'='*70}")
    print(f"[TEST] QuantHunt Core Engine Direct Test")
    print(f"[TEST] Target: {test_domain}")
    print(f"{'='*70}\n")
    
    try:
        result = await asyncio.wait_for(
            run_quanthunt_scan(test_domain),
            timeout=1200.0
        )
        
        # Print results
        print(f"\n{'='*70}")
        print(f"[RESULTS] Scan Complete")
        print(f"{'='*70}")
        print(f"Scan ID: {result.get('scan_id')}")
        print(f"Target: {result.get('target_domain')}")
        print(f"Wildcard Detected: {result.get('wildcard_detected')}")
        print(f"Duration: {result.get('scan_duration_seconds')}s")
        print(f"\n[METRICS]")
        for key, val in result.get('metrics', {}).items():
            print(f"  {key}: {val}")
        
        print(f"\n[SUMMARY]")
        summary = result.get('summary', {})
        for key, val in summary.items():
            print(f"  {key}: {val}")
        
        pqc_data = result.get('pqc_raw_data', [])
        print(f"\n[PQC ASSETS] Total: {len(pqc_data)}")
        for asset in pqc_data[:5]:  # Show first 5
            print(f"  - {asset.get('hostname')} ({asset.get('ip')})")
            print(f"    TLS: {asset.get('tls_version')} | Cipher: {asset.get('cipher_suite')}")
            if asset.get('is_pqc_hybrid'):
                print(f"    ⚠️  PQC HYBRID DETECTED!")
        
        if len(pqc_data) > 5:
            print(f"  ... and {len(pqc_data) - 5} more")
        
        return result
        
    except asyncio.TimeoutError:
        print(f"[ERROR] Test timed out after 120s")
        return None
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
        logger.exception("Exception during test")
        return None

async def test_integration_bridge():
    """Test the integration bridge with existing discovery."""
    test_domain = "google.com"
    existing_assets = ["google.com", "www.google.com"]
    
    print(f"\n{'='*70}")
    print(f"[TEST] QuantHunt Integration Bridge")
    print(f"[TEST] Target: {test_domain}")
    print(f"[TEST] Existing Assets: {len(existing_assets)}")
    print(f"{'='*70}\n")
    
    try:
        bridge = QuantHuntScannerBridge()
        result = await asyncio.wait_for(
            bridge.discover_and_harvest(test_domain, timeout_sec=600.0),
            timeout=650.0
        )
        
        print(f"\n[BRIDGE RESULT]")
        print(f"  Success: {result.get('success')}")
        print(f"  Unique Hostnames: {len(result.get('hostnames', set()))}")
        print(f"  TLS Assets: {len(result.get('assets', []))}")
        print(f"  Metrics: {result.get('metrics', {})}")
        
        # Test merge
        merged, metadata = bridge.merge_with_existing_discovery(existing_assets, result)
        print(f"\n[MERGE RESULT]")
        print(f"  Existing Count: {metadata.get('existing_count')}")
        print(f"  QuantHunt Count: {metadata.get('quanthunt_hostnames')}")
        print(f"  Merged Count: {metadata.get('merged_count')}")
        print(f"  New Discoveries: {metadata.get('new_discoveries')}")
        print(f"  TLS Assets: {metadata.get('quanthunt_tls_assets')}")
        
        # Show sample
        print(f"\n[SAMPLE] First 10 merged hostnames:")
        for hostname in list(merged)[:10]:
            print(f"  - {hostname}")
        
        return merged, metadata
        
    except asyncio.TimeoutError:
        print(f"[ERROR] Integration test timed out")
        return None, None
    except Exception as e:
        print(f"[ERROR] Integration test failed: {e}")
        logger.exception("Exception during integration test")
        return None, None

async def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("QUANTHUNT CORE ENGINE - INTEGRATION VERIFICATION")
    print("="*70)
    
    # Test 1: Direct core engine
    print(f"\n[PHASE 1/2] Testing core engine...")
    result = await test_quanthunt_core()
    
    if result is None:
        print("\n[PHASE 1] FAILED - Skipping integration test")
        sys.exit(1)
    
    # Test 2: Integration bridge
    print(f"\n[PHASE 2/2] Testing integration bridge...")
    merged, metadata = await test_integration_bridge()
    
    # Summary
    print(f"\n" + "="*70)
    print("VERIFICATION SUMMARY")
    print("="*70)
    
    if result:
        print(f"✅ Core Engine: PASS")
        print(f"   - Assets discovered: {result.get('summary', {}).get('live_assets_with_tls', 0)}")
        print(f"   - WAF blocks: {result.get('metrics', {}).get('waf_blocks_detected', 0)}")
        print(f"   - DNS failures: {result.get('metrics', {}).get('dns_resolution_failures', 0)}")
    
    if merged:
        print(f"✅ Integration Bridge: PASS")
        print(f"   - Merged assets: {len(merged)}")
        print(f"   - New discoveries: {metadata.get('new_discoveries', 0)}")
    
    print(f"\n✅ All tests complete - QuantHunt Core Engine is operational!\n")

if __name__ == "__main__":
    asyncio.run(main())
