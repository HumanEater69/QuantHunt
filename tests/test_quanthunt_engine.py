"""
Comprehensive tests for the QuantHunt Engine.
Tests all five modules: Orchestrator, PassiveCrawler, Mutator, Resolver, TLSProber.
"""

import pytest
import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.quanthunt_engine import (
    Orchestrator, PassiveCrawler, Mutator, Resolver, TLSProber,
    RateLimiter, random_user_agent, run_quanthunt_scan
)
import aiohttp


class TestRateLimiter:
    """Test Module 1: Resilient Orchestrator - Rate Limiter"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_semaphore(self):
        """Verify semaphore bounds concurrent requests"""
        limiter = RateLimiter(max_concurrent=5)
        assert limiter.sem._value == 5
    
    @pytest.mark.asyncio
    async def test_rate_limiter_backoff(self):
        """Verify exponential backoff on failure"""
        limiter = RateLimiter(max_concurrent=10)
        await limiter.acquire("test.com")
        
        # Simulate failure
        await limiter.release("test.com", success=False)
        assert limiter.host_backoff["test.com"] > 0
        
        # Simulate recovery
        await limiter.acquire("test.com")
        await limiter.release("test.com", success=True)
        assert limiter.host_backoff["test.com"] < 0.5


class TestOrchestrator:
    """Test Module 1: Resilient Orchestrator"""
    
    def test_orchestrator_init(self):
        """Test orchestrator initialization"""
        orch = Orchestrator(concurrency=30, socket_timeout=5)
        assert orch.socket_timeout == 5
        assert len(orch.visited_hashes) == 0
    
    def test_cycle_detection(self):
        """Test URL cycle detection via hashing"""
        orch = Orchestrator()
        url = "https://example.com/page1"
        
        # First visit should be allowed
        assert orch.mark_visited(url) is True
        
        # Second visit should be rejected (cycle detected)
        assert orch.mark_visited(url) is False


class TestUserAgent:
    """Test Module 1: Random User-Agent generation"""
    
    def test_user_agent_generation(self):
        """Verify user agents are randomized and valid"""
        agents = {random_user_agent() for _ in range(10)}
        
        # Should be multiple different agents (with high probability)
        assert len(agents) > 1
        
        # All should contain Mozilla or Chrome/Safari signature
        for agent in agents:
            assert any(x in agent for x in ['Mozilla', 'Chrome', 'Safari'])


class TestMutator:
    """Test Module 3: Mathematical Mutation Engine"""
    
    def test_mutator_generation(self):
        """Test subdomain permutation generation"""
        mutator = Mutator()
        mutations = mutator.generate("example.com")
        
        assert len(mutations) > 50  # Should generate many variants
        assert "api.example.com" in mutations
        assert "dev.example.com" in mutations
        assert "node01.example.com" in mutations
        assert any("stg" in m for m in mutations)
    
    def test_mutator_numeric_nodes(self):
        """Test numeric node generation"""
        mutator = Mutator()
        mutations = mutator.generate("test.io")
        
        # Should have node01-node50
        for i in range(1, 51):
            assert f"node{i:02d}.test.io" in mutations


class TestPassiveCrawler:
    """Test Module 2: Deep Extraction & Crawling"""
    
    @pytest.mark.asyncio
    async def test_hostname_validation(self):
        """Test hostname validation filters"""
        orch = Orchestrator()
        async with aiohttp.ClientSession() as session:
            crawler = PassiveCrawler(orch, session)
            
            # Valid hostnames
            assert crawler._is_valid_hostname("example.com") is True
            assert crawler._is_valid_hostname("sub.example.com") is True
            
            # Invalid hostnames
            assert crawler._is_valid_hostname("localhost") is False
            assert crawler._is_valid_hostname("127.0.0.1") is False
            assert crawler._is_valid_hostname("192.168.1.1") is False
    
    @pytest.mark.asyncio
    async def test_host_extraction(self):
        """Test extraction of hosts from HTML"""
        orch = Orchestrator()
        async with aiohttp.ClientSession() as session:
            crawler = PassiveCrawler(orch, session)
            
            html = '''
            <a href="https://api.example.com/v1">API</a>
            <a href="/internal">Home</a>
            <img src="https://cdn.example.com/image.png" />
            '''
            
            hosts = crawler.extract_hosts_and_resources("example.com", html)
            
            assert "example.com" in hosts
            assert "api.example.com" in hosts
            assert "cdn.example.com" in hosts


class TestResolver:
    """Test Module 4: Mass Resolution & Wildcard Analytics"""
    
    @pytest.mark.asyncio
    async def test_resolver_init(self):
        """Test resolver initialization"""
        orch = Orchestrator()
        resolver = Resolver(orch)
        
        assert len(resolver.wildcard_ips) == 0
        assert len(resolver.live_dns) == 0
        assert len(resolver.wildcard_cnames) == 0
    
    @pytest.mark.asyncio
    async def test_cname_mapping(self):
        """Test CNAME record storage"""
        orch = Orchestrator()
        resolver = Resolver(orch)
        
        # Note: This test would need mocking for actual DNS queries
        # or a test environment with predictable DNS
        assert isinstance(resolver.cname_map, dict)


class TestTLSProber:
    """Test Module 5: Cryptographic & PQC Probing"""
    
    def test_tls_prober_init(self):
        """Test TLS prober initialization"""
        orch = Orchestrator()
        prober = TLSProber(orch, concurrency=50)
        
        # Prober should be ready to probe
        assert prober.orch == orch
    
    @pytest.mark.asyncio
    async def test_tls_result_structure(self):
        """Test TLS probe result contains required fields"""
        orch = Orchestrator()
        prober = TLSProber(orch)
        
        # Note: This probes a non-responsive IP, should return empty result
        result = await prober.probe_tls("192.0.2.1")
        
        assert "host" in result
        assert "ip" in result
        assert "tls_version" in result
        assert "cipher" in result
        assert "key_alg" in result
        assert "is_pqc_hybrid" in result


class TestEngineIntegration:
    """Integration tests for the complete engine"""
    
    @pytest.mark.asyncio
    async def test_engine_output_structure(self):
        """Test that engine returns properly structured JSON output"""
        import json
        
        # Use a safe test domain with no actual network calls
        # This test just validates output structure
        result_str = await run_quanthunt_scan("example.com")
        result = json.loads(result_str)
        
        # Verify required top-level keys
        assert "scan_id" in result
        assert "target" in result
        assert "wildcard_detected" in result
        assert "metrics" in result
        assert "pqc_posture_data" in result
        
        # Verify metrics structure
        metrics = result["metrics"]
        assert "passive_discovered" in metrics
        assert "live_dns" in metrics
        assert "live_tls_measured" in metrics
        assert "service_reachable_non_443" in metrics
        assert "unique_ips" in metrics
        
        # Verify pqc_posture_data is list
        assert isinstance(result["pqc_posture_data"], list)
    
    @pytest.mark.asyncio
    async def test_engine_target_normalization(self):
        """Test that engine normalizes various target formats"""
        import json
        
        # Test with https:// prefix
        result1 = await run_quanthunt_scan("https://example.com")
        obj1 = json.loads(result1)
        assert obj1["target"] == "example.com"
        
        # Test with http:// prefix
        result2 = await run_quanthunt_scan("http://example.com/")
        obj2 = json.loads(result2)
        assert obj2["target"] == "example.com"
        
        # Test with whitespace
        result3 = await run_quanthunt_scan("  example.com  ")
        obj3 = json.loads(result3)
        assert obj3["target"] == "example.com"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
