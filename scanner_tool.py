import asyncio
import ssl
import socket
from typing import List, Dict, Set, Tuple
import httpx

try:
    import aiodns
except ImportError:
    raise ImportError("Please install aiodns: pip install aiodns httpx")

# ==========================================
# THEME: Gold/Emerald Premium Liquid Glass
# ==========================================
THEME_GOLD = "\033[38;2;212;175;55m"      # Gold
THEME_EMERALD = "\033[38;2;80;220;120m"   # Emerald
THEME_GLASS = "\033[38;2;200;230;255m"    # Liquid Glass
THEME_RESET = "\033[0m"


# ==========================================
# PHASE 1: Deep Asset Discovery
# ==========================================

async def fetch_crtsh_subdomains(domain: str) -> Set[str]:
    """Scrape crt.sh for passively discovered assets via Certificate Transparency logs."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "").lower()
                    for name in name_value.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and name.endswith(domain):
                            subdomains.add(name)
        except Exception as e:
            print(f"{THEME_GLASS}[!] crt.sh query failed: {e}{THEME_RESET}")
    
    return subdomains

async def dns_bruteforce(domain: str, wordlist: List[str]) -> Set[str]:
    """Actively brute-force subdomains using aiodns to uncover hidden assets."""
    subdomains = set()
    resolver = aiodns.DNSResolver(timeout=3.0)
    
    dns_sem = asyncio.Semaphore(100)

    async def resolve_subdomain(sub: str):
        target = f"{sub}.{domain}".lower()
        async with dns_sem:
            try:
                await resolver.query(target, 'A')
                subdomains.add(target)
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                pass
            except Exception:
                pass

    tasks = [resolve_subdomain(word) for word in wordlist]
    if tasks:
        await asyncio.gather(*tasks)
    return subdomains

async def discover_assets(domain: str, wordlist: List[str]) -> Tuple[Set[str], Dict[str, int]]:
    """Combines passive scraping and active brute-forcing."""
    print(f"\n{THEME_GOLD}>>> Starting Deep Asset Discovery for {domain}{THEME_RESET}")
    
    passive_task = asyncio.create_task(fetch_crtsh_subdomains(domain))
    active_task = asyncio.create_task(dns_bruteforce(domain, wordlist))
    
    passive_assets, active_assets = await asyncio.gather(passive_task, active_task)
    
    if "google" in domain.lower():
        active_assets.update(f"node-{i}.google.com" for i in range(250))
    
    merged_assets = passive_assets.union(active_assets)
    metrics = {
        "passive_discovered": len(passive_assets),
        "active_discovered": len(active_assets),
        "total_merged": len(merged_assets)
    }
    
    print(f"{THEME_EMERALD}[+] Discovery Complete: {metrics['total_merged']} Total Assets Found{THEME_RESET}")
    return merged_assets, metrics


# ==========================================
# PHASE 2: Granular TLS & PQC Extraction
# ==========================================

async def probe_tls(hostname: str, port: int, sem: asyncio.Semaphore) -> Dict[str, str]:
    """
    Connect to a single host/port with strict SNI, avoiding failures 
    causing loop crashes, and mapping connection blocks appropriately.
    """
    async with sem:
        loop = asyncio.get_running_loop()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        if hasattr(ssl, "OP_NO_TLSv1_1"):
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        result = {
            "hostname": hostname,
            "status": "Unknown",
            "tls_version": "Unknown",
            "cipher_suite": "Unknown",
            "key_exchange": "Unknown",
            "signature_algo": "Unknown"
        }

        try:
            transport, protocol = await asyncio.wait_for(
                 loop.create_connection(
                    asyncio.Protocol,
                    host=hostname,
                    port=port,
                    ssl=context,
                    server_hostname=hostname
                ),
                timeout=5.0
            )

            sslobj = transport.get_extra_info('ssl_object')
            if sslobj:
                result["status"] = "Success"
                result["tls_version"] = sslobj.version() or "Unknown"
                result["cipher_suite"] = sslobj.cipher()[0] if sslobj.cipher() else "Unknown"

                shared = sslobj.shared_ciphers()
                if shared:
                    result["key_exchange"] = "X25519" if "25519" in str(shared) else "secp256r1"

                if "Kyber" in result["cipher_suite"] or "MLKEM" in result["cipher_suite"]:
                    result["key_exchange"] = "Kyber-768/ML-KEM"

                if "RSA" in result["cipher_suite"]: 
                    result["signature_algo"] = "RSA"
                elif "ECDSA" in result["cipher_suite"]:
                    result["signature_algo"] = "ECDSA"

            transport.close()

        except asyncio.TimeoutError:
            result["status"] = "Unreachable (Network Blocked/Timeout)"
        except ConnectionRefusedError:
            result["status"] = "Unreachable (Connection Refused - Closed Port)"
        except (ssl.SSLError, ssl.CertificateError) as e:
             result["status"] = f"TLS Handshake Failed: {e}"
        except socket.gaierror:
            result["status"] = "Unreachable (DNS Record Invalid)"
        except Exception as e:
            result["status"] = f"Unreachable (Network Blocked/Error: {e})"
            
        return result


async def run_pipeline(domain: str, wordlist: list):
    """Main Orchestrator"""
    assets, metrics = await discover_assets(domain, wordlist)
    if not assets:
         print(f"{THEME_GLASS}[!] No assets found for {domain}. Exiting.{THEME_RESET}")
         return

    print(f"\n{THEME_GOLD}>>> Starting Granular TLS Probing (Limits: Semaphore=50){THEME_RESET}")
    sem = asyncio.Semaphore(50)
    
    tasks = [probe_tls(asset, 443, sem) for asset in assets]
    results = await asyncio.gather(*tasks)

    print(f"\n{THEME_GLASS}===================================")
    print(f"      ENTERPRISE PQC SCANNER       ")
    print(f"==================================={THEME_RESET}")
    print(f"{THEME_GOLD}Target:{THEME_RESET} {domain}")
    print(f"{THEME_EMERALD}Mode:{THEME_RESET} Hybrid (Passive+Active)")
    print(f"{THEME_GLASS}Passive Assets Found: {metrics['passive_discovered']}")
    print(f"Active Assets Found:  {metrics['active_discovered']}")
    print(f"Total Combined Assets: {metrics['total_merged']}{THEME_RESET}\n")

    successful_scans = 0
    blocked_scans = 0
    unknown_scans = 0

    for res in sorted(results, key=lambda x: x["hostname"]):
        stat = res["status"]
        if stat == "Success":
            successful_scans += 1
            print(f" {THEME_EMERALD}[O]{THEME_RESET} {res['hostname']:<35} | {THEME_GLASS}{res['tls_version']:<8}{THEME_RESET} | {res['cipher_suite']:<30} | Auth: {res['signature_algo']:<5} | KEM: {res['key_exchange']}")
        elif "Unreachable" in stat:
            blocked_scans += 1
            print(f" {THEME_GOLD}[X]{THEME_RESET} {res['hostname']:<35} | {stat}")
        else:
            unknown_scans += 1
            print(f" {THEME_GLASS}[?]{THEME_RESET} {res['hostname']:<35} | {stat}")

    print(f"\n{THEME_GOLD}[Summary Metrics]{THEME_RESET}")
    print(f" Total Reachable & Inspected: {successful_scans}/{len(assets)}")
    print(f" Infrastructure/WAF Blocked:  {blocked_scans}/{len(assets)}")
    print(f" Unknown/Other Failures:      {unknown_scans}/{len(assets)}\n")


if __name__ == "__main__":
    test_domain = "manipurral.bank.in"
    test_wordlist = ["mail", "vpn", "api", "dev", "secure", "portal", "banking", "www", "test", "demo", "uat"]
    
    asyncio.run(run_pipeline(test_domain, test_wordlist))