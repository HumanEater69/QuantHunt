
import os

code = """from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Dict, Any

from ..models import TLSInfo
from .cipher_parser import parse_cipher_suite
from .cipher_database import get_cipher_metadata

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TLS_PROBE_CONCURRENCY_LIMIT = 50
_SEM = asyncio.Semaphore(TLS_PROBE_CONCURRENCY_LIMIT)

def _build_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

async def inspect_tls_async(host: str, port: int = 443, timeout: float = 7.0) -> TLSInfo:
    """Perform a robust TLS handshake extracting granular cryptographic details."""
    async with _SEM:
        info = TLSInfo(host=host, port=port)
        ctx = _build_context()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            ssl_writer = await asyncio.wait_for(
                asyncio.get_running_loop().start_tls(
                    writer.transport,
                    writer.get_extra_info("socket"),
                    ctx,
                    server_hostname=host # Strict Constraints SNI
                ),
                timeout=timeout
            )

            # Success extraction
            socket_extra = ssl_writer.get_extra_info("ssl_object")
            
            info.tls_version = socket_extra.version()
            cipher_info = socket_extra.cipher()
            info.cipher_suite = cipher_info[0] if cipher_info else "Unknown"
            
            # Additional detail extraction if possible
            parsed = parse_cipher_suite(info.cipher_suite)
            info.key_exchange_algorithm = str(parsed.get("key_exchange") or "Unknown").strip()
            
            try:
                # OpenSSL hints or cert chains
                cert = socket_extra.getpeercert(binary_form=False)
            except Exception:
                pass
                
            info.key_exchange_family = "hybrid" if "ML" in info.key_exchange_algorithm.upper() else "classical"
            info.network_status = "ok"

            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            info.scan_error = "Unreachable (Network Blocked)"
            info.network_status = "network_blocked"
        except ConnectionRefusedError:
            info.scan_error = "Unreachable (Service Closed)"
            info.network_status = "service_closed"
        except ssl.SSLError as e:
            info.scan_error = f"TLS Error ({e})"
            info.network_status = "tls_handshake"
        except Exception as e:
            info.scan_error = "Unreachable (Network Blocked)"
            info.network_status = "network_blocked"
            
        return info

async def probe_service_ports_async(host: str, timeout: float = 5.0) -> list[dict[str, object]]:
    return []
"""

with open("backend/scanner/tls_inspector.py", "w", encoding="utf-8") as f:
    f.write(code)

