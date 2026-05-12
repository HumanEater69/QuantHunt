from __future__ import annotations

import asyncio
import contextlib
import re
import socket
import ssl

import httpx

try:
    import dns.asyncresolver  # type: ignore
except Exception:  # pragma: no cover - optional dependency fallback
    dns = None
else:
    import dns  # type: ignore

from ..models import PQCResult, PQCStatus

GROUP_PATTERN = re.compile(r"Server Temp Key:\s+(\S+)", re.I)
TLS_VERSION_PATTERN = re.compile(r"Protocol(?:\s+version)?\s*:\s*(TLSv[\d.]+)", re.I)
ERROR_PATTERN = re.compile(r"verify error|handshake failure|alert|errno|connection refused|timed out|timeout", re.I)

PQC_GROUPS = {
    "X25519MLKEM768",
    "SECP256R1MLKEM768",
    "SECP384R1MLKEM1024",
    "X25519KYBER768DRAFT00",
}

CLASSICAL_GROUPS = {
    "X25519",
    "SECP256R1",
    "SECP384R1",
    "P-256",
    "P-384",
}

ASN_ORG_MAP = [
    ("cloudflare", "Cloudflare"),
    ("google", "Google"),
    ("amazon", "Amazon AWS"),
    ("aws", "Amazon AWS"),
    ("fastly", "Fastly"),
    ("akamai", "Akamai"),
    ("microsoft", "Microsoft Azure"),
    ("azure", "Microsoft Azure"),
    ("anthropic", "Anthropic"),
    ("meta ", "Meta"),
    ("facebook", "Meta"),
    ("apple", "Apple"),
]


def _normalize_host(hostname: str) -> str:
    return str(hostname or "").strip().rstrip(".")


def _version_tuple(version_text: str | None) -> tuple[int, int, int]:
    text = str(version_text or "")
    match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return (0, 0, 0)
    return tuple(int(part) for part in match.groups())


async def _openssl_version(openssl_binary: str) -> tuple[int, int, int] | None:
    try:
        process = await asyncio.create_subprocess_exec(
            openssl_binary,
            "version",
            "-v",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return None
    stdout, stderr = await process.communicate()
    output = (stdout or b"") + (stderr or b"")
    if process.returncode != 0:
        return None
    return _version_tuple(output.decode("utf-8", errors="ignore"))


async def _resolve_hostname(hostname: str) -> str | None:
    host = _normalize_host(hostname)
    if not host:
        return None

    if dns is not None:
        resolver = dns.asyncresolver.Resolver()  # type: ignore[attr-defined]
        for record_type in ("A", "AAAA"):
            with contextlib.suppress(Exception):
                answers = await resolver.resolve(host, record_type)
                for answer in answers:
                    text = str(answer).strip()
                    if text:
                        return text

    loop = asyncio.get_running_loop()
    with contextlib.suppress(Exception):
        infos = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        for family, _socktype, _proto, _canonname, sockaddr in infos:
            if family in (socket.AF_INET, socket.AF_INET6) and sockaddr:
                return str(sockaddr[0])
    return None


async def _reverse_dns(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        host, _aliases, _ips = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return host
    except Exception:
        return None


async def _asn_org(ip: str | None) -> str | None:
    if not ip:
        return None
    url = f"http://ip-api.com/json/{ip}?fields=status,message,as,org,query"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(4.0, connect=2.0)) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return None
            payload = response.json()
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    org = str(payload.get("org") or payload.get("as") or "").strip()
    return org or None


def _detect_provider_from_text(text: str | None) -> str | None:
    blob = str(text or "").lower()
    for needle, provider in ASN_ORG_MAP:
        if needle in blob:
            return provider
    return None


def _detect_cdn_headers(headers: httpx.Headers) -> tuple[str | None, list[str]]:
    detected: list[str] = []
    provider: str | None = None
    normalized = {k.lower(): v for k, v in headers.items()}
    items = list(normalized.items())

    for raw_key, provider_name in {
        "CF-Ray": "Cloudflare",
        "cf-ray": "Cloudflare",
        "server:cloudflare": "Cloudflare",
        "x-amz-cf-id": "Amazon CloudFront",
        "x-amz-request-id": "Amazon AWS",
        "x-cache:cloudfront": "Amazon CloudFront",
        "via:cloudfront": "Amazon CloudFront",
        "x-goog-": "Google",
        "via:1.1 google": "Google",
        "x-google-": "Google",
        "x-fastly-": "Fastly",
        "fastly-io-info": "Fastly",
        "x-azure-": "Microsoft Azure",
        "x-ms-": "Microsoft Azure",
        "x-akamai-": "Akamai",
        "akamai-cache-status": "Akamai",
        "x-served-by": "Fastly",
    }.items():
        lowered = raw_key.lower()
        if ":" in lowered:
            key, value = lowered.split(":", 1)
            for hdr_key, hdr_value in items:
                if hdr_key == key and value in f"{hdr_key}:{hdr_value}".lower():
                    detected.append(raw_key)
                    provider = provider or provider_name
        elif lowered.endswith("-"):
            for hdr_key, _hdr_value in items:
                if hdr_key.startswith(lowered):
                    detected.append(hdr_key)
                    provider = provider or provider_name
        else:
            for hdr_key, hdr_value in items:
                if hdr_key == lowered or hdr_value.lower() == lowered:
                    detected.append(raw_key)
                    provider = provider or provider_name

    seen: set[str] = set()
    unique: list[str] = []
    for item in detected:
        token = item.strip()
        if token and token not in seen:
            seen.add(token)
            unique.append(token)
    return provider, unique


async def _cdn_probe(hostname: str, port: int, timeout: int) -> tuple[str | None, list[str]]:
    timeout_cfg = httpx.Timeout(max(2.0, float(timeout)), connect=min(4.0, float(timeout)))
    try:
        async with httpx.AsyncClient(timeout=timeout_cfg, verify=False, follow_redirects=True) as client:
            response = await client.head(f"https://{hostname}:{port}")
            provider, headers = _detect_cdn_headers(response.headers)
            if provider or headers:
                return provider, headers
            return None, []
    except Exception:
        return None, []


async def _run_openssl_probe(
    hostname: str,
    port: int,
    timeout: int,
    openssl_binary: str,
) -> tuple[str, str | None, str | None, str | None]:
    cmd = [
        openssl_binary,
        "s_client",
        "-connect",
        f"{hostname}:{port}",
        "-groups",
        "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:secp256r1:secp384r1",
        "-tls1_3",
        "-brief",
        "-servername",
        hostname,
    ]
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=b""),
            timeout=max(2.0, float(timeout)),
        )
    except asyncio.TimeoutError:
        process.kill()
        with contextlib.suppress(Exception):
            await process.communicate()
        return "", None, None, "openssl probe timed out"

    output = ((stdout or b"") + (stderr or b"")).decode("utf-8", errors="ignore")
    group = None
    tls_version = None
    for match in GROUP_PATTERN.finditer(output):
        group = match.group(1).strip().upper() or group
    version_match = TLS_VERSION_PATTERN.search(output)
    if version_match:
        tls_version = version_match.group(1).strip()
    error = output.strip() if ERROR_PATTERN.search(output) else None
    return output, group, tls_version, error


def _classify_group(group: str | None) -> tuple[PQCStatus | None, str | None]:
    normalized = (group or "").strip().upper()
    if not normalized:
        return None, None
    if normalized in PQC_GROUPS or any(token in normalized for token in ("MLKEM", "KYBER")):
        return PQCStatus.PASS, normalized
    if normalized in CLASSICAL_GROUPS or normalized:
        return None, normalized
    return None, normalized


async def _python_ssl_probe(hostname: str, port: int, timeout: int) -> tuple[str | None, str | None, str | None]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        with contextlib.suppress(Exception):
            context.minimum_version = ssl.TLSVersion.TLSv1_3  # type: ignore[attr-defined]

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=hostname,
                port=port,
                ssl=context,
                server_hostname=hostname,
                ssl_handshake_timeout=max(2.0, float(timeout)),
            ),
            timeout=max(2.0, float(timeout)),
        )
    except Exception as exc:
        return None, None, str(exc)

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        tls_version = ssl_object.version() if ssl_object else None
        cipher = ssl_object.cipher()[0] if ssl_object and ssl_object.cipher() else None
        return tls_version, cipher, None
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def probe_pqc(
    hostname: str,
    port: int = 443,
    timeout: int = 10,
    openssl_binary: str = "openssl",
) -> PQCResult:
    host = _normalize_host(hostname)
    result = PQCResult(
        hostname=host,
        port=port,
        status=PQCStatus.ERROR,
        detection_method="fallback",
    )

    if not host:
        result.error = "empty hostname"
        return result

    result.resolved_ip = await _resolve_hostname(host)

    version = await _openssl_version(openssl_binary)
    use_openssl = version is not None and version >= (3, 4, 0)

    if use_openssl:
        try:
            output, group, tls_version, error = await _run_openssl_probe(host, port, timeout, openssl_binary)
            result.raw_openssl_output = output or None
            result.negotiated_group = group
            result.tls_version = tls_version
            result.detection_method = "openssl"
            if group:
                status, normalized_group = _classify_group(group)
                result.negotiated_group = normalized_group
                if status == PQCStatus.PASS:
                    result.status = PQCStatus.PASS
                    return result
            if result.tls_version and not result.tls_version.startswith("TLSv1.3"):
                result.status = PQCStatus.FAIL
                result.error = error
                return result
            if error and not result.negotiated_group:
                result.status = PQCStatus.FAIL
                result.error = error
                return result
        except FileNotFoundError:
            use_openssl = False
        except Exception as exc:
            result.error = str(exc)
            use_openssl = False

    if not use_openssl:
        result.detection_method = "python_ssl"
        tls_version, cipher, error = await _python_ssl_probe(host, port, timeout)
        result.tls_version = tls_version
        result.negotiated_group = cipher
        if error:
            result.status = PQCStatus.ERROR
            result.error = error
            return result
        if cipher and any(token in cipher.upper() for token in ("MLKEM", "KYBER")):
            result.status = PQCStatus.PASS
            return result
        if tls_version and tls_version != "TLSv1.3":
            result.status = PQCStatus.FAIL
            return result

    if result.status == PQCStatus.PASS:
        return result

    if not result.tls_version:
        result.tls_version = "TLSv1.3" if result.negotiated_group else None

    provider, headers = await _cdn_probe(host, port, timeout)
    result.cdn_headers_detected = headers
    ptr = await _reverse_dns(result.resolved_ip)
    asn_org = await _asn_org(result.resolved_ip)
    result.asn_org = asn_org or ptr

    provider_from_asn = _detect_provider_from_text(asn_org)
    provider_from_ptr = _detect_provider_from_text(ptr)
    result.provider = provider or provider_from_asn or provider_from_ptr

    if result.tls_version and result.tls_version != "TLSv1.3":
        result.status = PQCStatus.FAIL
        return result

    if result.provider or headers or provider_from_asn or provider_from_ptr:
        result.status = PQCStatus.HYBRID
    elif result.negotiated_group or result.tls_version:
        result.status = PQCStatus.FAIL
    else:
        result.status = PQCStatus.ERROR
        if not result.error:
            result.error = "probe failed"

    return result


async def bulk_probe_pqc(
    hostnames: list[str],
    concurrency: int = 20,
    timeout: int = 10,
    port: int = 443,
) -> list[PQCResult]:
    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[PQCResult] = [
        PQCResult(hostname=str(host or "").strip(), port=443, status=PQCStatus.ERROR, detection_method="fallback")
        for host in hostnames
    ]

    async def _probe_at(index: int, host: str) -> None:
        async with sem:
            try:
                results[index] = await probe_pqc(host, port=port, timeout=timeout)
            except Exception as exc:
                results[index] = PQCResult(
                    hostname=str(host or "").strip(),
                    port=port,
                    status=PQCStatus.ERROR,
                    detection_method="fallback",
                    error=str(exc),
                )

    await asyncio.gather(*(_probe_at(index, host) for index, host in enumerate(hostnames)))
    return results