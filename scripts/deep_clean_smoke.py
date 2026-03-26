from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "runlogs"

class SmokeFailure(RuntimeError):
    pass

def _json_request(url: str, method: str = "GET", payload: dict | None = None, timeout: float = 10.0) -> tuple[int, dict]:
    data = None
    headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url=url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        parsed = {}
        if body:
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"raw": body}
        return exc.code, parsed

def _wait_for_server(base_url: str, deadline_sec: float) -> None:
    start = time.time()
    while time.time() - start < deadline_sec:
        try:
            status, _ = _json_request(f"{base_url}/api/network-status", timeout=2.0)
            if status == 200:
                return
        except Exception:
            pass
        time.sleep(0.6)
    raise SmokeFailure(f"Server did not become ready within {deadline_sec:.0f}s")

def _poll_scan(base_url: str, scan_id: str, timeout_sec: float) -> dict:
    start = time.time()
    while time.time() - start < timeout_sec:
        status, body = _json_request(f"{base_url}/api/scan/{scan_id}", timeout=8.0)
        if status != 200:
            raise SmokeFailure(f"Failed polling scan {scan_id}: HTTP {status} {body}")
        scan = body.get("scan") or {}
        state = str(scan.get("status") or "").lower()
        if state in {"completed", "failed"}:
            return body
        time.sleep(2.0)
    raise SmokeFailure(f"Timed out waiting for scan {scan_id} completion")

def _assert_completed(scan_body: dict, context: str, allow_failed: bool) -> None:
    scan = scan_body.get("scan") or {}
    status = str(scan.get("status") or "").lower()
    if status == "completed":
        return
    if allow_failed and status == "failed":
        return
    raise SmokeFailure(f"{context} did not complete successfully (status={status})")

def _run_standalone(base_url: str, domain: str, timeout_sec: float, allow_failed: bool) -> dict:
    status, body = _json_request(
        f"{base_url}/api/scan",
        method="POST",
        payload={"domain": domain, "deep_scan": False},
    )
    if status != 200:
        raise SmokeFailure(f"Standalone scan start failed: HTTP {status} {body}")
    scan_id = body.get("scan_id")
    if not scan_id:
        raise SmokeFailure(f"Standalone response missing scan_id: {body}")
    result = _poll_scan(base_url, str(scan_id), timeout_sec=timeout_sec)
    _assert_completed(result, "Standalone scan", allow_failed=allow_failed)
    return result

def _run_fleet(base_url: str, domains: list[str], timeout_sec: float, allow_failed: bool) -> list[dict]:
    status, body = _json_request(
        f"{base_url}/api/scan/batch",
        method="POST",
        payload={"domains": domains, "deep_scan": False},
    )
    if status != 200:
        raise SmokeFailure(f"Fleet scan start failed: HTTP {status} {body}")

    scans = body.get("scans")
    if not isinstance(scans, list) or not scans:
        raise SmokeFailure(f"Fleet response missing scan list: {body}")

    results: list[dict] = []
    for item in scans:
        scan_id = item.get("scan_id")
        if not scan_id:
            raise SmokeFailure(f"Fleet item missing scan_id: {item}")
        result = _poll_scan(base_url, str(scan_id), timeout_sec=timeout_sec)
        _assert_completed(result, f"Fleet scan {item.get('domain')}", allow_failed=allow_failed)
        results.append(result)
    return results

def _start_clean_server(port: int) -> subprocess.Popen:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out_path = LOG_DIR / f"deep-clean-{port}.out.log"
    err_path = LOG_DIR / f"deep-clean-{port}.err.log"
    out_f = out_path.open("w", encoding="utf-8")
    err_f = err_path.open("w", encoding="utf-8")

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]

    return subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=out_f,
        stderr=err_f,
        env=os.environ.copy(),
    )

def main() -> int:
    parser = argparse.ArgumentParser(description="Deep clean end-to-end smoke checks for QuantHunt")
    parser.add_argument("--port", type=int, default=8013, help="Port for temporary clean server process")
    parser.add_argument("--startup-timeout", type=float, default=40.0, help="Server startup timeout in seconds")
    parser.add_argument("--scan-timeout", type=float, default=240.0, help="Per scan completion timeout in seconds")
    parser.add_argument("--standalone-domain", default="pnb.bank.in", help="Domain for standalone scan check")
    parser.add_argument(
        "--fleet-domains",
        default="pnb.bank.in,axis.bank.in",
        help="Comma-separated domains for fleet check",
    )
    parser.add_argument(
        "--allow-failed",
        action="store_true",
        help="Treat failed terminal scans as acceptable completion",
    )
    args = parser.parse_args()

    base_url = f"http://127.0.0.1:{args.port}"
    fleet_domains = [x.strip() for x in str(args.fleet_domains).split(",") if x.strip()]
    if not fleet_domains:
        raise SmokeFailure("No fleet domains provided")

    server = _start_clean_server(args.port)
    started = time.time()

    try:
        _wait_for_server(base_url, deadline_sec=args.startup_timeout)

        net_status, net_body = _json_request(f"{base_url}/api/network-status")
        if net_status != 200:
            raise SmokeFailure(f"Network status check failed: HTTP {net_status} {net_body}")

        standalone = _run_standalone(
            base_url,
            domain=args.standalone_domain,
            timeout_sec=args.scan_timeout,
            allow_failed=args.allow_failed,
        )

        fleet_results = _run_fleet(
            base_url,
            domains=fleet_domains,
            timeout_sec=args.scan_timeout,
            allow_failed=args.allow_failed,
        )

        elapsed = time.time() - started
        print("DEEP CLEAN SMOKE: PASS")
        print(f"Base URL: {base_url}")
        print(f"Client IP: {net_body.get('ip', 'unknown')} | VPN: {net_body.get('message', '')}")
        print(
            "Standalone:",
            (standalone.get("scan") or {}).get("domain"),
            (standalone.get("scan") or {}).get("status"),
            (standalone.get("scan") or {}).get("scan_id"),
        )
        print("Fleet:")
        for entry in fleet_results:
            scan = entry.get("scan") or {}
            print(f"  - {scan.get('domain')} | {scan.get('status')} | {scan.get('scan_id')}")
        print(f"Elapsed: {elapsed:.1f}s")
        return 0
    except SmokeFailure as exc:
        print(f"DEEP CLEAN SMOKE: FAIL - {exc}")
        return 1
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()

if __name__ == "__main__":
    raise SystemExit(main())
