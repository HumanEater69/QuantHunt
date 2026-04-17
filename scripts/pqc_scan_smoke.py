#!/usr/bin/env python3
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
from typing import Any


ROOT = Path(__file__).resolve().parent.parent


class SmokeFailure(RuntimeError):
    pass


def _json_request(
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    data = None
    headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url=url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return int(resp.status), json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") if exc.fp else ""
        body: dict[str, Any]
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"raw": raw}
        return int(exc.code), body


def _start_server(port: int) -> subprocess.Popen:
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
        env=os.environ.copy(),
    )


def _wait_for_server(base_url: str, timeout_sec: float) -> None:
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            status, _ = _json_request(f"{base_url}/api/network-status", timeout=2.0)
            if status == 200:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise SmokeFailure(f"server did not become ready within {timeout_sec:.0f}s")


def _poll_scan(base_url: str, scan_id: str, timeout_sec: float) -> dict[str, Any]:
    start = time.time()
    while time.time() - start < timeout_sec:
        status, body = _json_request(f"{base_url}/api/scan/{scan_id}", timeout=8.0)
        if status != 200:
            raise SmokeFailure(f"poll failed for {scan_id}: HTTP {status} {body}")
        scan = body.get("scan") or {}
        state = str(scan.get("status") or "").lower()
        if state in {"completed", "failed"}:
            return body
        time.sleep(2.0)
    raise SmokeFailure(f"timeout waiting for scan {scan_id}")


def _print_pqc_assets(scan_body: dict[str, Any], max_assets: int = 8) -> None:
    scan = scan_body.get("scan") or {}
    assets = scan_body.get("assets") or []
    print(f"Scan: {scan.get('domain')} | {scan.get('status')} | {scan.get('scan_id')}")
    print("PQC assets:")
    for asset in assets[:max_assets]:
        print(
            "  - {hostname} | {status} | {provider} | {group} | {tls} | {method}".format(
                hostname=asset.get("hostname"),
                status=asset.get("pqc_status"),
                provider=asset.get("pqc_provider") or "-",
                group=asset.get("pqc_negotiated_group") or "-",
                tls=asset.get("pqc_tls_version") or "-",
                method=asset.get("pqc_detection_method") or "-",
            )
        )
        error = str(asset.get("pqc_error") or "").strip()
        if error:
            print(f"      error: {error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Real PQC scan smoke test for QuantHunt")
    parser.add_argument("--base", help="Backend base URL. If omitted, a temporary uvicorn server is started.")
    parser.add_argument("--port", type=int, default=8013, help="Port for the temporary backend server")
    parser.add_argument("--startup-timeout", type=float, default=40.0, help="Server startup timeout in seconds")
    parser.add_argument("--scan-timeout", type=float, default=240.0, help="Scan completion timeout in seconds")
    parser.add_argument("--domain", default="example.com", help="Domain to scan")
    parser.add_argument("--scan-model", default="general", choices=["general", "banking"], help="Scan model")
    parser.add_argument("--deep-scan", action="store_true", default=True, help="Enable deep scan mode")
    parser.add_argument("--shallow", dest="deep_scan", action="store_false", help="Disable deep scan mode")
    args = parser.parse_args()

    base_url = str(args.base).rstrip("/") if args.base else f"http://127.0.0.1:{args.port}"
    server = None

    try:
        if not args.base:
            server = _start_server(args.port)
        _wait_for_server(base_url, timeout_sec=args.startup_timeout)

        status, payload = _json_request(
            f"{base_url}/api/scan",
            method="POST",
            payload={"domain": args.domain, "deep_scan": bool(args.deep_scan), "scan_model": args.scan_model},
        )
        if status != 200:
            raise SmokeFailure(f"scan start failed: HTTP {status} {payload}")

        scan_id = str(payload.get("scan_id") or "")
        if not scan_id:
            raise SmokeFailure(f"scan start response missing scan_id: {payload}")

        final_body = _poll_scan(base_url, scan_id, timeout_sec=args.scan_timeout)
        _print_pqc_assets(final_body)

        print("PQC scan smoke: PASS")
        return 0
    except SmokeFailure as exc:
        print(f"PQC scan smoke: FAIL - {exc}")
        return 1
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    raise SystemExit(main())