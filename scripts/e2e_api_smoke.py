from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def http_json(method: str, url: str, payload: dict[str, Any] | None = None, timeout: float = 20.0) -> tuple[int, Any, dict[str, str]]:
    data = None
    headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            body = json.loads(raw) if raw else {}
            meta = {"content_type": str(resp.headers.get("Content-Type", "")), "content_length": str(resp.headers.get("Content-Length", ""))}
            return int(resp.status), body, meta
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") if exc.fp else ""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"raw": raw}
        return int(exc.code), body, {}


def http_bytes(method: str, url: str, timeout: float = 30.0) -> tuple[int, int, str]:
    req = urllib.request.Request(url=url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            blob = resp.read()
            return int(resp.status), len(blob), str(resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as exc:
        return int(exc.code), 0, ""


def poll_scan(base: str, scan_id: str, timeout_sec: int = 240) -> dict[str, Any]:
    start = time.time()
    while time.time() - start < timeout_sec:
        st, body, _ = http_json("GET", f"{base}/api/scan/{scan_id}")
        if st != 200:
            raise RuntimeError(f"poll failed for {scan_id}: HTTP {st} {body}")
        scan = body.get("scan") or {}
        status = str(scan.get("status") or "").lower()
        if status in {"completed", "failed"}:
            return body
        time.sleep(2)
    raise RuntimeError(f"timeout waiting for scan {scan_id}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8013")
    ap.add_argument("--single-domain", default="example.com")
    ap.add_argument("--batch-domains", default="example.com,cloudflare.com")
    args = ap.parse_args()

    base = str(args.base).rstrip("/")
    batch_domains = [x.strip() for x in str(args.batch_domains).split(",") if x.strip()]

    out: dict[str, Any] = {
        "base": base,
        "single": {},
        "batch": {},
        "downloads": {},
    }

    # baseline completed scan for download checks
    st, scans_body, _ = http_json("GET", f"{base}/api/scans?scan_model=general")
    if st != 200:
        raise RuntimeError(f"/api/scans failed: HTTP {st} {scans_body}")
    completed = [x for x in (scans_body or []) if str(x.get("status", "")).lower() == "completed" and x.get("scan_id")]
    baseline_scan_id = str(completed[0]["scan_id"]) if completed else ""
    out["baseline_completed_scan_id"] = baseline_scan_id or None

    # single scan
    st, single_create, _ = http_json(
        "POST",
        f"{base}/api/scan",
        payload={"domain": args.single_domain, "deep_scan": True, "scan_model": "general"},
    )
    if st != 200:
        raise RuntimeError(f"single create failed: HTTP {st} {single_create}")
    single_scan_id = str(single_create.get("scan_id") or "")
    if not single_scan_id:
        raise RuntimeError(f"single create missing scan_id: {single_create}")
    single_final = poll_scan(base, single_scan_id)
    out["single"] = {
        "scan_id": single_scan_id,
        "create": single_create,
        "final_status": (single_final.get("scan") or {}).get("status"),
    }

    # batch scan
    st, batch_create, _ = http_json(
        "POST",
        f"{base}/api/scan/batch",
        payload={"domains": batch_domains, "deep_scan": True, "scan_model": "general"},
    )
    if st != 200:
        raise RuntimeError(f"batch create failed: HTTP {st} {batch_create}")
    scans = batch_create.get("scans") or []
    batch_scan_ids = [str(x.get("scan_id")) for x in scans if x.get("scan_id")]
    if not batch_scan_ids:
        raise RuntimeError(f"batch create missing scan ids: {batch_create}")

    # progress endpoint check
    progress_payload = {
        "scans": [
            {"scan_id": x.get("scan_id"), "scan_model": x.get("scan_model")}
            for x in scans
            if x.get("scan_id")
        ]
    }
    st, batch_progress, _ = http_json("POST", f"{base}/api/scan/batch/progress", payload=progress_payload)
    out["batch_progress_http"] = st
    out["batch_progress_keys"] = sorted(list((batch_progress or {}).keys())) if isinstance(batch_progress, dict) else []

    batch_finals = []
    for sid in batch_scan_ids:
        final = poll_scan(base, sid)
        batch_finals.append({"scan_id": sid, "status": (final.get("scan") or {}).get("status")})

    out["batch"] = {
        "create": batch_create,
        "finals": batch_finals,
    }

    # choose download scan id preferring completed from this run
    download_scan_id = ""
    if str(out["single"].get("final_status", "")).lower() == "completed":
        download_scan_id = single_scan_id
    else:
        for f in batch_finals:
            if str(f.get("status", "")).lower() == "completed":
                download_scan_id = str(f["scan_id"])
                break
    if not download_scan_id and baseline_scan_id:
        download_scan_id = baseline_scan_id

    if not download_scan_id:
        out["downloads"] = {"error": "no completed scan available to verify artifact endpoints"}
    else:
        cbom_http, cbom_body, _ = http_json("GET", f"{base}/api/scan/{download_scan_id}/cbom")
        report_http, report_size, report_ct = http_bytes("GET", f"{base}/api/scan/{download_scan_id}/report.pdf")
        cert_http, cert_size, cert_ct = http_bytes("GET", f"{base}/api/scan/{download_scan_id}/certificate.pdf")
        out["downloads"] = {
            "scan_id": download_scan_id,
            "cbom_http": cbom_http,
            "cbom_has_components": bool(isinstance(cbom_body, dict) and isinstance(cbom_body.get("components"), list)),
            "report_http": report_http,
            "report_size_bytes": report_size,
            "report_content_type": report_ct,
            "certificate_http": cert_http,
            "certificate_size_bytes": cert_size,
            "certificate_content_type": cert_ct,
        }

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
