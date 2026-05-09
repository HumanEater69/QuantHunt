from __future__ import annotations

import asyncio
import json
import os
import traceback
from typing import Any

from supabase import Client, create_client

from .quanthunt_engine import run_quanthunt_scan


POLL_SECONDS = float(os.getenv("QUANTHUNT_WORKER_POLL_SECONDS", "8"))


def get_supabase() -> Client:
    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    return create_client(url, key)


def claim_pending_scan(supabase: Client) -> dict[str, Any] | None:
    response = supabase.rpc("claim_pending_scan").execute()
    if not response.data:
        return None
    if isinstance(response.data, list):
        return response.data[0] if response.data else None
    return response.data


def update_scan_status(
    supabase: Client,
    scan_id: str,
    status: str,
    results: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {"status": status}
    if results is not None:
        payload["results"] = results
    supabase.table("scan_jobs").update(payload).eq("id", scan_id).execute()


async def run_scan_for_row(supabase: Client, row: dict[str, Any]) -> None:
    scan_id = str(row["id"])
    target_domain = str(row["target_domain"]).strip().lower()
    try:
        raw = await run_quanthunt_scan(target_domain)
        try:
            results = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            results = {"raw_output": raw}
        update_scan_status(supabase, scan_id, "completed", results)
    except Exception as exc:
        traceback.print_exc()
        update_scan_status(
            supabase,
            scan_id,
            "failed",
            {"error": str(exc), "target_domain": target_domain},
        )


async def poll_forever() -> None:
    supabase = get_supabase()
    while True:
        row = claim_pending_scan(supabase)
        if row:
            await run_scan_for_row(supabase, row)
            continue
        await asyncio.sleep(POLL_SECONDS)


def main() -> None:
    asyncio.run(poll_forever())


if __name__ == "__main__":
    main()
