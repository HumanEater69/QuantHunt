from __future__ import annotations

import asyncio

from .models import ScanState

class InMemoryStore:
    def __init__(self) -> None:
        self._scans: dict[str, ScanState] = {}
        self._lock = asyncio.Lock()

    async def create_scan(self, scan: ScanState) -> None:
        async with self._lock:
            self._scans[scan.scan_id] = scan

    async def get_scan(self, scan_id: str) -> ScanState | None:
        async with self._lock:
            return self._scans.get(scan_id)

    async def update_scan(self, scan: ScanState) -> None:
        async with self._lock:
            self._scans[scan.scan_id] = scan

    async def list_scans(self) -> list[ScanState]:
        async with self._lock:
            return list(self._scans.values())

store = InMemoryStore()
