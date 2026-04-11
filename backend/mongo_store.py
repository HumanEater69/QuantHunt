from __future__ import annotations

import os
from datetime import datetime, timezone
from threading import Lock
from typing import Any

try:
    from pymongo import ASCENDING, MongoClient  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency
    ASCENDING = 1
    MongoClient = None

_MONGO_CLIENT: Any = None
_MONGO_LOCK = Lock()
_MONGO_INDEX_READY = False
_MONGO_LAST_ERROR: str | None = None


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


def mongo_enabled() -> bool:
    return bool(_env("MONGODB_URI")) and MongoClient is not None


def _mongo_db_name() -> str:
    return _env("MONGODB_DB", "quanthunt")


def _mongo_collection_name() -> str:
    return _env("MONGODB_COLLECTION", "scan_snapshots")


def _get_client() -> Any:
    global _MONGO_CLIENT
    global _MONGO_LAST_ERROR

    uri = _env("MONGODB_URI")
    if not uri:
        raise RuntimeError("MONGODB_URI is not configured")
    if MongoClient is None:
        raise RuntimeError("pymongo is not installed")

    with _MONGO_LOCK:
        if _MONGO_CLIENT is not None:
            return _MONGO_CLIENT
        client = MongoClient(uri, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000)
        try:
            client.admin.command("ping")
        except Exception as ex:  # pragma: no cover - network dependent
            _MONGO_LAST_ERROR = str(ex)
            raise
        _MONGO_CLIENT = client
        _MONGO_LAST_ERROR = None
        return _MONGO_CLIENT


def _get_collection():
    client = _get_client()
    db = client[_mongo_db_name()]
    return db[_mongo_collection_name()]


def _ensure_indexes() -> None:
    global _MONGO_INDEX_READY

    if _MONGO_INDEX_READY:
        return
    coll = _get_collection()
    coll.create_index([("scan.scan_id", ASCENDING)], unique=True, name="uq_scan_id")
    coll.create_index([("scan.domain", ASCENDING)], name="idx_domain")
    coll.create_index([("scan.created_at", ASCENDING)], name="idx_created_at")
    _MONGO_INDEX_READY = True


def mongo_status() -> dict[str, Any]:
    if not mongo_enabled():
        return {
            "enabled": False,
            "connected": False,
            "database": _mongo_db_name(),
            "collection": _mongo_collection_name(),
            "error": None,
        }

    try:
        _get_client().admin.command("ping")
        return {
            "enabled": True,
            "connected": True,
            "database": _mongo_db_name(),
            "collection": _mongo_collection_name(),
            "error": None,
        }
    except Exception as ex:  # pragma: no cover - network dependent
        return {
            "enabled": True,
            "connected": False,
            "database": _mongo_db_name(),
            "collection": _mongo_collection_name(),
            "error": str(ex),
        }


def upsert_scan_snapshot(scan_payload: dict[str, Any], scan_model: str | None = None) -> bool:
    if not mongo_enabled():
        return False

    scan = scan_payload.get("scan") or {}
    scan_id = str(scan.get("scan_id") or "").strip()
    if not scan_id:
        return False

    _ensure_indexes()
    coll = _get_collection()
    now_iso = datetime.now(timezone.utc).isoformat()

    doc: dict[str, Any] = {
        "scan": scan,
        "scan_model": str(scan_model or "").strip().lower() or scan.get("scan_model") or "general",
        "report_buckets": scan_payload.get("report_buckets") or {},
        "assets": scan_payload.get("assets") or [],
        "logs": scan_payload.get("logs") or [],
        "cbom": scan_payload.get("cbom"),
        "chain_blocks": scan_payload.get("chain_blocks") or [],
        "updated_at": now_iso,
    }

    coll.update_one(
        {"scan.scan_id": scan_id},
        {
            "$set": doc,
            "$setOnInsert": {"created_at": now_iso},
        },
        upsert=True,
    )
    return True
