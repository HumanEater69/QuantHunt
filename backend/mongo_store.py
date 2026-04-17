from __future__ import annotations

from datetime import datetime, timezone
import os
from threading import Lock
from typing import Any

try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None  # type: ignore[assignment]

_CLIENT = None
_CLIENT_LOCK = Lock()
_LAST_ERROR: str | None = None


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mongo_uri() -> str:
    for key in ("MONGODB_URI", "MONGO_URI", "MONGO_URL"):
        value = str(os.getenv(key, "")).strip()
        if value:
            return value
    return ""


def _mongo_db_name() -> str:
    for key in ("MONGODB_DB", "MONGO_DB", "MONGO_DATABASE"):
        value = str(os.getenv(key, "")).strip()
        if value:
            return value
    return "quanthunt"


def _mongo_collection_name() -> str:
    value = str(os.getenv("MONGO_SNAPSHOT_COLLECTION", "")).strip()
    return value or "scan_snapshots"


def _mongo_available() -> bool:
    return MongoClient is not None


def _mongo_enabled() -> bool:
    return bool(_mongo_uri()) and _mongo_available()


def _get_client() -> Any:
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT is not None:
            return _CLIENT
        uri = _mongo_uri()
        if not uri:
            return None
        if not _mongo_available():
            return None
        _CLIENT = MongoClient(uri, serverSelectionTimeoutMS=1500)
        return _CLIENT


def mongo_status() -> dict[str, Any]:
    global _LAST_ERROR
    uri_configured = bool(_mongo_uri())
    pymongo_available = _mongo_available()
    status: dict[str, Any] = {
        "enabled": uri_configured and pymongo_available,
        "uri_configured": uri_configured,
        "pymongo_available": pymongo_available,
        "connected": False,
        "db": _mongo_db_name(),
        "collection": _mongo_collection_name(),
        "last_error": _LAST_ERROR,
    }

    if not status["enabled"]:
        if uri_configured and not pymongo_available:
            status["last_error"] = "pymongo not installed"
        return status

    try:
        client = _get_client()
        if client is None:
            status["last_error"] = "mongo client unavailable"
            return status
        client.admin.command("ping")
        status["connected"] = True
        status["last_error"] = None
        _LAST_ERROR = None
        return status
    except Exception as exc:
        _LAST_ERROR = str(exc)
        status["last_error"] = _LAST_ERROR
        return status


def upsert_scan_snapshot(detail: dict[str, Any], scan_model: str = "general") -> dict[str, Any]:
    global _LAST_ERROR

    if not isinstance(detail, dict):
        raise TypeError("detail must be a dict")

    if not _mongo_enabled():
        return {
            "ok": False,
            "reason": "mongo disabled",
            "enabled": False,
        }

    scan = detail.get("scan") if isinstance(detail.get("scan"), dict) else {}
    scan_id = scan.get("scan_id")
    domain = scan.get("domain")
    if not scan_id:
        raise ValueError("detail.scan.scan_id is required for mongo snapshot upsert")

    payload = {
        "_id": f"{scan_model}:{scan_id}",
        "scan_id": scan_id,
        "scan_model": str(scan_model or "general"),
        "domain": domain,
        "status": scan.get("status"),
        "progress": scan.get("progress"),
        "updated_at": _utc_iso_now(),
        "payload": detail,
    }

    try:
        client = _get_client()
        if client is None:
            return {
                "ok": False,
                "reason": "mongo client unavailable",
                "enabled": True,
            }
        coll = client[_mongo_db_name()][_mongo_collection_name()]
        coll.replace_one({"_id": payload["_id"]}, payload, upsert=True)
        _LAST_ERROR = None
        return {
            "ok": True,
            "id": payload["_id"],
            "db": _mongo_db_name(),
            "collection": _mongo_collection_name(),
        }
    except Exception as exc:
        _LAST_ERROR = str(exc)
        raise
