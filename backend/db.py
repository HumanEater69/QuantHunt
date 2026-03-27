from __future__ import annotations

import os
from contextvars import ContextVar, Token
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

SCAN_MODELS = ("general", "banking")
DEFAULT_SCAN_MODEL = "general"

NEON_DATABASE_URL = os.getenv("NEON_DATABASE_URL", "").strip()

DATABASE_URL = (
    os.getenv("DATABASE_URL", "").strip()
    or NEON_DATABASE_URL
    or "sqlite:///./quantumshield_general.db"
)
BANKING_DATABASE_URL = (
    os.getenv("BANKING_DATABASE_URL", "").strip()
    or NEON_DATABASE_URL
    or "sqlite:///./quantumshield_banking.db"
)

DATABASE_URLS: dict[str, str] = {
    "general": DATABASE_URL,
    "banking": BANKING_DATABASE_URL,
}

_ACTIVE_SCAN_MODEL: ContextVar[str] = ContextVar("active_scan_model", default=DEFAULT_SCAN_MODEL)

def normalize_scan_model(scan_model: str | None) -> str:
    model = str(scan_model or "").strip().lower()
    if model not in SCAN_MODELS:
        return DEFAULT_SCAN_MODEL
    return model

def get_active_scan_model() -> str:
    return normalize_scan_model(_ACTIVE_SCAN_MODEL.get())

def set_active_scan_model(scan_model: str) -> Token:
    return _ACTIVE_SCAN_MODEL.set(normalize_scan_model(scan_model))

def reset_active_scan_model(token: Token) -> None:
    _ACTIVE_SCAN_MODEL.reset(token)

def _build_engine(url: str):
    return create_engine(
        url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )

ENGINES = {model: _build_engine(url) for model, url in DATABASE_URLS.items()}
SESSION_LOCALS = {
    model: sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True, expire_on_commit=False)
    for model, engine in ENGINES.items()
}

engine = ENGINES[DEFAULT_SCAN_MODEL]

def get_engine(scan_model: str | None = None):
    model = normalize_scan_model(scan_model or get_active_scan_model())
    return ENGINES[model]

def get_all_engines() -> dict[str, object]:
    return dict(ENGINES)

@contextmanager
def get_session(scan_model: str | None = None) -> Session:
    model = normalize_scan_model(scan_model or get_active_scan_model())
    session = SESSION_LOCALS[model]()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
