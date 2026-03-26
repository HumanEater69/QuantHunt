from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class Base(DeclarativeBase):
    pass

class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    deep_scan: Mapped[bool] = mapped_column(default=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    logs: Mapped[list["ScanLog"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["CryptoFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    recommendations: Mapped[list["Recommendation"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    cbom_exports: Mapped[list["CbomExport"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    chain_blocks: Mapped[list["ChainBlock"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    message: Mapped[str] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="logs")

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    asset_type: Mapped[str] = mapped_column(String(32), default="web")
    tls_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    label: Mapped[str] = mapped_column(String(64), default="Unknown")
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="assets")
    findings: Mapped[list["CryptoFinding"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    recommendations: Mapped[list["Recommendation"]] = relationship(back_populates="asset", cascade="all, delete-orphan")

class CryptoFinding(Base):
    __tablename__ = "crypto_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    category: Mapped[str] = mapped_column(String(64))
    algorithm: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32))
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    asset: Mapped["Asset"] = relationship(back_populates="findings")

class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    phase: Mapped[str] = mapped_column(String(64), default="Phase 1")
    text: Mapped[str] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="recommendations")
    asset: Mapped["Asset"] = relationship(back_populates="recommendations")

class CbomExport(Base):
    __tablename__ = "cbom_exports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    cbom_json: Mapped[dict] = mapped_column(JSON)

    scan: Mapped["Scan"] = relationship(back_populates="cbom_exports")

class ChainBlock(Base):
    __tablename__ = "chain_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    block_index: Mapped[int] = mapped_column(Integer, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.scan_id"), index=True, unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    payload_hash: Mapped[str] = mapped_column(String(64), index=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[int] = mapped_column(Integer, default=0)
    difficulty: Mapped[int] = mapped_column(Integer, default=2)
    block_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    algo_version: Mapped[str] = mapped_column(String(32), default="chain-v1-sha256-pow")

    scan: Mapped["Scan"] = relationship(back_populates="chain_blocks")
