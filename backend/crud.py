from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .tables import Asset, CbomExport, ChainBlock, CryptoFinding, Recommendation, Scan, ScanLog

def create_scan(session: Session, domain: str, deep_scan: bool = True) -> Scan:
    scan = Scan(scan_id=str(uuid4()), domain=domain, deep_scan=deep_scan, status="queued")
    session.add(scan)
    session.flush()
    return scan

def get_scan(session: Session, scan_id: str) -> Scan | None:
    return session.get(Scan, scan_id)

def add_log(session: Session, scan_id: str, message: str) -> None:
    session.add(ScanLog(scan_id=scan_id, message=message))

def set_scan_state(session: Session, scan_id: str, status: str, progress: int | None = None, error: str | None = None) -> None:
    scan = session.get(Scan, scan_id)
    if not scan:
        return
    scan.status = status
    if progress is not None:
        scan.progress = progress
    if error is not None:
        scan.error = error
    if status in {"completed", "failed"}:
        scan.completed_at = datetime.now(timezone.utc)

def create_asset(
    session: Session,
    scan_id: str,
    hostname: str,
    tls_version: str | None,
    cipher_suite: str | None,
    risk_score: float,
    label: str,
    metadata_json: dict | None = None,
    asset_type: str = "web",
) -> Asset:
    asset = Asset(
        scan_id=scan_id,
        hostname=hostname,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        risk_score=risk_score,
        label=label,
        metadata_json=metadata_json,
        asset_type=asset_type,
    )
    session.add(asset)
    session.flush()
    return asset

def add_crypto_finding(session: Session, scan_id: str, asset_id: int, category: str, algorithm: str, status: str, details: str | None = None) -> None:
    session.add(
        CryptoFinding(
            scan_id=scan_id,
            asset_id=asset_id,
            category=category,
            algorithm=algorithm,
            status=status,
            details=details,
        )
    )

def add_recommendation(session: Session, scan_id: str, asset_id: int, text: str, phase: str = "Phase 1") -> None:
    session.add(Recommendation(scan_id=scan_id, asset_id=asset_id, text=text, phase=phase))

def save_cbom(session: Session, scan_id: str, cbom_json: dict) -> None:
    session.add(CbomExport(scan_id=scan_id, cbom_json=cbom_json))

def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def _mine_block(seed: str, difficulty: int) -> tuple[int, str]:
    prefix = "0" * max(1, difficulty)
    nonce = 0
    while True:
        digest = _sha256(f"{seed}|{nonce}")
        if digest.startswith(prefix):
            return nonce, digest
        nonce += 1

def append_chain_block(session: Session, scan_id: str, payload: dict, difficulty: int = 2) -> ChainBlock:
    existing = session.execute(select(ChainBlock).where(ChainBlock.scan_id == scan_id)).scalars().first()
    if existing:
        return existing

    prev = session.execute(select(ChainBlock).order_by(desc(ChainBlock.block_index))).scalars().first()
    block_index = (prev.block_index + 1) if prev else 1
    prev_hash = prev.block_hash if prev else "0" * 64
    payload_hash = _sha256(_canonical_json(payload))
    seed = f"{block_index}|{scan_id}|{payload_hash}|{prev_hash}|{difficulty}"
    nonce, block_hash = _mine_block(seed, difficulty)
    block = ChainBlock(
        block_index=block_index,
        scan_id=scan_id,
        payload_hash=payload_hash,
        prev_hash=prev_hash,
        nonce=nonce,
        difficulty=difficulty,
        block_hash=block_hash,
    )
    session.add(block)
    session.flush()
    return block

def _oid_for_algorithm(algorithm: str) -> str:
    a = (algorithm or "").upper()
    if any(x in a for x in ["ML-KEM", "MLKEM", "KYBER"]):
        return "2.16.840.1.101.3.4.4.1"
    if any(x in a for x in ["ML-DSA", "MLDSA", "DILITHIUM"]):
        return "2.16.840.1.101.3.4.5.1"
    if any(x in a for x in ["SLH-DSA", "SLHDSA", "SPHINCS"]):
        return "2.16.840.1.101.3.4.5.2"
    if "RSA" in a:
        return "1.2.840.113549.1.1.1"
    if "ECDSA" in a:
        return "1.2.840.10045.4.3.2"
    if "CHACHA20" in a:
        return "1.3.6.1.4.1.11591.15.1"
    if any(x in a for x in ["AES_256", "AES256"]):
        return "2.16.840.1.101.3.4.1.42"
    if any(x in a for x in ["AES_128", "AES128"]):
        return "2.16.840.1.101.3.4.1.2"
    return "unknown"

def _cert_in_enrichment(category: str, algorithm: str, status: str) -> dict:
    primitive_map = {
        "key_exchange": "KEM / Key Establishment",
        "authentication": "Digital Signature / Identity",
        "tls_version": "Protocol Version",
        "certificate": "Certificate Signature",
        "symmetric": "Bulk Symmetric Encryption",
    }
    status_upper = (status or "").upper()
    sec_level_map = {
        "SAFE": ">= 192-bit equivalent",
        "ACCEPTABLE": "128-bit baseline",
        "WARNING": "< 128-bit / transition",
        "CRITICAL": "< 112-bit / deprecated",
    }
    key_state_map = {
        "SAFE": "active-pqc",
        "ACCEPTABLE": "active-classical",
        "WARNING": "transition-required",
        "CRITICAL": "legacy-high-risk",
    }
    return {
        "algorithm_name": algorithm or "unknown",
        "primitive": primitive_map.get(category, "cryptographic-control"),
        "oid": _oid_for_algorithm(algorithm),
        "classical_security_level": sec_level_map.get(status_upper, "unknown"),
        "key_state": key_state_map.get(status_upper, "unknown"),
        "activation_date": datetime.now(timezone.utc).date().isoformat(),
        "cert_in_profile": "Annexure-A minimum mapping",
    }

def assemble_scan_payload(session: Session, scan_id: str) -> dict | None:
    scan = session.get(Scan, scan_id)
    if not scan:
        return None

    logs = session.execute(
        select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.id.asc())
    ).scalars().all()
    assets = session.execute(
        select(Asset).where(Asset.scan_id == scan_id).order_by(desc(Asset.risk_score))
    ).scalars().all()
    findings = session.execute(
        select(CryptoFinding).where(CryptoFinding.scan_id == scan_id)
    ).scalars().all()
    recs = session.execute(
        select(Recommendation).where(Recommendation.scan_id == scan_id)
    ).scalars().all()
    cbom = session.execute(
        select(CbomExport).where(CbomExport.scan_id == scan_id).order_by(desc(CbomExport.id))
    ).scalars().first()
    chain_blocks = session.execute(
        select(ChainBlock).where(ChainBlock.scan_id == scan_id).order_by(ChainBlock.block_index.asc())
    ).scalars().all()

    rec_map: dict[int, list[str]] = {}
    for r in recs:
        rec_map.setdefault(r.asset_id, []).append(r.text)

    finding_map: dict[int, dict[str, dict]] = {}
    for f in findings:
        finding_map.setdefault(f.asset_id, {})[f.category] = {
            "algorithm": f.algorithm,
            "status": f.status,
            "details": f.details,
        }

    packed_assets = []
    for a in assets:
        cat = finding_map.get(a.id, {})
        packed_assets.append(
            {
                "asset_id": a.id,
                "asset": a.hostname,
                "asset_type": a.asset_type,
                "tls": a.metadata_json.get("tls", {}) if a.metadata_json else {},
                "api": a.metadata_json.get("api", {}) if a.metadata_json else {},
                "key_exchange_status": cat.get("key_exchange", {}).get("status", "WARNING"),
                "auth_status": cat.get("authentication", {}).get("status", "WARNING"),
                "tls_status": cat.get("tls_version", {}).get("status", "WARNING"),
                "cert_algo_status": cat.get("certificate", {}).get("status", "WARNING"),
                "symmetric_status": cat.get("symmetric", {}).get("status", "WARNING"),
                "hndl_risk_score": a.risk_score,
                "label": a.label,
                "recommendations": rec_map.get(a.id, []),
            }
        )

    return {
        "scan_id": scan.scan_id,
        "domain": scan.domain,
        "deep_scan": scan.deep_scan,
        "status": scan.status,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "progress": scan.progress,
        "error": scan.error,
        "logs": [l.message for l in logs],
        "discovered_assets": [a.hostname for a in assets],
        "findings": packed_assets,
        "cbom": cbom.cbom_json if cbom else None,
        "chain_blocks": [
            {
                "block_index": b.block_index,
                "timestamp": b.timestamp.isoformat() if b.timestamp else None,
                "payload_hash": b.payload_hash,
                "prev_hash": b.prev_hash,
                "nonce": b.nonce,
                "difficulty": b.difficulty,
                "block_hash": b.block_hash,
                "algo_version": b.algo_version,
            }
            for b in chain_blocks
        ],
    }

def leaderboard_payload(session: Session) -> list[dict]:
    scans = session.execute(select(Scan).order_by(Scan.created_at.desc())).scalars().all()
    rows = []
    for s in scans:
        assets = session.execute(select(Asset).where(Asset.scan_id == s.scan_id)).scalars().all()
        if not assets:
            continue
        avg = round(sum(a.risk_score for a in assets) / len(assets), 2)
        rows.append(
            {
                "scan_id": s.scan_id,
                "domain": s.domain,
                "status": s.status,
                "average_hndl_risk": avg,
                "avg_score": avg,
                "assets": len(assets),
                "asset_count": len(assets),
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
        )
    rows.sort(key=lambda x: x["average_hndl_risk"], reverse=True)
    return rows

def _badge_status_from_score(score: float) -> str:
    if score > 80:
        return "CRITICAL"
    if score > 60:
        return "QUANTUM_SAFE"
    return "TRANSITIONING"

def scans_list_payload(session: Session) -> list[dict]:
    scans = session.execute(select(Scan).order_by(Scan.created_at.desc())).scalars().all()
    return [
        {
            "scan_id": s.scan_id,
            "domain": s.domain,
            "status": s.status,
            "progress": s.progress,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in scans
    ]

def scan_detail_payload(session: Session, scan_id: str) -> dict | None:
    scan = session.get(Scan, scan_id)
    if not scan:
        return None
    logs = session.execute(
        select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.id.asc())
    ).scalars().all()
    assets = session.execute(
        select(Asset).where(Asset.scan_id == scan_id).order_by(desc(Asset.risk_score))
    ).scalars().all()
    cbom = session.execute(
        select(CbomExport).where(CbomExport.scan_id == scan_id).order_by(desc(CbomExport.id))
    ).scalars().first()
    chain_blocks = session.execute(
        select(ChainBlock).where(ChainBlock.scan_id == scan_id).order_by(ChainBlock.block_index.asc())
    ).scalars().all()

    assets_payload = []
    for a in assets:
        meta = a.metadata_json or {}
        tls_meta = meta.get("tls", {})
        api_meta = meta.get("api", {})
        vpn_meta = meta.get("vpn_signals", {})
        flat_meta = {
            "hsts": bool(tls_meta.get("hsts_present")),
            "ocsp": bool(tls_meta.get("ocsp_stapling")),
            "jwt_alg": (api_meta.get("jwt_algorithms") or [None])[0],
            "vpn_exposed": bool(meta.get("vpn_exposed")),
        }
        assets_payload.append(
            {
                "id": a.id,
                "scan_id": a.scan_id,
                "hostname": a.hostname,
                "asset_type": a.asset_type,
                "tls_version": a.tls_version,
                "cipher_suite": a.cipher_suite,
                "risk_score": a.risk_score,
                "label": _badge_status_from_score(a.risk_score),
                "metadata_json": json.dumps(flat_meta),
                "vpn_signals": {
                    "udp_500": bool(vpn_meta.get("udp_500")),
                    "udp_4500": bool(vpn_meta.get("udp_4500")),
                    "sstp": bool(vpn_meta.get("sstp")),
                },
            }
        )

    return {
        "scan": {
            "scan_id": scan.scan_id,
            "domain": scan.domain,
            "status": scan.status,
            "progress": scan.progress,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error": scan.error,
        },
        "logs": [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "message": l.message,
            }
            for l in logs
        ],
        "assets": assets_payload,
        "cbom": cbom.cbom_json if cbom else None,
        "chain_blocks": [
            {
                "id": b.id,
                "block_index": b.block_index,
                "timestamp": b.timestamp.isoformat() if b.timestamp else None,
                "payload_hash": b.payload_hash,
                "prev_hash": b.prev_hash,
                "nonce": b.nonce,
                "difficulty": b.difficulty,
                "block_hash": b.block_hash,
                "algo_version": b.algo_version,
            }
            for b in chain_blocks
        ],
    }

def findings_payload(session: Session, scan_id: str) -> dict | None:
    scan = session.get(Scan, scan_id)
    if not scan:
        return None
    findings = session.execute(
        select(CryptoFinding).where(CryptoFinding.scan_id == scan_id).order_by(CryptoFinding.id.asc())
    ).scalars().all()
    recommendations = session.execute(
        select(Recommendation).where(Recommendation.scan_id == scan_id).order_by(Recommendation.id.asc())
    ).scalars().all()
    return {
        "scan_id": scan_id,
        "findings": [
            ({
                "id": f.id,
                "asset_id": f.asset_id,
                "category": f.category,
                "algorithm": f.algorithm,
                "status": f.status,
                "details": f.details,
            } | _cert_in_enrichment(f.category, f.algorithm, f.status))
            for f in findings
        ],
        "recommendations": [
            {
                "id": r.id,
                "asset_id": r.asset_id,
                "phase": r.phase,
                "text": r.text,
            }
            for r in recommendations
        ],
    }
