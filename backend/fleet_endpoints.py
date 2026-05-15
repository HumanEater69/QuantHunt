"""
Batch Fleet Scanning and Reporting Endpoints

Provides:
- Fleet batch scanning (concurrent domain scans)
- Certificate export (CSV, JSON, PEM formats)
- Report downloads (PDF, HTML, JSON, CSV formats)
- Batch status tracking
"""

import asyncio
import csv
import json
from datetime import datetime
from io import StringIO, BytesIO
from typing import Any
from uuid import uuid4

from fastapi import HTTPException, Query
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy import desc, select

from .db import get_session
from .models import (
    FleetScanBatchRequest,
    FleetScanStatus,
    FleetScanBatchStatus,
    CertificateExportRequest,
    ReportDownloadRequest,
)
from .tables import Scan, Asset
from .crud import create_scan_record, get_scan


# Global batch tracking (in production, use Redis/database)
_FLEET_BATCHES: dict[str, FleetScanBatchStatus] = {}


async def batch_fleet_scan(req: FleetScanBatchRequest) -> dict[str, str]:
    """
    Initiate a batch scan of multiple domains concurrently.
    Returns batch_id for tracking progress.
    """
    batch_id = str(uuid4())
    batch_status = FleetScanBatchStatus(
        batch_id=batch_id,
        total_domains=len(req.domains),
        status="running",
    )
    _FLEET_BATCHES[batch_id] = batch_status

    # Spawn async tasks for each domain
    async def scan_domain(domain: str, idx: int):
        try:
            with get_session() as session:
                scan = create_scan_record(
                    session,
                    domain,
                    deep_scan=req.deep_scan,
                )
                domain_status = FleetScanStatus(
                    domain=domain,
                    scan_id=scan.scan_id,
                    status="running",
                )
                batch_status.scans.append(domain_status)

                # Trigger scan (simplified - in production use task queue)
                from .backend.scanner.pipeline import run_scan_pipeline
                await asyncio.to_thread(
                    run_scan_pipeline,
                    scan.scan_id,
                    domain,
                    req.scan_model,
                    req.dns_resolvers,
                    [],
                    None,
                )

                # Update status
                domain_status.status = "completed"
                domain_status.progress = 100

                # Count findings
                assets = session.execute(
                    select(Asset).where(Asset.scan_id == scan.scan_id)
                ).scalars().all()
                domain_status.discovered_assets_count = len(assets)
                domain_status.critical_findings = sum(
                    1 for a in assets
                    if "critical" in str(a.label or "").lower()
                )
                batch_status.completed += 1

        except Exception as e:
            domain_status = FleetScanStatus(
                domain=domain,
                status="failed",
                error=str(e),
            )
            batch_status.scans.append(domain_status)
            batch_status.failed += 1

    # Concurrency limiter
    sem = asyncio.Semaphore(req.concurrent_scans)

    async def bounded_scan(domain: str, idx: int):
        async with sem:
            await scan_domain(domain, idx)

    # Launch all scans
    tasks = [
        bounded_scan(domain, idx)
        for idx, domain in enumerate(req.domains)
    ]
    asyncio.create_task(asyncio.gather(*tasks))

    return {
        "batch_id": batch_id,
        "total_domains": len(req.domains),
        "status": "running",
    }


async def get_fleet_batch_status(batch_id: str) -> FleetScanBatchStatus:
    """Get current status of a fleet batch scan."""
    batch = _FLEET_BATCHES.get(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    return batch


def export_certificates_csv(req: CertificateExportRequest) -> str:
    """Export certificates in CSV format."""
    output = StringIO()
    writer = csv.writer(output)

    # Headers
    writer.writerow([
        "Domain",
        "Host",
        "Port",
        "Subject",
        "Issuer",
        "NotBefore",
        "NotAfter",
        "SignatureAlgo",
        "KeyBits",
        "KeyExchange",
        "TLSVersion",
        "CipherSuite",
    ])

    scan_ids = req.scan_ids or []
    with get_session() as session:
        for scan_id in scan_ids:
            scan = get_scan(session, scan_id)
            if not scan:
                continue

            assets = session.execute(
                select(Asset).where(Asset.scan_id == scan_id)
            ).scalars().all()

            for asset in assets:
                if not asset.tls_data:
                    continue

                tls = asset.tls_data
                writer.writerow([
                    scan.domain,
                    tls.get("host"),
                    tls.get("port", 443),
                    tls.get("cert_subject", ""),
                    tls.get("cert_issuer", ""),
                    tls.get("cert_not_before", ""),
                    tls.get("cert_not_after", ""),
                    tls.get("cert_sig_algo", ""),
                    tls.get("cert_public_key_bits", ""),
                    tls.get("key_exchange_algorithm", ""),
                    tls.get("tls_version", ""),
                    tls.get("cipher_suite", ""),
                ])

    return output.getvalue()


def export_certificates_json(req: CertificateExportRequest) -> str:
    """Export certificates in JSON format."""
    result = {"certificates": []}
    scan_ids = req.scan_ids or []

    with get_session() as session:
        for scan_id in scan_ids:
            scan = get_scan(session, scan_id)
            if not scan:
                continue

            assets = session.execute(
                select(Asset).where(Asset.scan_id == scan_id)
            ).scalars().all()

            for asset in assets:
                if not asset.tls_data:
                    continue

                cert_entry = {
                    "domain": scan.domain,
                    "asset": asset.asset,
                    "tls": asset.tls_data,
                }
                result["certificates"].append(cert_entry)

    return json.dumps(result, indent=2)


async def export_certificates(req: CertificateExportRequest) -> StreamingResponse:
    """Export certificates in requested format."""
    if req.format == "csv":
        content = export_certificates_csv(req)
        media_type = "text/csv"
        filename = "certificates.csv"
    elif req.format == "json":
        content = export_certificates_json(req)
        media_type = "application/json"
        filename = "certificates.json"
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {req.format}",
        )

    return StreamingResponse(
        iter([content]),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


async def download_reports(req: ReportDownloadRequest) -> StreamingResponse:
    """Download scan reports in requested format."""
    scan_ids = req.scan_ids or []

    if req.format == "json":
        reports = []
        with get_session() as session:
            for scan_id in scan_ids:
                scan_rec = get_scan(session, scan_id)
                if not scan_rec:
                    continue

                scan_data = {
                    "scan_id": scan_rec.scan_id,
                    "domain": scan_rec.domain,
                    "status": scan_rec.status,
                    "progress": scan_rec.progress,
                    "created_at": scan_rec.created_at.isoformat() if scan_rec.created_at else None,
                    "completed_at": scan_rec.completed_at.isoformat() if scan_rec.completed_at else None,
                }

                if req.include_findings:
                    assets = session.execute(
                        select(Asset).where(Asset.scan_id == scan_id)
                    ).scalars().all()
                    scan_data["findings"] = [
                        {
                            "asset": a.asset,
                            "label": a.label,
                            "hndl_score": a.hndl_risk_score,
                            "tls_data": a.tls_data,
                        }
                        for a in assets
                    ]

                reports.append(scan_data)

        content = json.dumps({"reports": reports}, indent=2)
        media_type = "application/json"
        filename = f"reports_{datetime.now().isoformat()}.json"

    elif req.format == "csv":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ScanID",
            "Domain",
            "Status",
            "Progress",
            "Asset",
            "Label",
            "HNDLScore",
            "CreatedAt",
        ])

        with get_session() as session:
            for scan_id in scan_ids:
                scan_rec = get_scan(session, scan_id)
                if not scan_rec:
                    continue

                assets = session.execute(
                    select(Asset).where(Asset.scan_id == scan_id)
                ).scalars().all()

                for asset in assets:
                    writer.writerow([
                        scan_rec.scan_id,
                        scan_rec.domain,
                        scan_rec.status,
                        scan_rec.progress,
                        asset.asset,
                        asset.label,
                        asset.hndl_risk_score,
                        scan_rec.created_at.isoformat() if scan_rec.created_at else "",
                    ])

        content = output.getvalue()
        media_type = "text/csv"
        filename = f"reports_{datetime.now().isoformat()}.csv"

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {req.format}. Supported: json, csv, pdf, html",
        )

    return StreamingResponse(
        iter([content]),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
