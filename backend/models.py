from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class ScanRequest(BaseModel):
    domain: str
    deep_scan: bool = True
    scan_model: Literal["general", "banking"] = "general"

class BatchScanRequest(BaseModel):
    domains: list[str]
    deep_scan: bool = True
    scan_model: Literal["general", "banking"] = "general"

class BatchProgressScanRef(BaseModel):
    scan_id: str
    scan_model: Literal["general", "banking"] = "general"
    domain: str | None = None

class BatchProgressRequest(BaseModel):
    scans: list[BatchProgressScanRef]

class QuantHuntChatRequest(BaseModel):
    message: str
    context: str | None = None
    mode: Literal["auto", "offline", "online"] = "auto"
    focus: Literal["general", "analysis", "prediction", "solutions"] = "general"
    scan_model: Literal["general", "banking"] = "general"

class PdfGenerateRequest(BaseModel):
    scan_id: str | None = None
    domain: str | None = None
    kind: Literal["report", "certificate"] = "report"

class PqcSimRequest(BaseModel):
    domain: str | None = None
    rtt_ms: float | None = None
    loss_rate: float = 0.01
    profile: Literal["classical", "hybrid"] = "hybrid"
    endpoint_category: str = "Core Web"
    current_cipher_suite: str = "TLS_AES_128_GCM_SHA256"
    baseline_ttfb_ms: float | None = None

class PqcFleetExportRequest(BaseModel):
    domains: list[str]
    loss_rate: float = 0.012
    baseline_ttfb_ms: float | None = None

class NetworkHintsRequest(BaseModel):
    connection_type: str | None = None
    effective_type: str | None = None
    downlink_mbps: float | None = None
    rtt_ms: float | None = None
    vpn_hint: bool | None = None

class TLSInfo(BaseModel):
    host: str
    port: int = 443
    tls_version: str | None = None
    cipher_suite: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    cert_sig_algo: str | None = None
    accepted_ciphers: list[str] = Field(default_factory=list)
    supported_cipher_suites: list[str] = Field(default_factory=list)
    cipher_components: dict[str, Any] = Field(default_factory=dict)
    cipher_metadata: dict[str, Any] = Field(default_factory=dict)
    supported_cipher_analysis: list[dict[str, Any]] = Field(default_factory=list)
    hsts_present: bool = False
    ocsp_stapling: bool = False
    scan_error: str | None = None

class APIInfo(BaseModel):
    host: str
    api_ports_open: list[int] = Field(default_factory=list)
    jwt_algorithms: list[str] = Field(default_factory=list)
    security_headers: dict[str, str] = Field(default_factory=dict)
    framework_hints: dict[str, str] = Field(default_factory=dict)

class AssetFinding(BaseModel):
    asset: str
    tls: TLSInfo
    api: APIInfo
    key_exchange_status: Literal["CRITICAL", "WARNING", "ACCEPTABLE", "SAFE"]
    auth_status: Literal["CRITICAL", "WARNING", "ACCEPTABLE", "SAFE"]
    tls_status: Literal["CRITICAL", "WARNING", "ACCEPTABLE", "SAFE"]
    cert_algo_status: Literal["CRITICAL", "WARNING", "ACCEPTABLE", "SAFE"]
    symmetric_status: Literal["CRITICAL", "WARNING", "ACCEPTABLE", "SAFE"]
    hndl_risk_score: float
    label: str
    recommendations: list[str]

class ScanState(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    domain: str
    deep_scan: bool = True
    status: Literal["queued", "running", "completed", "failed"] = "queued"
    created_at: str = Field(default_factory=now_iso)
    completed_at: str | None = None
    progress: int = 0
    logs: list[str] = Field(default_factory=list)
    discovered_assets: list[str] = Field(default_factory=list)
    findings: list[AssetFinding] = Field(default_factory=list)
    cbom: dict[str, Any] | None = None
    error: str | None = None
