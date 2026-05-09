"""
QuantHunt HNDL v2 Recalibration Engine

Recalculates HNDL scores using the web-enhanced v2 formula:
  HNDL_v2 = baseline × W_cipher
          + HarvestWindow_factor × W_harvest
          + ASN_risk_factor × W_infra
          + Exposure_breadth_factor × W_surface
          + CT_shadow_asset_factor × W_shadow

Critical rule: scores never drop below Stage 9 baseline.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("quanthunt.hndl_v2")


# ── HNDL v2 Weights ──────────────────────────────────────
@dataclass(frozen=True)
class HNDLv2Weights:
    W_cipher: float = 0.35
    W_harvest: float = 0.25
    W_infra: float = 0.20
    W_surface: float = 0.12
    W_shadow: float = 0.08

    def validate(self) -> bool:
        return abs(sum([self.W_cipher, self.W_harvest, self.W_infra, self.W_surface, self.W_shadow]) - 1.0) < 0.001


# ── Per-Asset Output ──────────────────────────────────────
@dataclass
class AssetHNDLv2:
    """Per-asset HNDL v2 recalibrated output."""
    asset_url: str
    hndl_baseline: float = 0.0
    hndl_v2_score: float = 0.0
    delta: float = 0.0
    score_drivers: List[str] = field(default_factory=list)
    quantum_migration_urgency: str = "MEDIUM"
    recommended_pqc_action: str = "scheduled_audit"
    cbom_component_ref: str = ""

    # Factor breakdown
    cipher_factor: float = 0.0
    harvest_factor: float = 0.0
    infra_factor: float = 0.0
    surface_factor: float = 0.0
    shadow_factor: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_url": self.asset_url,
            "hndl_baseline": round(self.hndl_baseline, 2),
            "hndl_v2_score": round(self.hndl_v2_score, 2),
            "delta": round(self.delta, 2),
            "score_drivers": self.score_drivers,
            "quantum_migration_urgency": self.quantum_migration_urgency,
            "recommended_pqc_action": self.recommended_pqc_action,
            "cbom_component_ref": self.cbom_component_ref,
            "factor_breakdown": {
                "cipher": round(self.cipher_factor, 4),
                "harvest_window": round(self.harvest_factor, 4),
                "infrastructure": round(self.infra_factor, 4),
                "exposure_surface": round(self.surface_factor, 4),
                "shadow_assets": round(self.shadow_factor, 4),
            },
        }


# ── Domain Summary ────────────────────────────────────────
@dataclass
class DomainHNDLSummary:
    """Domain-level HNDL v2 summary for frontend."""
    domain: str = ""
    total_assets_scanned_baseline: int = 0
    total_assets_discovered_web: int = 0
    net_new_asset_count: int = 0
    domain_hndl_baseline_avg: float = 0.0
    domain_hndl_v2_avg: float = 0.0
    domain_hndl_delta: float = 0.0
    highest_risk_asset: str = ""
    critical_assets_count: int = 0
    estimated_harvest_exposure_years: float = 0.0
    antigravity_confidence_score: float = 0.0
    # Per-asset breakdown
    asset_scores: List[AssetHNDLv2] = field(default_factory=list)
    # Distribution
    score_distribution: Dict[str, int] = field(default_factory=dict)
    # Weight config
    weights: HNDLv2Weights = field(default_factory=HNDLv2Weights)

    def to_frontend_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "total_assets_scanned_baseline": self.total_assets_scanned_baseline,
            "total_assets_discovered_web": self.total_assets_discovered_web,
            "net_new_asset_count": self.net_new_asset_count,
            "domain_hndl_baseline_avg": round(self.domain_hndl_baseline_avg, 2),
            "domain_hndl_v2_avg": round(self.domain_hndl_v2_avg, 2),
            "domain_hndl_delta": round(self.domain_hndl_delta, 2),
            "highest_risk_asset": self.highest_risk_asset,
            "critical_assets_count": self.critical_assets_count,
            "estimated_harvest_exposure_years": round(self.estimated_harvest_exposure_years, 2),
            "antigravity_confidence_score": round(self.antigravity_confidence_score, 4),
            "asset_scores": [a.to_dict() for a in self.asset_scores],
            "score_distribution": self.score_distribution,
            "weights": {
                "W_cipher": self.weights.W_cipher,
                "W_harvest": self.weights.W_harvest,
                "W_infra": self.weights.W_infra,
                "W_surface": self.weights.W_surface,
                "W_shadow": self.weights.W_shadow,
            },
        }


# ── Factor Computation ────────────────────────────────────
def harvest_window_factor(first_seen_date: str | None) -> float:
    """
    HarvestWindow_factor from Google first-index date.
    >5yr=1.0, >2yr=0.8, >1yr=0.6, >90d=0.4, else=0.2
    """
    if not first_seen_date:
        return 0.2
    try:
        if "T" in first_seen_date:
            dt = datetime.fromisoformat(first_seen_date.replace("Z", "+00:00"))
        else:
            dt = datetime.strptime(first_seen_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - dt).days
    except Exception:
        return 0.2

    if days > 1825:
        return 1.0
    if days > 730:
        return 0.8
    if days > 365:
        return 0.6
    if days > 90:
        return 0.4
    return 0.2


def asn_risk_factor(hosting_provider: str, is_banking_domain: bool = False) -> float:
    """
    ASN_risk_factor: national critical=1.0, major cloud=0.7, CDN=0.5, unknown=0.4.
    Indian banking domains get +0.1 RBI PQC mandate bonus.
    """
    upper = (hosting_provider or "").upper()
    critical = ("NIC INDIA", "BSNL", "SBI", "RBI", "NPCI", "NICSI", "IRCTC")
    major = ("AWS", "AMAZON", "GOOGLE", "GCP", "AZURE", "MICROSOFT", "CLOUDFLARE")
    cdn = ("AKAMAI", "FASTLY", "LIMELIGHT", "STACKPATH")

    base = 0.4
    if any(k in upper for k in critical):
        base = 1.0
    elif any(k in upper for k in major):
        base = 0.7
    elif any(k in upper for k in cdn):
        base = 0.5

    if is_banking_domain:
        base = min(1.0, base + 0.1)
    return base


def exposure_breadth_factor(new_assets: int, total_assets: int) -> float:
    """Ratio of newly discovered shadow assets to total."""
    if total_assets <= 0:
        return 0.0
    return min(1.0, new_assets / max(total_assets, 1))


def ct_shadow_factor(ct_subdomains_not_in_scan: int, criticality_weight: float = 0.5) -> float:
    """CT log subdomains not in original scan × criticality."""
    return min(1.0, ct_subdomains_not_in_scan * criticality_weight * 0.1)


def _urgency_label(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _pqc_action(score: float) -> str:
    if score >= 80:
        return "immediate_kyber_migration"
    if score >= 60:
        return "scheduled_audit"
    return "monitor"


def _is_banking(domain: str) -> bool:
    d = (domain or "").lower()
    return d.endswith(".bank.in") or ".bank." in d or any(
        b in d for b in ("sbi", "pnb", "hdfc", "icici", "axis", "kotak", "bob", "canara", "union", "rbi")
    )


# ── Main Recalibration Engine ─────────────────────────────
class HNDLv2RecalibrationEngine:
    """
    Recalculates HNDL scores with the v2 web-enhanced formula.
    Critical rule: v2 score NEVER drops below Stage 9 baseline.
    """

    def __init__(self, weights: HNDLv2Weights | None = None) -> None:
        self.weights = weights or HNDLv2Weights()
        if not self.weights.validate():
            raise ValueError("HNDL v2 weights must sum to 1.0")

    def recalibrate_asset(
        self,
        asset_url: str,
        baseline_score: float,
        first_seen_date: str | None = None,
        hosting_provider: str = "",
        new_asset_count: int = 0,
        total_asset_count: int = 1,
        ct_shadow_count: int = 0,
        domain: str = "",
        stale_cache: bool = False,
    ) -> AssetHNDLv2:
        """Recalibrate a single asset's HNDL score."""
        W = self.weights
        banking = _is_banking(domain)

        # Normalize baseline to 0-100 scale
        cipher_norm = min(100.0, max(0.0, baseline_score))

        # Compute each factor
        hw = harvest_window_factor(first_seen_date)
        ar = asn_risk_factor(hosting_provider, is_banking_domain=banking)
        eb = exposure_breadth_factor(new_asset_count, total_asset_count)
        cs = ct_shadow_factor(ct_shadow_count)

        # v2 score computation
        raw_v2 = (
            cipher_norm * W.W_cipher
            + (hw * 100) * W.W_harvest
            + (ar * 100) * W.W_infra
            + (eb * 100) * W.W_surface
            + (cs * 100) * W.W_shadow
        )

        # Apply stale cache confidence multiplier
        if stale_cache:
            raw_v2 *= 0.85

        # CRITICAL RULE: never lower below baseline
        v2_score = max(baseline_score, min(100.0, raw_v2))

        # Score drivers
        drivers: List[str] = []
        if hw >= 0.6:
            drivers.append("harvest_window_high")
        if ar >= 0.9:
            drivers.append("asn_critical_infra")
        elif ar >= 0.7:
            drivers.append("asn_major_cloud")
        if eb >= 0.3:
            drivers.append("high_exposure_breadth")
        if cs >= 0.3:
            drivers.append("shadow_subdomain_ct")
        if banking:
            drivers.append("rbi_pqc_mandate_exposure")
        if stale_cache:
            drivers.append("stale_cache_discount")

        result = AssetHNDLv2(
            asset_url=asset_url,
            hndl_baseline=baseline_score,
            hndl_v2_score=round(v2_score, 2),
            delta=round(v2_score - baseline_score, 2),
            score_drivers=drivers,
            quantum_migration_urgency=_urgency_label(v2_score),
            recommended_pqc_action=_pqc_action(v2_score),
            cbom_component_ref=f"bom-ref:quanthunt:{asset_url.replace('https://', '').replace('/', '-')}",
            cipher_factor=round(cipher_norm * W.W_cipher, 4),
            harvest_factor=round((hw * 100) * W.W_harvest, 4),
            infra_factor=round((ar * 100) * W.W_infra, 4),
            surface_factor=round((eb * 100) * W.W_surface, 4),
            shadow_factor=round((cs * 100) * W.W_shadow, 4),
        )
        return result

    def recalibrate_domain(
        self,
        domain: str,
        baseline_assets: List[Dict[str, Any]],
        antigravity_report: Any | None = None,
    ) -> DomainHNDLSummary:
        """
        Recalibrate all assets for a domain.

        baseline_assets: list of {"asset": str, "hndl_risk_score": float, ...}
        antigravity_report: AntigravityReport or dict from Stage 10-11
        """
        summary = DomainHNDLSummary(domain=domain, weights=self.weights)
        summary.total_assets_scanned_baseline = len(baseline_assets)

        # Extract antigravity data
        new_assets_count = 0
        ct_shadow_count = 0
        hosting_provider = ""
        discovered_assets_map: Dict[str, Dict] = {}

        if antigravity_report is not None:
            if hasattr(antigravity_report, "discovered_assets"):
                new_assets_count = len(antigravity_report.discovered_assets)
                for da in antigravity_report.discovered_assets:
                    discovered_assets_map[da.hostname] = {
                        "first_seen_date": da.first_seen_date,
                        "hosting_provider": da.hosting_provider,
                    }
                if antigravity_report.cloud_provider:
                    hosting_provider = antigravity_report.cloud_provider
                ct_shadow_count = len(antigravity_report.discovered_subdomains)
            elif isinstance(antigravity_report, dict):
                da_list = antigravity_report.get("discovered_assets", [])
                new_assets_count = len(da_list)
                for da in da_list:
                    hostname = da.get("hostname", "")
                    discovered_assets_map[hostname] = {
                        "first_seen_date": da.get("first_seen_date", ""),
                        "hosting_provider": da.get("hosting_provider", ""),
                    }
                hosting_provider = antigravity_report.get("infrastructure", {}).get("cloud_provider", "")
                ct_shadow_count = len(antigravity_report.get("discovered_subdomains", []))

        summary.total_assets_discovered_web = new_assets_count
        summary.net_new_asset_count = new_assets_count
        total_combined = summary.total_assets_scanned_baseline + new_assets_count

        # Recalibrate each baseline asset
        baseline_scores = []
        v2_scores = []
        max_harvest_days = 0

        for asset_data in baseline_assets:
            asset_url = asset_data.get("asset", "")
            baseline = float(asset_data.get("hndl_risk_score", 0))
            baseline_scores.append(baseline)

            # Check if antigravity has data for this asset
            hostname = asset_url.lower().strip()
            extra = discovered_assets_map.get(hostname, {})

            result = self.recalibrate_asset(
                asset_url=f"https://{asset_url}" if not asset_url.startswith("http") else asset_url,
                baseline_score=baseline,
                first_seen_date=extra.get("first_seen_date"),
                hosting_provider=extra.get("hosting_provider") or hosting_provider,
                new_asset_count=new_assets_count,
                total_asset_count=total_combined,
                ct_shadow_count=ct_shadow_count,
                domain=domain,
            )
            summary.asset_scores.append(result)
            v2_scores.append(result.hndl_v2_score)

        # Domain-level aggregation
        if baseline_scores:
            summary.domain_hndl_baseline_avg = sum(baseline_scores) / len(baseline_scores)
        if v2_scores:
            summary.domain_hndl_v2_avg = sum(v2_scores) / len(v2_scores)
        summary.domain_hndl_delta = summary.domain_hndl_v2_avg - summary.domain_hndl_baseline_avg

        # Highest risk asset
        if summary.asset_scores:
            highest = max(summary.asset_scores, key=lambda a: a.hndl_v2_score)
            summary.highest_risk_asset = highest.asset_url
            summary.critical_assets_count = sum(1 for a in summary.asset_scores if a.hndl_v2_score >= 80)

        # Harvest exposure estimate (max across assets)
        for a in summary.asset_scores:
            if a.harvest_factor > 0:
                days_est = a.harvest_factor / max(self.weights.W_harvest, 0.01)
                years = days_est / 365.0
                if years > summary.estimated_harvest_exposure_years:
                    summary.estimated_harvest_exposure_years = years

        # Distribution
        summary.score_distribution = {
            "safe_0_30": sum(1 for s in v2_scores if s <= 30),
            "hybrid_31_55": sum(1 for s in v2_scores if 30 < s <= 55),
            "vulnerable_56_75": sum(1 for s in v2_scores if 55 < s <= 75),
            "critical_76_100": sum(1 for s in v2_scores if s > 75),
        }

        # Confidence: log saturation based on data completeness
        total_signals = len(baseline_assets) + new_assets_count + ct_shadow_count
        summary.antigravity_confidence_score = round(
            min(1.0, 0.3 + 0.7 * (1.0 - math.exp(-total_signals / 50.0))), 4
        )

        logger.info(
            f"[HNDL-v2] {domain}: baseline_avg={summary.domain_hndl_baseline_avg:.2f} → "
            f"v2_avg={summary.domain_hndl_v2_avg:.2f} (Δ={summary.domain_hndl_delta:+.2f}), "
            f"critical={summary.critical_assets_count}, confidence={summary.antigravity_confidence_score}"
        )
        return summary
