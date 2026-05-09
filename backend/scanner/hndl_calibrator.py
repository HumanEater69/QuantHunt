"""
Module 3: HNDL Score Calibration Engine (The Brain)

Recalculates the HNDL (Handling/Posture) risk score by fusing:
  - Base per-asset HNDL scores (from pqc_engine.py)
  - Search intelligence penalties (Module 1: exposed configs, dev servers, leaked creds)
  - Infrastructure rewards (Module 2: modern TLS/PQC adoption across ASN block)

The calibrated score is the definitive enterprise-grade PQC posture metric.

Usage:
    calibrator = HNDLCalibrationEngine()
    result = calibrator.calibrate(
        base_scores=[38.18, 42.5, ...],
        search_report=search_intel_report,
        infra_report=infra_report,
    )
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("quanthunt.hndl_calibrator")


# ---------------------------------------------------------------------------
# HNDL Weighting Configuration
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class HNDLWeights:
    """
    Immutable weight configuration for HNDL score components.
    Must sum to 1.0 for the base components.
    """
    # --- Base score components (from pqc_engine.py) ---
    key_exchange: float = 0.50
    key_size: float = 0.20
    cert_validity: float = 0.15
    tls_protocol: float = 0.15

    # --- Intelligence overlay weights ---
    # These are additive penalty/reward modifiers, not base weights
    env_file_penalty_per_finding: float = 8.0
    env_file_penalty_cap: float = 40.0
    dev_server_penalty_per_finding: float = 5.0
    dev_server_penalty_cap: float = 30.0
    leaked_cred_penalty_per_finding: float = 12.0
    leaked_cred_penalty_cap: float = 48.0
    infrastructure_reward_max: float = -20.0

    def validate(self) -> bool:
        base_sum = self.key_exchange + self.key_size + self.cert_validity + self.tls_protocol
        return abs(base_sum - 1.0) < 0.001


# ---------------------------------------------------------------------------
# Intelligence adjustment data
# ---------------------------------------------------------------------------
@dataclass
class IntelligenceAdjustment:
    """Penalty/reward adjustments from search and infrastructure intelligence."""
    # Search engine penalties
    env_file_count: int = 0
    dev_server_count: int = 0
    leaked_cred_count: int = 0
    env_penalty: float = 0.0
    dev_penalty: float = 0.0
    cred_penalty: float = 0.0
    total_search_penalty: float = 0.0

    # Infrastructure rewards
    modern_tls_ratio: float = 0.0
    pqc_detected_count: int = 0
    infra_reward: float = 0.0

    # Net adjustment
    net_adjustment: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "env_file_count": self.env_file_count,
            "dev_server_count": self.dev_server_count,
            "leaked_cred_count": self.leaked_cred_count,
            "env_penalty": round(self.env_penalty, 2),
            "dev_penalty": round(self.dev_penalty, 2),
            "cred_penalty": round(self.cred_penalty, 2),
            "total_search_penalty": round(self.total_search_penalty, 2),
            "modern_tls_ratio": round(self.modern_tls_ratio, 4),
            "pqc_detected_count": self.pqc_detected_count,
            "infra_reward": round(self.infra_reward, 2),
            "net_adjustment": round(self.net_adjustment, 2),
        }


# ---------------------------------------------------------------------------
# Calibration result
# ---------------------------------------------------------------------------
@dataclass
class HNDLCalibrationResult:
    """Complete calibrated HNDL posture output for the frontend."""
    target_domain: str = ""

    # --- Raw inputs ---
    base_scores: List[float] = field(default_factory=list)
    base_avg_hndl: float = 0.0
    asset_count: int = 0

    # --- Intelligence overlay ---
    adjustment: IntelligenceAdjustment = field(default_factory=IntelligenceAdjustment)

    # --- Calibrated output ---
    calibrated_avg_hndl: float = 0.0
    calibrated_per_asset: List[float] = field(default_factory=list)
    posture_label: str = ""
    confidence: float = 0.0

    # --- Distribution ---
    score_distribution: Dict[str, int] = field(default_factory=dict)
    percentile_75: float = 0.0
    percentile_95: float = 0.0

    # --- Discovery expansion metrics ---
    search_discovered_hosts: int = 0
    infra_discovered_hosts: int = 0
    total_expanded_hosts: int = 0

    def to_frontend_dict(self) -> Dict[str, Any]:
        """
        The exact shape passed to the React frontend.
        This is the contract between backend and frontend.
        """
        return {
            "target_domain": self.target_domain,
            "base_avg_hndl": round(self.base_avg_hndl, 2),
            "calibrated_avg_hndl": round(self.calibrated_avg_hndl, 2),
            "asset_count": self.asset_count,
            "posture_label": self.posture_label,
            "confidence": round(self.confidence, 4),
            "intelligence_adjustment": self.adjustment.to_dict(),
            "score_distribution": self.score_distribution,
            "percentile_75": round(self.percentile_75, 2),
            "percentile_95": round(self.percentile_95, 2),
            "discovery_expansion": {
                "search_discovered_hosts": self.search_discovered_hosts,
                "infra_discovered_hosts": self.infra_discovered_hosts,
                "total_expanded_hosts": self.total_expanded_hosts,
            },
            "calibrated_per_asset": [round(s, 2) for s in self.calibrated_per_asset],
            "weights_used": {
                "key_exchange": 0.50,
                "key_size": 0.20,
                "cert_validity": 0.15,
                "tls_protocol": 0.15,
            },
        }


# ---------------------------------------------------------------------------
# Main calibration engine
# ---------------------------------------------------------------------------
class HNDLCalibrationEngine:
    """
    Module 3 entry point.
    Fuses base HNDL scores with intelligence from Modules 1 & 2
    to produce a calibrated enterprise posture score.
    """

    def __init__(self, weights: HNDLWeights | None = None) -> None:
        self.weights = weights or HNDLWeights()
        if not self.weights.validate():
            raise ValueError("HNDL base weights must sum to 1.0")

    def _compute_search_penalty(
        self,
        search_report: Any | None,
    ) -> IntelligenceAdjustment:
        """Extract and cap search intelligence penalties."""
        adj = IntelligenceAdjustment()
        if search_report is None:
            return adj

        # Extract counts from SearchIntelReport or dict
        if hasattr(search_report, "exposed_env_files"):
            adj.env_file_count = len(search_report.exposed_env_files)
            adj.dev_server_count = len(search_report.exposed_dev_servers)
            adj.leaked_cred_count = len(search_report.exposed_certs_keys)
        elif isinstance(search_report, dict):
            adj.env_file_count = int(search_report.get("exposed_env_files", 0))
            adj.dev_server_count = int(search_report.get("exposed_dev_servers", 0))
            adj.leaked_cred_count = int(search_report.get("exposed_certs_keys", 0))

        # Apply capped penalties
        adj.env_penalty = min(
            self.weights.env_file_penalty_cap,
            adj.env_file_count * self.weights.env_file_penalty_per_finding,
        )
        adj.dev_penalty = min(
            self.weights.dev_server_penalty_cap,
            adj.dev_server_count * self.weights.dev_server_penalty_per_finding,
        )
        adj.cred_penalty = min(
            self.weights.leaked_cred_penalty_cap,
            adj.leaked_cred_count * self.weights.leaked_cred_penalty_per_finding,
        )
        adj.total_search_penalty = adj.env_penalty + adj.dev_penalty + adj.cred_penalty
        return adj

    def _compute_infra_reward(
        self,
        infra_report: Any | None,
        adjustment: IntelligenceAdjustment,
    ) -> IntelligenceAdjustment:
        """Compute infrastructure reward based on modern TLS adoption ratio."""
        if infra_report is None:
            return adjustment

        if hasattr(infra_report, "modern_tls_ratio"):
            adjustment.modern_tls_ratio = infra_report.modern_tls_ratio
            adjustment.pqc_detected_count = infra_report.pqc_detected_count
            adjustment.infra_reward = infra_report.infrastructure_reward
        elif isinstance(infra_report, dict):
            adjustment.modern_tls_ratio = float(infra_report.get("modern_tls_ratio", 0))
            adjustment.pqc_detected_count = int(infra_report.get("pqc_detected_count", 0))
            hndl_adj = infra_report.get("hndl_adjustment", {})
            adjustment.infra_reward = float(hndl_adj.get("infrastructure_reward", 0))

        adjustment.net_adjustment = adjustment.total_search_penalty + adjustment.infra_reward
        return adjustment

    @staticmethod
    def _percentile(scores: List[float], p: float) -> float:
        """Compute the p-th percentile of a sorted list."""
        if not scores:
            return 0.0
        sorted_scores = sorted(scores)
        k = (len(sorted_scores) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_scores[int(k)]
        return sorted_scores[f] * (c - k) + sorted_scores[c] * (k - f)

    @staticmethod
    def _posture_label(score: float) -> str:
        """Classify calibrated score into posture label."""
        if score <= 30:
            return "Quantum-Safe (NIST Compliant)"
        if score <= 55:
            return "Quantum-Resilient (Hybrid)"
        if score <= 75:
            return "Quantum-Vulnerable (HNDL Risk)"
        return "Critical HNDL Exposure"

    @staticmethod
    def _confidence(asset_count: int, search_count: int, infra_count: int) -> float:
        """
        Confidence score: how much data backs the calibrated score.
        More sources → higher confidence, asymptotically approaching 1.0.
        """
        total_signals = asset_count + search_count + infra_count
        if total_signals == 0:
            return 0.0
        # Logarithmic saturation: diminishing returns after ~100 signals
        return round(min(1.0, 0.3 + 0.7 * (1.0 - math.exp(-total_signals / 50.0))), 4)

    def calibrate(
        self,
        target_domain: str,
        base_scores: List[float],
        search_report: Any | None = None,
        infra_report: Any | None = None,
    ) -> HNDLCalibrationResult:
        """
        Fuse base HNDL scores with intelligence penalties/rewards.

        The calibration formula:
            calibrated_per_asset[i] = clamp(base_scores[i] + net_adjustment, 0, 100)
            calibrated_avg = mean(calibrated_per_asset)
        """
        result = HNDLCalibrationResult(target_domain=target_domain)
        result.base_scores = list(base_scores)
        result.asset_count = len(base_scores)
        result.base_avg_hndl = (
            sum(base_scores) / max(len(base_scores), 1) if base_scores else 0.0
        )

        # Step 1: Compute search penalties
        adjustment = self._compute_search_penalty(search_report)

        # Step 2: Compute infrastructure rewards
        adjustment = self._compute_infra_reward(infra_report, adjustment)
        result.adjustment = adjustment

        # Step 3: Apply calibration to each asset score
        net = adjustment.net_adjustment
        calibrated = [
            round(min(100.0, max(0.0, score + net)), 2)
            for score in base_scores
        ]
        result.calibrated_per_asset = calibrated
        result.calibrated_avg_hndl = (
            sum(calibrated) / max(len(calibrated), 1) if calibrated else 0.0
        )

        # Step 4: Posture classification
        result.posture_label = self._posture_label(result.calibrated_avg_hndl)

        # Step 5: Distribution stats
        result.percentile_75 = self._percentile(calibrated, 75)
        result.percentile_95 = self._percentile(calibrated, 95)
        result.score_distribution = {
            "safe_0_30": sum(1 for s in calibrated if s <= 30),
            "hybrid_31_55": sum(1 for s in calibrated if 30 < s <= 55),
            "vulnerable_56_75": sum(1 for s in calibrated if 55 < s <= 75),
            "critical_76_100": sum(1 for s in calibrated if s > 75),
        }

        # Step 6: Discovery expansion metrics
        if search_report is not None:
            if hasattr(search_report, "discovered_subdomains"):
                result.search_discovered_hosts = len(search_report.discovered_subdomains)
            elif isinstance(search_report, dict):
                result.search_discovered_hosts = len(search_report.get("discovered_subdomains", []))

        if infra_report is not None:
            if hasattr(infra_report, "discovered_hostnames"):
                result.infra_discovered_hosts = len(infra_report.discovered_hostnames)
            elif isinstance(infra_report, dict):
                result.infra_discovered_hosts = len(infra_report.get("discovered_hostnames", []))

        result.total_expanded_hosts = result.search_discovered_hosts + result.infra_discovered_hosts

        # Step 7: Confidence
        result.confidence = self._confidence(
            result.asset_count,
            result.search_discovered_hosts,
            result.infra_discovered_hosts,
        )

        logger.info(
            f"[HNDL-CALIBRATE] {target_domain}: "
            f"base_avg={result.base_avg_hndl:.2f} → calibrated_avg={result.calibrated_avg_hndl:.2f} "
            f"(net_adj={net:+.2f}, penalty={adjustment.total_search_penalty:+.2f}, "
            f"reward={adjustment.infra_reward:+.2f}, confidence={result.confidence:.2f})"
        )
        return result
