"""Intelligent Decision Engine for SentinelAI.

Decouples from simple threshold-based scoring to provide a more
sophisticated and explainable risk-action matrix.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Tuple

from app.risk_engine.models import SignalResult


class BaseDecisionEngine(ABC):
    """Abstract interface for risk decision engines."""

    @abstractmethod
    def decide(self, agg_score: float, results: List[SignalResult]) -> Tuple[str, str]:
        """Determine action and provide reasoning.

        Returns
        -------
        (action, reasoning) : (str, str)
            Action is one of "allow", "throttle", "block".
        """


class HeuristicDecisionEngine(BaseDecisionEngine):
    """Rule-based decision matrix for combinatory risk evaluation.

    This engine inspects individual signal scores to detect specific
    threat combinations that a simple average might dilute.

    Parameters
    ----------
    throttle_threshold : float
        General threshold for throttles if no specific rule matches (default 0.3).
    block_threshold : float
        General threshold for blocks if no specific rule matches (default 0.7).
    """

    def __init__(
        self,
        throttle_threshold: float = 0.3,
        block_threshold: float = 0.7,
    ) -> None:
        self._throttle = throttle_threshold
        self._block = block_threshold

    def decide(self, agg_score: float, results: List[SignalResult]) -> Tuple[str, str]:
        # --- Extract key signals for easier rule matching ---
        # (Using .get since some signals might not be registered or fired)
        signal_map = {r.name: r.score for r in results}
        
        anomaly = signal_map.get("anomaly_detector", 0.0)
        deviation = signal_map.get("behavioral_fingerprint", 0.0)
        frequency = signal_map.get("ip_frequency", 0.0)

        # ------------------------------------------------------------------
        # CRITICAL BLOCK RULES
        # ------------------------------------------------------------------
        
        # Rule 1: Multi-Factor Threat (ML Anomaly + Personal Baseline Deviation)
        # Reason: High-confidence indicator of account takeover or specialized bot.
        if anomaly > 0.8 and deviation > 0.8:
            return "block", "Critical: High-confidence anomaly confirmed by behavioral deviation"

        # Rule 2: Force Block on Extreme Aggregated Risk
        if agg_score >= self._block:
            return "block", f"Security: Aggregated risk score {agg_score:.2f} exceeds safety threshold"

        # Rule 3: Extreme Burst (Hard Limit)
        if frequency > 0.95:
            return "block", "Abuse: Extreme request frequency detected (Hard Limit)"

        # ------------------------------------------------------------------
        # THROTTLE RULES
        # ------------------------------------------------------------------

        # Rule 4: Suspicious behavior (Medium ML confidence)
        if anomaly > 0.7:
            return "throttle", f"Warning: Infrastructure anomaly detected (score={anomaly:.2f})"

        # Rule 5: Personal behavior shift
        if deviation > 0.7:
            return "throttle", f"Warning: Current behavior deviates significantly from baseline (score={deviation:.2f})"

        # Rule 6: General Throttle Threshold
        if agg_score >= self._throttle:
            return "throttle", f"Caution: Elevated aggregated risk score {agg_score:.2f}"

        # ------------------------------------------------------------------
        # ALLOW
        # ------------------------------------------------------------------
        return "allow", "Traffic within normal parameters"
