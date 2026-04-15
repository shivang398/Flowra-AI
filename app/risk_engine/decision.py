"""Intelligent Decision Engine for FlowraAI.

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
        self._redis = None

    def set_redis(self, redis_client):
        """Configure redis client and hydrate existing tuned thresholds."""
        self._redis = redis_client
        self.load_from_storage()

    def load_from_storage(self):
        if self._redis:
            import redis
            try:
                t = self._redis.get("flowra:thresholds:throttle")
                b = self._redis.get("flowra:thresholds:block")
                if t: self._throttle = float(t)
                if b: self._block = float(b)
            except redis.RedisError:
                pass

    def adjust_thresholds(self, was_correct: bool, current_action: str) -> dict:
        """Simple adaptive threshold adjustments based on admin feedback."""
        lr = 0.05
        
        # False Positive: we blocked/throttled a safe user -> Threshold too low.
        if not was_correct and current_action in ["block", "throttle", "rate_limit"]:
            self._throttle = min(0.9, self._throttle + lr)
            self._block = min(0.95, self._block + lr)
            
        # False Negative: we allowed an attacker through -> Threshold too high.
        elif not was_correct and current_action == "allow":
            self._throttle = max(0.1, self._throttle - lr)
            self._block = max(0.2, self._block - lr)
            
        # Persist updated values across restarts
        if self._redis:
            import redis
            try:
                self._redis.set("flowra:thresholds:throttle", str(self._throttle))
                self._redis.set("flowra:thresholds:block", str(self._block))
            except redis.RedisError:
                pass
            
        return {"throttle_threshold": round(self._throttle, 3), "block_threshold": round(self._block, 3)}

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

        # Rule 6: Extreme Burst (Hard Limit)
        if frequency > 0.95:
            return "rate_limit", "Abuse: Extreme request frequency detected (Hard Limit)"

        # ------------------------------------------------------------------
        # THROTTLE RULES
        # ------------------------------------------------------------------

        # Rule 7: Suspicious behavior (Medium ML confidence)
        if anomaly > 0.7:
            return "throttle", f"Warning: Infrastructure anomaly detected (score={anomaly:.2f})"

        # Rule 8: Personal behavior shift
        if deviation > 0.7:
            return "throttle", f"Warning: Current behavior deviates significantly from baseline (score={deviation:.2f})"

        # Rule 9: General Throttle Threshold
        if agg_score >= self._throttle:
            return "throttle", f"Caution: Elevated aggregated risk score {agg_score:.2f}"

        # ------------------------------------------------------------------
        # ALLOW
        # ------------------------------------------------------------------
        return "allow", "Traffic within normal parameters"
