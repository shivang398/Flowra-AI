"""Risk signal backed by the Isolation Forest anomaly detector.

This bridges ``app.anomaly_detector`` → ``app.risk_engine`` so the ML
model participates in the weighted scoring pipeline alongside the
rule-based signals.
"""

from __future__ import annotations

from app.anomaly_detector.detector import AnomalyDetector
from app.risk_engine.base_signal import BaseSignal
from app.risk_engine.models import SignalResult


class AnomalySignal(BaseSignal):
    """Wraps :class:`AnomalyDetector` as a :class:`BaseSignal`.

    Parameters
    ----------
    detector : AnomalyDetector
        A trained detector instance.
    weight : float
        Relative importance in the risk aggregation (default 1.5).
    """

    def __init__(self, detector: AnomalyDetector, weight: float = 1.5) -> None:
        self._detector = detector
        self._weight = weight

    @property
    def name(self) -> str:
        return "anomaly_detector"

    @property
    def weight(self) -> float:
        return self._weight

    def evaluate(self, ctx: dict) -> SignalResult:
        features = ctx["features"]  # BehaviorFeatures from FeatureExtractor
        request_count = ctx.get("request_count", 100)
        result = self._detector.predict(features, request_count=request_count)

        return SignalResult(
            name=self.name,
            score=result.anomaly_score,
            weight=self._weight,
            detail=(
                f"anomaly_score={result.anomaly_score:.4f}, "
                f"is_anomalous={result.is_anomalous}, "
                f"raw={result.raw_score:.4f}"
            ),
        )
