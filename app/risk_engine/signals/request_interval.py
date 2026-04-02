"""Signal: suspiciously uniform request intervals (bot-like behaviour).

Reads pre-computed ``interval_std_dev`` from :class:`FeatureExtractor`
output instead of maintaining its own timestamp log.
"""

from __future__ import annotations

from app.risk_engine.base_signal import BaseSignal
from app.risk_engine.models import SignalResult


class RequestIntervalSignal(BaseSignal):
    """Detects bot-like behaviour using interval regularity.

    A human clicks at irregular intervals → high standard deviation.
    A bot or script fires at near-identical intervals → low std-dev.

    Parameters
    ----------
    suspicion_threshold : float
        Std-dev (in seconds) below which the traffic looks automated (default 0.5).
    weight : float
        Relative importance (default 0.8).
    """

    def __init__(
        self,
        suspicion_threshold: float = 0.5,
        weight: float = 0.8,
    ) -> None:
        self._threshold = suspicion_threshold
        self._weight = weight

    @property
    def name(self) -> str:
        return "request_interval"

    @property
    def weight(self) -> float:
        return self._weight

    def evaluate(self, ctx: dict) -> SignalResult:
        features = ctx["features"]
        std = features.interval_std_dev

        # Not enough data to judge
        if std is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                weight=self._weight,
                detail=f"not enough samples (need ≥3 requests, have {features.request_frequency})",
            )

        # Low std-dev → high risk (bot-like)
        if std >= self._threshold:
            score = 0.0
        else:
            score = 1.0 - (std / self._threshold)

        return SignalResult(
            name=self.name,
            score=score,
            weight=self._weight,
            detail=(
                f"interval std-dev={std:.4f}s "
                f"(threshold={self._threshold}s, avg_interval="
                f"{features.average_interval:.4f}s)"
            ),
        )
