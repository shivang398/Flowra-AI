"""Signal: request frequency per IP within a sliding window.

Now reads pre-computed features from :class:`FeatureExtractor` via
``ctx["features"]`` instead of maintaining its own timestamp log.
"""

from __future__ import annotations

from app.risk_engine.base_signal import BaseSignal
from app.risk_engine.models import SignalResult


class IPFrequencySignal(BaseSignal):
    """Scores risk based on request frequency from FeatureExtractor output.

    Parameters
    ----------
    low_threshold : int
        Request count below which risk is near-zero (default 5).
    high_threshold : int
        Request count at or above which risk saturates at 1.0 (default 20).
    weight : float
        Relative importance of this signal (default 1.0).
    """

    def __init__(
        self,
        low_threshold: int = 5,
        high_threshold: int = 20,
        weight: float = 1.0,
    ) -> None:
        self._low = low_threshold
        self._high = high_threshold
        self._weight = weight

    @property
    def name(self) -> str:
        return "ip_frequency"

    @property
    def weight(self) -> float:
        return self._weight

    def evaluate(self, ctx: dict) -> SignalResult:
        features = ctx["features"]  # BehaviorFeatures instance
        freq = features.request_frequency

        if freq <= self._low:
            score = 0.0
        elif freq >= self._high:
            score = 1.0
        else:
            score = (freq - self._low) / (self._high - self._low)

        return SignalResult(
            name=self.name,
            score=score,
            weight=self._weight,
            detail=f"{freq} requests in last {features.window_sec}s window",
        )
