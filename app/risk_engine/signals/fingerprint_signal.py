"""Risk signal identifying behavior that deviates from an IP's baseline.

This signal consumes the results from the Behavioral Fingerprinting layer.
"""

from __future__ import annotations

from app.fingerprint.models import FingerprintResult
from app.risk_engine.base_signal import BaseSignal
from app.risk_engine.models import SignalResult


class FingerprintSignal(BaseSignal):
    """Wraps :class:`FingerprintResult` as a :class:`BaseSignal`.

    Parameters
    ----------
    weight : float
        Relative importance of baseline deviation (default 1.2).
    """

    def __init__(self, weight: float = 1.2) -> None:
        self._weight = weight

    @property
    def name(self) -> str:
        return "behavioral_fingerprint"

    @property
    def weight(self) -> float:
        return self._weight

    def evaluate(self, ctx: dict) -> SignalResult:
        # fingerprint: FingerprintResult
        fingerprint = ctx.get("fingerprint")
        if fingerprint is None:
            return SignalResult(
                name=self.name,
                score=0.0,
                weight=self._weight,
                detail="No fingerprint data available",
            )

        return SignalResult(
            name=self.name,
            score=fingerprint.deviation_score,
            weight=self._weight,
            detail=fingerprint.explanation,
        )
