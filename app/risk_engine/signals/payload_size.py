"""Signal: abnormally large payloads may indicate abuse.

Reads ``payload_bytes`` from pre-computed features.
"""

from __future__ import annotations

from app.risk_engine.base_signal import BaseSignal
from app.risk_engine.models import SignalResult


class PayloadSizeSignal(BaseSignal):
    """Scores requests by payload size in bytes.

    Parameters
    ----------
    safe_bytes : int
        Payloads up to this size score 0 (default 1 KB).
    danger_bytes : int
        Payloads at or above this size score 1.0 (default 50 KB).
    weight : float
        Relative importance (default 0.5).
    """

    def __init__(
        self,
        safe_bytes: int = 1_024,
        danger_bytes: int = 50_000,
        weight: float = 0.5,
    ) -> None:
        self._safe = safe_bytes
        self._danger = danger_bytes
        self._weight = weight

    @property
    def name(self) -> str:
        return "payload_size"

    @property
    def weight(self) -> float:
        return self._weight

    def evaluate(self, ctx: dict) -> SignalResult:
        features = ctx["features"]
        size = features.payload_bytes

        if size <= self._safe:
            score = 0.0
        elif size >= self._danger:
            score = 1.0
        else:
            score = (size - self._safe) / (self._danger - self._safe)

        return SignalResult(
            name=self.name,
            score=score,
            weight=self._weight,
            detail=f"payload {size:,} bytes (safe<{self._safe:,}, danger>={self._danger:,})",
        )
