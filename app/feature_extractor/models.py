"""Data models for extracted behavioral features."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class BehaviorFeatures:
    """Snapshot of behavioral features extracted for a single request.

    This is the structured output of :meth:`FeatureExtractor.extract`.
    Signals and the risk engine consume this instead of computing raw
    metrics themselves.
    """

    ip: str
    timestamp: float

    # --- Extracted features ---
    request_frequency: int
    """Number of requests from this IP in the trailing window."""

    average_interval: float | None
    """Mean time (seconds) between consecutive requests, or None if < 2 requests."""

    interval_std_dev: float | None
    """Std-dev of inter-request intervals, or None if < 3 requests."""

    payload_bytes: int
    """Size of the current request payload in bytes."""

    window_sec: float
    """The sliding window length used for frequency / interval calculations."""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "timestamp": self.timestamp,
            "request_frequency": self.request_frequency,
            "average_interval": round(self.average_interval, 6) if self.average_interval is not None else None,
            "interval_std_dev": round(self.interval_std_dev, 6) if self.interval_std_dev is not None else None,
            "payload_bytes": self.payload_bytes,
            "window_sec": self.window_sec,
        }
