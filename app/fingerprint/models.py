"""Data models for behavioral fingerprinting."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FingerprintBaseline:
    """Running statistics for an IP's behavior.

    Uses Welford's algorithm parameters to maintain mean and variance
    without storing historical request data.
    """

    count: int = 0
    interval_count: int = 0  # To handle requests with no prior interval
    
    # Frequency (requests in window)
    mean_freq: float = 0.0
    m2_freq: float = 0.0
    
    # Interval (time between requests)
    mean_interval: float = 0.0
    m2_interval: float = 0.0

    @property
    def var_freq(self) -> float:
        return self.m2_freq / self.count if self.count > 0 else 0.0

    @property
    def var_interval(self) -> float:
        return self.m2_interval / self.interval_count if self.interval_count > 0 else 0.0


@dataclass(frozen=True, slots=True)
class FingerprintResult:
    """Output of :meth:`FingerprintEngine.update_and_get`."""

    ip: str
    deviation_score: float  # 0.0 (baseline) to 1.0+ (extreme deviation)
    baseline: FingerprintBaseline
    explanation: str

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "deviation_score": round(self.deviation_score, 4),
            "explanation": self.explanation,
            "baseline": {
                "count": self.baseline.count,
                "avg_freq": round(self.baseline.mean_freq, 2),
                "avg_interval": round(self.baseline.mean_interval, 4),
            },
        }
