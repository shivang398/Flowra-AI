"""Data models for anomaly detection results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    """Output of :meth:`AnomalyDetector.predict`.

    Attributes
    ----------
    anomaly_score : float
        Normalised score in [0, 1].  Higher = more anomalous.
    is_anomalous : bool
        Hard decision based on the configured threshold.
    raw_score : float
        The raw Isolation Forest decision_function value (unbounded).
        Negative = anomaly in sklearn's convention.
    """

    anomaly_score: float
    is_anomalous: bool
    raw_score: float

    def to_dict(self) -> dict:
        return {
            "anomaly_score": round(self.anomaly_score, 4),
            "is_anomalous": self.is_anomalous,
            "raw_score": round(self.raw_score, 4),
        }
