"""Data models for anomaly detection results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    """Output of :meth:`AnomalyDetector.predict`."""

    anomaly_score: float
    confidence: float
    is_anomalous: bool
    raw_score: float

    def to_dict(self) -> dict:
        return {
            "anomaly_score": round(self.anomaly_score, 4),
            "confidence": round(self.confidence, 4),
            "is_anomalous": self.is_anomalous,
            "raw_score": round(self.raw_score, 4),
        }
