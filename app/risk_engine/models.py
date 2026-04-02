"""Structured data models for the risk engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SignalResult:
    """Output produced by a single risk signal."""

    name: str
    score: float          # 0.0 (safe) → 1.0 (dangerous)
    weight: float         # relative importance—engine normalises at aggregation time
    detail: str = ""      # human-readable explanation


@dataclass(frozen=True, slots=True)
class RiskVerdict:
    """Structured response returned by :meth:`RiskEngine.evaluate`."""

    risk_score: float               # aggregated, weighted score in [0, 1]
    action: str                     # "allow" | "throttle" | "block"
    signals: list[SignalResult]     # individual signal contributions
    explanation: str                # one-line human summary
    reasoning: str = ""             # detailed human-readable decision logic
    features: dict = field(default_factory=dict) # raw behavioral features used

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 4),
            "action": self.action,
            "signals": [
                {"name": s.name, "score": round(s.score, 4), "weight": s.weight, "detail": s.detail}
                for s in self.signals
            ],
            "explanation": self.explanation,
            "reasoning": self.reasoning,
            "features": self.features,
        }
