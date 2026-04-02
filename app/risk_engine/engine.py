from __future__ import annotations

import time
from typing import Sequence, Optional

from app.feature_extractor import FeatureExtractor
from app.fingerprint import FingerprintEngine
from app.risk_engine.base_signal import BaseSignal
from app.risk_engine.decision import BaseDecisionEngine, HeuristicDecisionEngine
from app.risk_engine.models import RiskVerdict, SignalResult
from app.risk_engine.signals import (
    IPFrequencySignal,
    PayloadSizeSignal,
    RequestIntervalSignal,
)


class RiskEngine:
    """Modular risk assessment engine.

    Owns a :class:`FeatureExtractor`, a :class:`FingerprintEngine`,
    a :class:`BaseDecisionEngine`, and a list of :class:`BaseSignal` instances.

    On every :meth:`evaluate` call it:
    1. Extracts behavioral features (single request).
    2. Updates & Retrieves the IP's behavioral fingerprint (baseline).
    3. Runs all signals (Rule-based, ML-Anomaly, Fingerprint).
    4. Aggregates scores and delegates the final ACTION and REASONING
       to the DecisionEngine.

    Parameters
    ----------
    feature_extractor : FeatureExtractor | None
    fingerprint_engine : FingerprintEngine | None
    decision_engine : BaseDecisionEngine | None
    signals : Sequence[BaseSignal] | None
    """

    def __init__(
        self,
        feature_extractor: Optional[FeatureExtractor] = None,
        fingerprint_engine: Optional[FingerprintEngine] = None,
        decision_engine: Optional[BaseDecisionEngine] = None,
        signals: Optional[Sequence[BaseSignal]] = None,
    ) -> None:
        self._extractor = feature_extractor or FeatureExtractor()
        self._fingerprint = fingerprint_engine or FingerprintEngine()
        self._decision = decision_engine or HeuristicDecisionEngine()
        self._signals: list[BaseSignal] = list(signals) if signals is not None else [
            IPFrequencySignal(),
            PayloadSizeSignal(),
            RequestIntervalSignal(),
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def extractor(self) -> FeatureExtractor:
        return self._extractor

    @property
    def fingerprint(self) -> FingerprintEngine:
        return self._fingerprint

    def register_signal(self, signal: BaseSignal) -> None:
        """Add a new signal at runtime."""
        self._signals.append(signal)

    def evaluate(self, ctx: dict) -> RiskVerdict:
        """Process a request and return a structured verdict."""
        ts = ctx.get("timestamp", time.time())

        # 1. Feature extraction (single source of truth)
        features = self._extractor.extract(
            ip=ctx["ip"],
            timestamp=ts,
            payload_bytes=ctx.get("payload_bytes", 0),
        )

        # 2. Behavioral Fingerprinting (long-term stats)
        fingerprint = self._fingerprint.update_and_get(ctx["ip"], features)

        # 3. Enrich context for signals
        enriched = {
            **ctx,
            "timestamp": ts,
            "features": features,
            "fingerprint": fingerprint,
        }

        # --- Signal evaluation ---
        results: list[SignalResult] = [s.evaluate(enriched) for s in self._signals]
        agg_score = self._aggregate(results)
        
        # --- Decision making (Intelligent Logic) ---
        action, reasoning = self._decision.decide(agg_score, results)
        explanation = self._explain(results, agg_score, action)

        return RiskVerdict(
            risk_score=agg_score,
            action=action,
            signals=results,
            explanation=explanation,
            reasoning=reasoning,
            features=features.to_dict(),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate(results: list[SignalResult]) -> float:
        """Weighted average of all signal scores, clamped to [0, 1]."""
        total_weight = sum(r.weight for r in results)
        if total_weight == 0:
            return 0.0
        raw = sum(r.score * r.weight for r in results) / total_weight
        return max(0.0, min(1.0, raw))

    @staticmethod
    def _explain(results: list[SignalResult], score: float, action: str) -> str:
        fired = [r for r in results if r.score > 0]
        if not fired:
            return f"All clear — aggregated risk {score:.2f}, action={action}"
        parts = [f"{r.name}({r.score:.2f})" for r in fired]
        return f"Signals fired: {', '.join(parts)} → aggregated {score:.2f}, action={action}"
