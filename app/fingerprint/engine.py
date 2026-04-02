"""Behavioral Fingerprinting Engine — detects deviations from an IP's baseline."""

from __future__ import annotations

import math
from typing import Optional

from app.feature_extractor.models import BehaviorFeatures
from app.fingerprint.models import FingerprintBaseline, FingerprintResult
from app.fingerprint.store import BaseFingerprintStore, InMemoryFingerprintStore


class FingerprintEngine:
    """Tracks per-IP baseline and computes deviation for each request.

    Uses Welford's Online Algorithm to update running mean and variance.

    Parameters
    ----------
    store : BaseFingerprintStore | None
        Storage backend (default: InMemoryFingerprintStore).
    min_samples : int
        Minimum requests before we trust a baseline (default: 5).
    """

    def __init__(
        self,
        store: Optional[BaseFingerprintStore] = None,
        min_samples: int = 5,
    ) -> None:
        self._store = store or InMemoryFingerprintStore()
        self._min_samples = min_samples

    def update_and_get(self, ip: str, features: BehaviorFeatures) -> FingerprintResult:
        """Update an IP's baseline with new features and return the deviation."""
        baseline = self._store.get(ip)
        
        # 1. Compute deviation score *before* updating baseline
        # (Compare current behavior to the established history)
        score = self._compute_deviation(baseline, features)
        
        # 2. Update baseline via Welford's
        new_baseline = self._update_welford(baseline, features)
        self._store.set(ip, new_baseline)

        explanation = self._explain(score, baseline, features)

        return FingerprintResult(
            ip=ip,
            deviation_score=score,
            baseline=new_baseline,
            explanation=explanation,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _compute_deviation(self, b: FingerprintBaseline, f: BehaviorFeatures) -> float:
        """Calculate normalized deviation score based on Z-scores."""
        if b.count < self._min_samples:
            return 0.0

        # Frequency Z-score
        std_freq = math.sqrt(b.var_freq)
        diff_f = abs(f.request_frequency - b.mean_freq)
        # Handle zero variance: If diff > 0.5, it's a deviation
        z_freq = diff_f / max(0.1, std_freq)
        
        # Interval Z-score
        z_interval = 0.0
        if f.average_interval is not None and b.interval_count > 0:
            std_int = math.sqrt(b.var_interval)
            diff_i = abs(f.average_interval - b.mean_interval)
            z_interval = diff_i / max(0.05, std_int)

        # Combined normalized deviation
        # Mapping Z-scores to a 0-1 risk range. 
        # Z > 3 is considered significant deviation.
        avg_z = (z_freq + z_interval) / 2
        norm_score = min(1.0, avg_z / 4.0)  # Caps at 1.0 around Z=4
        return norm_score

    def _update_welford(self, b: FingerprintBaseline, f: BehaviorFeatures) -> FingerprintBaseline:
        """Update running statistics for frequency and interval."""
        n = b.count + 1
        
        # --- Update Frequency ---
        d_f = f.request_frequency - b.mean_freq
        new_mean_f = b.mean_freq + (d_f / n)
        new_m2_f = b.m2_freq + (d_f * (f.request_frequency - new_mean_f))
        
        # --- Update Interval ---
        new_n_i = b.interval_count
        new_mean_i = b.mean_interval
        new_m2_i = b.m2_interval
        
        if f.average_interval is not None:
            new_n_i += 1
            d_i = f.average_interval - b.mean_interval
            new_mean_i = b.mean_interval + (d_i / new_n_i)
            new_m2_i = b.m2_interval + (d_i * (f.average_interval - new_mean_i))

        return FingerprintBaseline(
            count=n,
            interval_count=new_n_i,
            mean_freq=new_mean_f,
            m2_freq=new_m2_f,
            mean_interval=new_mean_i,
            m2_interval=new_m2_i,
        )

    def _explain(self, score: float, b: FingerprintBaseline, f: BehaviorFeatures) -> str:
        if b.count < self._min_samples:
            return f"Baseline building ({b.count}/{self._min_samples} requests)"
        
        if score > 0.3:  # Lowered threshold for "significant"
            return f"Significant deviation ({score:.2f}) from behavior baseline"
        
        return f"Consistent with baseline (score={score:.2f}, samples={b.count})"
