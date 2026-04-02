"""Core feature extraction logic.

The :class:`FeatureExtractor` is the **single source of truth** for per-IP
behavioral tracking.  It records every request, prunes stale data, and
computes derived features (frequency, interval stats, payload size) in one
pass.  The risk engine's signals then read these pre-computed features
instead of each maintaining their own timestamp logs.
"""

from __future__ import annotations

import statistics
import time

from app.feature_extractor.models import BehaviorFeatures
from app.feature_extractor.store import BaseStore, InMemoryStore


class FeatureExtractor:
    """Extracts behavioral features from incoming API requests.

    Parameters
    ----------
    store : BaseStore | None
        Pluggable storage backend.  Defaults to :class:`InMemoryStore`.
        Pass a Redis-backed store for distributed deployments.
    window_sec : float
        Sliding window for frequency and interval calculations (default 10 s).
    """

    def __init__(
        self,
        store: BaseStore | None = None,
        window_sec: float = 10.0,
    ) -> None:
        self._store = store or InMemoryStore()
        self._window = window_sec

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        ip: str,
        timestamp: float | None = None,
        payload_bytes: int = 0,
    ) -> BehaviorFeatures:
        """Record the request and return a feature snapshot.

        This method is **not** thread-safe by itself; in an async FastAPI
        app each request runs on the event loop so concurrent access is
        sequential.  For multi-worker setups, use a Redis-backed store
        which handles atomicity at the storage layer.

        Parameters
        ----------
        ip : str
            Client IP address.
        timestamp : float | None
            Request epoch timestamp.  Defaults to ``time.time()``.
        payload_bytes : int
            Size of the request body in bytes.
        """
        now = timestamp if timestamp is not None else time.time()

        # 1. Record this request
        self._store.append(ip, now)

        # 2. Prune entries outside the window
        cutoff = now - self._window
        self._store.prune(ip, cutoff)

        # 3. Read surviving timestamps (oldest → newest)
        timestamps = self._store.get_timestamps(ip)

        # 4. Compute features
        frequency = len(timestamps)
        avg_interval = self._compute_avg_interval(timestamps)
        std_dev = self._compute_interval_std(timestamps)

        return BehaviorFeatures(
            ip=ip,
            timestamp=now,
            request_frequency=frequency,
            average_interval=avg_interval,
            interval_std_dev=std_dev,
            payload_bytes=payload_bytes,
            window_sec=self._window,
        )

    @property
    def window_sec(self) -> float:
        return self._window

    @property
    def store(self) -> BaseStore:
        """Access the underlying store (useful for monitoring / testing)."""
        return self._store

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_avg_interval(timestamps: list[float]) -> float | None:
        """Mean inter-request interval, or None if fewer than 2 data points."""
        if len(timestamps) < 2:
            return None
        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]
        return sum(intervals) / len(intervals)

    @staticmethod
    def _compute_interval_std(timestamps: list[float]) -> float | None:
        """Std-dev of inter-request intervals, or None if fewer than 3 points.

        We need ≥ 2 intervals (i.e. ≥ 3 timestamps) to compute a
        meaningful standard deviation.
        """
        if len(timestamps) < 3:
            return None
        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]
        return statistics.stdev(intervals)
