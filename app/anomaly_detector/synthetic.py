"""Synthetic data generator for training the anomaly detector.

Produces feature vectors that mimic *normal* API traffic so the
Isolation Forest learns the inlier distribution.  The three features
match what :class:`BehaviorFeatures` produces:

    [request_frequency, average_interval, payload_bytes]

All generated with controlled randomness around realistic baselines.
"""

from __future__ import annotations

import numpy as np


def generate_normal_traffic(
    n_samples: int = 2000,
    seed: int = 42,
) -> np.ndarray:
    """Return an (n_samples, 3) array of normal-traffic feature vectors.

    Feature columns
    ---------------
    0 — request_frequency : int-like
        Requests per 10 s window.  Normal users: 1–6.
    1 — average_interval : float
        Mean seconds between requests.  Normal: 1.5–5.0 s.
    2 — payload_bytes : int-like
        Request body size.  Normal: 50–2 000 bytes.

    Parameters
    ----------
    n_samples : int
        Number of synthetic normal samples (default 2 000).
    seed : int
        Random seed for reproducibility.
    """
    rng = np.random.default_rng(seed)

    frequency = rng.integers(low=1, high=7, size=n_samples).astype(float)
    interval = rng.uniform(low=1.5, high=5.0, size=n_samples)
    payload = rng.integers(low=50, high=2_000, size=n_samples).astype(float)

    return np.column_stack([frequency, interval, payload])
