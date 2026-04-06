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
    n_samples: int = 10000,
    seed: int = 42,
) -> np.ndarray:
    """Return an (n_samples, 3) array of realistic normal-traffic feature vectors.

    Includes:
    - Linear time-of-day modulation (higher frequency during "business" window)
    - Session-like bursts (interval variability)
    - Log-normal payload sizes (heavy-tailed)
    """
    rng = np.random.default_rng(seed)
    
    # 1. Frequency with time-of-day simulation
    # Simple sine modulation over 'mock' 24h cycle
    times = np.linspace(0, 2 * np.pi, n_samples)
    modulation = (np.sin(times) + 1.2)  # Range ~0.2 to 2.2
    
    # Base frequency 1-4, modulated
    frequency = (rng.integers(low=1, high=5, size=n_samples) * modulation).astype(float)
    frequency = np.clip(frequency, 1, 10)  # Cap at 10 for normal
    
    # 2. Intervals (Session-like)
    # Some users are fast (1-2s), some slow (5-10s), mix of both in distributions
    fast_intervals = rng.uniform(low=0.8, high=2.5, size=n_samples // 2)
    slow_intervals = rng.uniform(low=3.0, high=12.0, size=n_samples - (n_samples // 2))
    interval = np.concatenate([fast_intervals, slow_intervals])
    rng.shuffle(interval)
    
    # 3. Payloads (Log-Normal)
    # Most requests are small (200-800B), but some are large (5KB+)
    # Log-normal distribution captures this 'heavy-tail' perfectly
    payload = rng.lognormal(mean=6.5, sigma=0.8, size=n_samples)
    payload = np.clip(payload, 50, 15000) # clip to reasonable range
    
    # Add small amount of jitter/noise (1%)
    frequency += rng.normal(0, 0.1, n_samples)
    interval += rng.normal(0, 0.2, n_samples)
    
    return np.column_stack([
        np.clip(frequency, 0, 15), 
        np.clip(interval, 0.1, 20), 
        payload
    ])
