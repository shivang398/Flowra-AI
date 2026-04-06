"""Core anomaly detection using Isolation Forest.

The :class:`AnomalyDetector` wraps scikit-learn's IsolationForest with:
- A normalisation layer that maps raw scores to [0, 1].
- A configurable anomaly threshold.
- Model persistence via joblib (train once, load on startup).
- A clean ``predict()`` method that accepts :class:`BehaviorFeatures`.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.anomaly_detector.models import AnomalyResult
from app.anomaly_detector.synthetic import generate_normal_traffic

logger = logging.getLogger(__name__)

# Default model save location
_DEFAULT_MODEL_DIR = Path("model")
_DEFAULT_MODEL_PATH = _DEFAULT_MODEL_DIR / "anomaly_detector.pkl"


class AnomalyDetector:
    """Isolation-Forest-based anomaly detector for API request features.

    Parameters
    ----------
    contamination : float
        Expected proportion of anomalies in training data (default 0.01).
        Since we train on synthetic *normal* traffic this should be very low.
    threshold : float
        Normalised score >= this marks a request as anomalous (default 0.65).
    n_estimators : int
        Number of trees in the forest (default 150).
    model_path : str | Path | None
        Where to save / load the trained model.  ``None`` uses the default
        ``model/anomaly_detector.pkl``.
    """

    # The 3 features consumed (in order)
    FEATURE_NAMES = ("request_frequency", "average_interval", "payload_bytes")

    def __init__(
        self,
        contamination: float = 0.05,
        threshold: float = 0.65,
        n_estimators: int = 200,
        warmup_steps: int = 50,
        model_path: str | Path | None = None,
    ) -> None:
        self._contamination = contamination
        self._threshold = threshold
        self._n_estimators = n_estimators
        self._warmup_steps = warmup_steps
        self._model_path = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
        self._model: IsolationForest | None = None

        # Normalisation bounds (fitted during train)
        self._score_min: float = 0.0
        self._score_max: float = 1.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def train(
        self,
        X: np.ndarray | None = None,
        n_samples: int = 10000,
        seed: int = 42,
        persist: bool = True,
    ) -> None:
        """Fit the Isolation Forest on normal traffic data.

        Parameters
        ----------
        X : ndarray, shape (n, 3) | None
            Training feature matrix.  When *None*, synthetic normal data
            is generated automatically.
        n_samples : int
            Number of synthetic samples when *X* is None.
        seed : int
            Random seed for synthetic generation.
        persist : bool
            Save the fitted model to disk (default True).
        """
        if X is None:
            X = generate_normal_traffic(n_samples=n_samples, seed=seed)

        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=seed,
            n_jobs=-1,
        )
        self._model.fit(X)

        # Compute normalisation bounds from training data so we can
        # map arbitrary decision_function values → [0, 1].
        raw_scores = self._model.decision_function(X)
        self._score_min = float(raw_scores.min())
        self._score_max = float(raw_scores.max())

        logger.info(
            "AnomalyDetector trained on %d samples  "
            "(score_range=[%.4f, %.4f], contamination=%.3f)",
            len(X), self._score_min, self._score_max, self._contamination,
        )

        if persist:
            self.save()

    def predict(self, features, request_count: int = 100) -> AnomalyResult:
        """Score a single request.

        Parameters
        ----------
        features : BehaviorFeatures | dict | list | ndarray
            Input features.
        request_count : int
            Number of previous requests from this IP (for warm-up logic).
        """
        if self._model is None:
            raise RuntimeError("AnomalyDetector is not trained")

        vec = self._to_vector(features)
        raw = float(self._model.decision_function(vec.reshape(1, -1))[0])

        # 1. Normalise to [0, 1]
        score_range = self._score_max - self._score_min
        norm = 1.0 - (raw - self._score_min) / max(1e-6, score_range)
        norm = max(0.0, min(1.0, norm))

        # 2. Warm-up Logic
        # New IPs (low request_count) get a 'grace' reduction in anomaly score
        # to prevent false positives during baseline building.
        if request_count < self._warmup_steps:
            warmup_factor = request_count / self._warmup_steps
            norm *= warmup_factor

        # 3. Confidence Scoring
        # Confidence is higher the further we are from the boundary (threshold).
        # Near the threshold ([threshold-0.1, threshold+0.1]), confidence is low.
        dist_from_threshold = abs(norm - self._threshold)
        confidence = min(1.0, dist_from_threshold * 5.0) # Reach max confidence at 0.2 distance

        return AnomalyResult(
            anomaly_score=norm,
            confidence=confidence,
            is_anomalous=norm >= self._threshold,
            raw_score=raw,
        )

    def save(self, path: str | Path | None = None) -> Path:
        """Persist the trained model + normalisation state."""
        dest = Path(path) if path else self._model_path
        dest.parent.mkdir(parents=True, exist_ok=True)

        state = {
            "model": self._model,
            "score_min": self._score_min,
            "score_max": self._score_max,
            "contamination": self._contamination,
            "threshold": self._threshold,
            "n_estimators": self._n_estimators,
        }
        joblib.dump(state, dest)
        logger.info("AnomalyDetector saved to %s", dest)
        return dest

    def load(self, path: str | Path | None = None) -> None:
        """Load a previously saved model."""
        src = Path(path) if path else self._model_path
        if not src.exists():
            raise FileNotFoundError(f"No model at {src}")

        state = joblib.load(src)
        self._model = state["model"]
        self._score_min = state["score_min"]
        self._score_max = state["score_max"]
        self._contamination = state["contamination"]
        self._threshold = state["threshold"]
        self._n_estimators = state["n_estimators"]
        logger.info("AnomalyDetector loaded from %s", src)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _to_vector(self, features) -> np.ndarray:
        """Convert various input formats to a (3,) numpy vector."""
        # BehaviorFeatures or any object with matching attributes
        if hasattr(features, "request_frequency"):
            return np.array([
                float(features.request_frequency),
                float(features.average_interval if features.average_interval is not None else 0.0),
                float(features.payload_bytes),
            ])

        # Dict
        if isinstance(features, dict):
            return np.array([
                float(features.get("request_frequency", 0)),
                float(features.get("average_interval", 0) or 0),
                float(features.get("payload_bytes", 0)),
            ])

        # List / ndarray passthrough
        arr = np.asarray(features, dtype=float)
        if arr.shape != (3,):
            raise ValueError(f"Expected 3 features, got shape {arr.shape}")
        return arr
