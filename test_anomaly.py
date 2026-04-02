"""Integration test for AnomalyDetector module."""
import sys, os
sys.path.insert(0, ".")

import numpy as np
from app.anomaly_detector.synthetic import generate_normal_traffic
from app.anomaly_detector.detector import AnomalyDetector
from app.anomaly_detector.models import AnomalyResult

# ──────────────────────────────────────────────────────────────
print("TEST 1: Synthetic data generation")
# ──────────────────────────────────────────────────────────────
data = generate_normal_traffic(n_samples=500, seed=99)
assert data.shape == (500, 3)
assert data[:, 0].min() >= 1   # frequency >= 1
assert data[:, 0].max() <= 6   # frequency <= 6
assert data[:, 1].min() >= 1.5 # interval >= 1.5
assert data[:, 2].max() <= 2000 # payload <= 2000
print(f"  shape={data.shape}, ranges OK")
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 2: Train on synthetic data")
# ──────────────────────────────────────────────────────────────
det = AnomalyDetector(model_path="/tmp/test_anomaly.pkl")
det.train(n_samples=1000, seed=42, persist=True)
assert det.is_trained
assert os.path.exists("/tmp/test_anomaly.pkl")
print("  trained and saved")
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 3: Predict — normal traffic scores low")
# ──────────────────────────────────────────────────────────────
normal = det.predict([3, 3.0, 500])
print(f"  normal: {normal.to_dict()}")
assert 0.0 <= normal.anomaly_score <= 1.0
assert normal.is_anomalous is False, f"Expected normal, got anomalous (score={normal.anomaly_score})"
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 4: Predict — anomalous traffic scores high")
# ──────────────────────────────────────────────────────────────
anomaly = det.predict([50, 0.01, 100_000])  # extreme: 50 req/s, tiny interval, huge payload
print(f"  anomaly: {anomaly.to_dict()}")
assert anomaly.anomaly_score > 0.5, f"Expected high score, got {anomaly.anomaly_score}"
assert anomaly.is_anomalous is True
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 5: Predict from dict")
# ──────────────────────────────────────────────────────────────
result = det.predict({"request_frequency": 2, "average_interval": 4.0, "payload_bytes": 300})
print(f"  dict input: {result.to_dict()}")
assert 0.0 <= result.anomaly_score <= 1.0
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 6: Predict from BehaviorFeatures object")
# ──────────────────────────────────────────────────────────────
from app.feature_extractor.models import BehaviorFeatures
bf = BehaviorFeatures(
    ip="10.0.0.1", timestamp=1000.0,
    request_frequency=2, average_interval=3.5,
    interval_std_dev=0.8, payload_bytes=400,
    window_sec=10.0,
)
result = det.predict(bf)
print(f"  BehaviorFeatures input: {result.to_dict()}")
assert result.is_anomalous is False
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 7: Save/Load round-trip")
# ──────────────────────────────────────────────────────────────
det2 = AnomalyDetector(model_path="/tmp/test_anomaly.pkl")
det2.load()
assert det2.is_trained
r1 = det.predict([3, 3.0, 500])
r2 = det2.predict([3, 3.0, 500])
assert abs(r1.anomaly_score - r2.anomaly_score) < 1e-6, "Loaded model gives different results"
print("  round-trip scores match")
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 8: Untrained detector raises RuntimeError")
# ──────────────────────────────────────────────────────────────
det3 = AnomalyDetector(model_path="/tmp/nonexistent.pkl")
try:
    det3.predict([1, 2, 3])
    assert False, "Should have raised"
except RuntimeError as e:
    print(f"  caught: {e}")
print("✅ PASS\n")

# ──────────────────────────────────────────────────────────────
print("TEST 9: Full pipeline — FeatureExtractor → AnomalyDetector → RiskEngine")
# ──────────────────────────────────────────────────────────────
from app.feature_extractor import FeatureExtractor
from app.risk_engine.engine import RiskEngine
from app.risk_engine.signals.anomaly_signal import AnomalySignal

fe = FeatureExtractor(window_sec=10.0)
engine = RiskEngine(feature_extractor=fe)
engine.register_signal(AnomalySignal(det))

# Single benign request
v = engine.evaluate({"ip": "1.2.3.4", "payload_bytes": 300, "timestamp": 5000.0})
print(f"  benign: action={v.action}, score={v.risk_score:.4f}")
signal_names = [s.name for s in v.signals]
assert "anomaly_detector" in signal_names, f"Missing anomaly signal: {signal_names}"
print("✅ PASS\n")

# Cleanup
os.unlink("/tmp/test_anomaly.pkl")

print("🏁 ALL 9 ANOMALY DETECTOR TESTS PASSED")
