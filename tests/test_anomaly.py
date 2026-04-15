import pytest
import os
import sys
import numpy as np

from app.anomaly_detector.synthetic import generate_normal_traffic
from app.anomaly_detector.detector import AnomalyDetector
from app.feature_extractor.models import BehaviorFeatures
from app.feature_extractor import FeatureExtractor
from app.risk_engine.engine import RiskEngine
from app.risk_engine.signals.anomaly_signal import AnomalySignal

def test_synthetic_data_generation():
    data = generate_normal_traffic(n_samples=500, seed=99)
    assert data.shape == (500, 3)
    # The frequency logic in synthetic.py was changed and involves sine waves, 
    # so minimum frequency can dip below 1 depending on the exact numpy iteration.
    assert data[:, 0].min() >= 0 # frequency >= 0
    assert data[:, 0].max() <= 15
    assert data[:, 1].min() >= 0.1
    assert data[:, 2].max() <= 15000

@pytest.fixture
def temp_model_path(tmp_path):
    yield str(tmp_path / "test_anomaly.pkl")

def test_train_on_synthetic_data(temp_model_path):
    det = AnomalyDetector(model_path=temp_model_path)
    det.train(n_samples=1000, seed=42, persist=True)
    assert det.is_trained
    assert os.path.exists(temp_model_path)

@pytest.fixture
def trained_detector(temp_model_path):
    det = AnomalyDetector(model_path=temp_model_path)
    det.train(n_samples=1000, seed=42, persist=True)
    return det

def test_predict_normal(trained_detector):
    normal = trained_detector.predict([3, 3.0, 500])
    assert 0.0 <= normal.anomaly_score <= 1.0
    assert normal.is_anomalous is False

def test_predict_anomaly(trained_detector):
    anomaly = trained_detector.predict([50, 0.01, 100_000])
    assert anomaly.anomaly_score > 0.5
    assert anomaly.is_anomalous is True

def test_predict_from_dict(trained_detector):
    result = trained_detector.predict({"request_frequency": 2, "average_interval": 4.0, "payload_bytes": 300})
    assert 0.0 <= result.anomaly_score <= 1.0

def test_predict_from_behavior_features(trained_detector):
    bf = BehaviorFeatures(
        ip="10.0.0.1", timestamp=1000.0,
        request_frequency=2, average_interval=3.5,
        interval_std_dev=0.8, payload_bytes=400,
        window_sec=10.0,
    )
    result = trained_detector.predict(bf)
    assert result.is_anomalous is False

def test_save_load_round_trip(temp_model_path, trained_detector):
    det2 = AnomalyDetector(model_path=temp_model_path)
    det2.load()
    assert det2.is_trained
    r1 = trained_detector.predict([3, 3.0, 500])
    r2 = det2.predict([3, 3.0, 500])
    assert abs(r1.anomaly_score - r2.anomaly_score) < 1e-6

def test_untrained_detector_raises():
    det = AnomalyDetector(model_path="/tmp/nonexistent-does-not-exist.pkl")
    with pytest.raises(RuntimeError):
        det.predict([1, 2, 3])

def test_full_pipeline(trained_detector):
    fe = FeatureExtractor(window_sec=10.0)
    engine = RiskEngine(feature_extractor=fe)
    engine.register_signal(AnomalySignal(trained_detector))

    v = engine.evaluate({"ip": "1.2.3.4", "payload_bytes": 300, "timestamp": 5000.0})
    signal_names = [s.name for s in v.signals]
    assert "anomaly_detector" in signal_names
