import sys
import os

# Add current dir to path to find 'app'
sys.path.append(os.getcwd())

from app.anomaly_detector.detector import AnomalyDetector
import logging

logging.basicConfig(level=logging.INFO)

def main():
    print("🚀 Retraining AnomalyDetector with enhanced synthetic data...")
    detector = AnomalyDetector()
    # This will use the new generate_normal_traffic with 10k samples
    detector.train(persist=True)
    print("✅ AnomalyDetector retrained and saved to model/anomaly_detector.pkl")

if __name__ == "__main__":
    main()
