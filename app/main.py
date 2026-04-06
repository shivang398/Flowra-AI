import asyncio
import logging
import time

from fastapi import FastAPI, Request, Depends, HTTPException
from pydantic import BaseModel

from app.auth import verify_token
from app.model import predict
from app.logger import log_request
from app.feature_extractor import FeatureExtractor
from app.fingerprint import FingerprintEngine
from app.anomaly_detector import AnomalyDetector
from app.risk_engine import RiskEngine
from app.risk_engine.decision import HeuristicDecisionEngine
from app.risk_engine.signals import AnomalySignal, FingerprintSignal

logging.basicConfig(level=logging.INFO)

app = FastAPI()

import os
from app.feature_extractor.store import RedisStore
from app.fingerprint.store import RedisFingerprintStore

# --- Shared engines (swap InMemoryStores → RedisStores for distributed) ---
USE_REDIS = os.environ.get("USE_REDIS", "false").lower() == "true"
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

if USE_REDIS:
    logging.info(f"Using Redis stores at {REDIS_URL}")
    feature_store = RedisStore(redis_url=REDIS_URL)
    fingerprint_store = RedisFingerprintStore(redis_url=REDIS_URL)
else:
    logging.info("Using InMemory stores")
    feature_store = None
    fingerprint_store = None

feature_extractor = FeatureExtractor(store=feature_store, window_sec=10.0)
fingerprint_engine = FingerprintEngine(store=fingerprint_store, min_samples=5)
decision_engine = HeuristicDecisionEngine(throttle_threshold=0.3, block_threshold=0.7)

# --- ML Anomaly detector ---
anomaly_detector = AnomalyDetector()
try:
    anomaly_detector.load()
except FileNotFoundError:
    anomaly_detector.train(persist=True)

# --- Risk engine: rules + ML + Fingerprinting + Decision Intelligence ---
risk_engine = RiskEngine(
    feature_extractor=feature_extractor,
    fingerprint_engine=fingerprint_engine,
    decision_engine=decision_engine,
)
risk_engine.register_signal(AnomalySignal(anomaly_detector))
risk_engine.register_signal(FingerprintSignal(weight=1.2))


class InputData(BaseModel):
    data: list


@app.get("/")
def root():
    return {"message": "SentinelAI running 🚀"}


@app.post("/predict")
async def basic_predict(
    input: InputData,
    request: Request,
    user=Depends(verify_token),
):
    """Original prediction endpoint with detailed risk breakdown."""
    start = time.time()
    
    # Context building
    body_bytes = len(input.model_dump_json().encode())
    ctx = {
        "ip": request.client.host,
        "payload_bytes": body_bytes,
        "timestamp": start,
    }
    
    # 1. Pipeline Execution
    verdict = risk_engine.evaluate(ctx)

    # 2. Enforcement
    if verdict.action == "block":
        raise HTTPException(
            status_code=403,
            detail=f"Blocked: {verdict.explanation}",
        )

    if verdict.action == "throttle":
        await asyncio.sleep(1)

    # 3. Model Inference
    result = predict(input.data)

    # 4. Logging
    log_request(
        latency=latency,
        risk_score=verdict.risk_score,
        action=verdict.action,
        anomaly_score=next((s.score for s in verdict.signals if s.name == "anomaly_detector"), 0.0),
        deviation_score=next((s.score for s in verdict.signals if s.name == "behavioral_fingerprint"), 0.0),
        features=verdict.features,
        reasoning=verdict.reasoning
    )

    return {
        "prediction": result,
        **verdict.to_dict(),
        "latency": latency,
    }


@app.post("/secure-predict")
async def secure_predict_pipeline(
    input: InputData,
    request: Request,
    user=Depends(verify_token),
):
    """The unified security pipeline endpoint.
    
    Returns specific fields: prediction, anomaly_score, deviation_score, action, latency.
    """
    start = time.time()
    
    # 1. Build request context
    body_bytes = len(input.model_dump_json().encode())
    ctx = {
        "ip": request.client.host,
        "payload_bytes": body_bytes,
        "timestamp": start
    }
    
    # 2. Pipeline Execution: Stats -> ML -> Fingerprints -> Decision Intelligence
    verdict = risk_engine.evaluate(ctx)
    action = verdict.action

    # 3. Enforcement
    if action == "block":
        # Log before raising if possible, or handle in middleware. 
        # For now, log and then raise.
        log_request(
            latency=time.time() - start,
            risk_score=verdict.risk_score,
            action=action,
            features=verdict.features,
            reasoning=verdict.reasoning
        )
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: {verdict.reasoning}"
        )

    if action == "throttle":
        await asyncio.sleep(1)

    # 4. Model Inference (if not blocked)
    result = predict(input.data)
    latency = time.time() - start
    
    # 5. Signal extraction for flat response
    signal_map = {s.name: s.score for s in verdict.signals}
    anomaly_score = signal_map.get("anomaly_detector", 0.0)
    deviation_score = signal_map.get("behavioral_fingerprint", 0.0)

    # 6. Logging
    log_request(
        latency=latency,
        risk_score=verdict.risk_score,
        action=action,
        anomaly_score=anomaly_score,
        deviation_score=deviation_score,
        features=verdict.features,
        reasoning=verdict.reasoning
    )

    return {
        "prediction": result,
        "anomaly_score": round(anomaly_score, 4),
        "deviation_score": round(deviation_score, 4),
        "action": action,
        "latency": round(latency, 4)
    }