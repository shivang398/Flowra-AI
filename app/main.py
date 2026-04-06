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
from app.risk_engine.signals import AnomalySignal, FingerprintSignal, PromptInjectionSignal

logging.basicConfig(level=logging.INFO)

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import os
from app.feature_extractor.store import RedisStore
from app.fingerprint.store import RedisFingerprintStore
from app.rate_limiter import rate_enforcer
from app.appeal import whitelist_manager, appeal_store, block_registry, AppealRequest

# --- Shared engines (swap InMemoryStores → RedisStores for distributed) ---
USE_REDIS = os.environ.get("USE_REDIS", "false").lower() == "true"
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

if USE_REDIS:
    import redis
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    logging.info(f"Using Redis stores at {REDIS_URL}")
    feature_store = RedisStore(redis_url=REDIS_URL)
    fingerprint_store = RedisFingerprintStore(redis_url=REDIS_URL)
    # Re-initialize appeal instances with redis client
    whitelist_manager._redis = r
    appeal_store._redis = r
    block_registry._redis = r
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
risk_engine.register_signal(PromptInjectionSignal(weight=2.0))


class InputData(BaseModel):
    data: list


@app.on_event("startup")
async def startup_event():
    from app.auth import SECRET_KEY
    if not SECRET_KEY:
        logging.critical("CRITICAL: SENTINEL_JWT_SECRET is not set. Exiting.")
        raise RuntimeError("SENTINEL_JWT_SECRET is not set")
    logging.info("SentinelAI security configuration validated.")

@app.get("/")
def root():
    return {"message": "SentinelAI running 🚀"}

@app.get("/token")
def generate_test_token():
    """Generates a test token ONLY for dashboard demo purposes."""
    from app.auth import SECRET_KEY, ALGORITHM
    from jose import jwt
    import time
    
    if not SECRET_KEY:
         raise HTTPException(status_code=500, detail="JWT SECRET_KEY not configured")
         
    payload = {"user": "demo_user", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/predict")
async def basic_predict(
    input: InputData,
    request: Request,
    user=Depends(verify_token),
):
    """Original prediction endpoint with detailed risk breakdown."""
    start = time.time()
    ip = request.client.host
    
    # 0. Whitelist/Block Check
    if whitelist_manager.is_whitelisted(ip):
         logging.info(f"IP {ip} is whitelisted, skipping security checks.")
         return {
             "prediction": predict(input.data),
             "action": "allow",
             "whitelisted": True,
             "anomaly_score": 0.0,
             "deviation_score": 0.0,
             "injection_score": 0.0,
             "latency": 0.0
         }

    if block_registry.is_blocked(ip):
         raise HTTPException(status_code=403, detail="Your IP is temporarily blocked. Please appeal if this is an error.")

    # Context building
    body_bytes = len(input.model_dump_json().encode())
    ctx = {
        "ip": ip,
        "payload_bytes": body_bytes,
        "payload_content": input.data,
        "timestamp": start,
    }
    
    # 1. Pipeline Execution
    verdict = risk_engine.evaluate(ctx)

    # 2. Rate Limiting and Backoff
    action = await rate_enforcer.enforce(ctx["ip"], verdict.action)

    # 3. Enforcement
    if action == "rate_limit":
        raise HTTPException(
            status_code=429,
            detail="Too Many Requests: Rate limit exceeded",
        )

    if action == "block":
        # Record the block
        block_registry.block(ip, verdict.reasoning, ttl_sec=int(os.environ.get("BLOCK_TTL_RISK", 3600)))
        
        # Log before raising
        log_request(
            latency=time.time() - start,
            risk_score=verdict.risk_score,
            action=action,
            anomaly_score=next((s.score for s in verdict.signals if s.name == "anomaly_detector"), 0.0),
            deviation_score=next((s.score for s in verdict.signals if s.name == "behavioral_fingerprint"), 0.0),
            injection_score=next((s.score for s in verdict.signals if s.name == "prompt_injection"), 0.0),
            features=verdict.features,
            reasoning=verdict.reasoning
        )
        raise HTTPException(
            status_code=403,
            detail=f"Blocked: {verdict.explanation}. Appeal at /appeal",
        )

    # 3. Model Inference
    try:
        result = predict(input.data)
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid data for model inference: {str(e)}")
    latency = time.time() - start

    # 4. Logging
    log_request(
        latency=latency,
        risk_score=verdict.risk_score,
        action=action,
        anomaly_score=next((s.score for s in verdict.signals if s.name == "anomaly_detector"), 0.0),
        deviation_score=next((s.score for s in verdict.signals if s.name == "behavioral_fingerprint"), 0.0),
        injection_score=next((s.score for s in verdict.signals if s.name == "prompt_injection"), 0.0),
        features=verdict.features,
        reasoning=verdict.reasoning
    )

    return {
        "prediction": result,
        **verdict.to_dict(),
        "latency": round(latency, 4),
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
    ip = request.client.host

    # 0. Quick Checks
    if whitelist_manager.is_whitelisted(ip):
         return {
             "prediction": predict(input.data),
             "action": "allow",
             "whitelisted": True,
             "anomaly_score": 0.0,
             "deviation_score": 0.0,
             "injection_score": 0.0,
             "latency": 0.0
         }

    if block_registry.is_blocked(ip):
         raise HTTPException(status_code=403, detail="IP Blocked")

    # 1. Build request context
    body_bytes = len(input.model_dump_json().encode())
    ctx = {
        "ip": ip,
        "payload_bytes": body_bytes,
        "payload_content": input.data,
        "timestamp": start
    }
    
    # 2. Pipeline Execution: Stats -> ML -> Fingerprints -> Decision Intelligence
    verdict = risk_engine.evaluate(ctx)
    action = verdict.action

    # 3. Enforcement
    action = await rate_enforcer.enforce(ctx["ip"], action)

    if action == "rate_limit":
        raise HTTPException(
            status_code=429,
            detail="Too Many Requests: Rate limit exceeded"
        )

    if action == "block":
        # Record the block
        block_registry.block(ip, verdict.reasoning, ttl_sec=int(os.environ.get("BLOCK_TTL_RISK", 3600)))
        
        # Log before raising if possible, or handle in middleware. 
        # For now, log and then raise.
        log_request(
            latency=time.time() - start,
            risk_score=verdict.risk_score,
            action=action,
            anomaly_score=next((s.score for s in verdict.signals if s.name == "anomaly_detector"), 0.0),
            deviation_score=next((s.score for s in verdict.signals if s.name == "behavioral_fingerprint"), 0.0),
            injection_score=next((s.score for s in verdict.signals if s.name == "prompt_injection"), 0.0),
            features=verdict.features,
            reasoning=verdict.reasoning
        )
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: {verdict.reasoning}. You can submit an appeal at /appeal."
        )

    # 4. Model Inference (if not blocked)
    # SAFETY CHECK: If prompt injection detected or data is not floats, we return 400 or skip inference
    try:
        result = predict(input.data)
    except (ValueError, TypeError) as e:
        # If it was a deliberate prompt injection test, we return 200 but maybe with a warning result
        # Or a 400 if it's truly bad data.
        # Given this is a security pipeline, we'll return 400 for malformed data
        raise HTTPException(status_code=400, detail=f"Invalid data for model inference: {str(e)}")

    latency = time.time() - start
    
    # 5. Signal extraction for flat response
    signal_map = {s.name: s.score for s in verdict.signals}
    anomaly_score = signal_map.get("anomaly_detector", 0.0)
    deviation_score = signal_map.get("behavioral_fingerprint", 0.0)
    injection_score = signal_map.get("prompt_injection", 0.0)

    # 6. Logging
    log_request(
        latency=latency,
        risk_score=verdict.risk_score,
        action=action,
        anomaly_score=anomaly_score,
        deviation_score=deviation_score,
        injection_score=injection_score,
        features=verdict.features,
        reasoning=verdict.reasoning
    )

    return {
        "prediction": result,
        "anomaly_score": round(anomaly_score, 4),
        "deviation_score": round(deviation_score, 4),
        "injection_score": round(injection_score, 4),
        "action": action,
        "latency": round(latency, 4)
    }
# --- Appeal & Admin Endpoints ---
from fastapi import Header
import uuid

def verify_admin(x_admin_key: str = Header(None)):
    admin_key = os.environ.get("SENTINEL_ADMIN_KEY")
    if not admin_key or x_admin_key != admin_key:
        raise HTTPException(status_code=401, detail="Invalid admin key")

@app.post("/appeal")
async def submit_appeal(request: Request, reason: str):
    ip = request.client.host
    appeal_id = str(uuid.uuid4())[:8]
    appeal = AppealRequest(id=appeal_id, ip=ip, reason=reason, timestamp=time.time())
    appeal_store.submit(appeal)
    return {"appeal_id": appeal_id, "message": "Appeal submitted successfully."}

@app.get("/appeal/{appeal_id}")
async def get_appeal_status(appeal_id: str):
    appeal = appeal_store.get(appeal_id)
    if not appeal:
        raise HTTPException(status_code=404, detail="Appeal not found")
    return {"status": appeal.status}

@app.post("/admin/appeal/{appeal_id}/decide", dependencies=[Depends(verify_admin)])
async def decide_appeal(appeal_id: str, approved: bool):
    status = "approved" if approved else "rejected"
    appeal = appeal_store.get(appeal_id)
    if not appeal:
        raise HTTPException(status_code=404, detail="Appeal not found")
    
    appeal_store.update_status(appeal_id, status)
    if approved:
        whitelist_manager.add(appeal.ip)
    return {"message": f"Appeal {appeal_id} {status}."}

@app.post("/admin/whitelist", dependencies=[Depends(verify_admin)])
async def add_to_whitelist(ip: str):
    whitelist_manager.add(ip)
    return {"message": f"IP {ip} whitelisted."}

@app.delete("/admin/whitelist/{ip}", dependencies=[Depends(verify_admin)])
async def remove_from_whitelist(ip: str):
    whitelist_manager.remove(ip)
    return {"message": f"IP {ip} removed from whitelist."}
