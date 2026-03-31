from fastapi import FastAPI, Request, Depends, HTTPException
from pydantic import BaseModel
import time

from app.auth import verify_token
from app.security import compute_risk, decide_action
from app.model import predict
from app.logger import log_request

app = FastAPI()


class InputData(BaseModel):
    data: list


@app.get("/")
def root():
    return {"message": "SentinelAI running 🚀"}


@app.post("/predict")
async def secure_predict(
    input: InputData,
    request: Request,
    user=Depends(verify_token)
):
    start = time.time()

    ip = request.client.host

    # 🧠 Risk scoring
    risk = compute_risk(ip)
    action = decide_action(risk)

    if action == "block":
        raise HTTPException(status_code=403, detail="Blocked: suspicious activity")

    elif action == "throttle":
        time.sleep(1)

    # 🤖 Inference
    result = predict(input.data)

    latency = time.time() - start

    # 📊 Logging
    log_request(latency, risk, action)

    return {
        "prediction": result,
        "risk_score": risk,
        "action": action,
        "latency": latency
    }