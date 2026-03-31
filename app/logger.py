import json
import time
import os

LOG_FILE = "logs/logs.json"

os.makedirs("logs", exist_ok=True)


def log_request(latency, risk, action):
    log = {
        "timestamp": time.time(),
        "latency": latency,
        "risk": risk,
        "action": action
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")