"""Structured JSON logging for FlowraAI requests and security signals.

Aggregates behavioral features, ML scores, and decision reasoning into
a machine-readable format ready for ELK/Dashboard ingestion.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

LOG_FILE = "logs/security_audit.json"

# Ensure log directory exists
os.makedirs("logs", exist_ok=True)


def log_request(
    ip: str,
    latency: float,
    risk_score: float,
    action: str,
    anomaly_score: Optional[float] = None,
    deviation_score: Optional[float] = None,
    injection_score: Optional[float] = None,
    features: Optional[Dict[str, Any]] = None,
    reasoning: str = "N/A",
) -> None:
    """Audit a single request and its security metadata to the log file."""
    audit_entry = {
        "timestamp": time.time(),
        "ip": ip,
        "latency_sec": round(latency, 4),
        "verdict": {
            "action": action,
            "risk_score": round(risk_score, 4),
            "reasoning": reasoning,
        },
        "signals": {
            "anomaly_score": round(anomaly_score, 4) if anomaly_score is not None else 0.0,
            "deviation_score": round(deviation_score, 4) if deviation_score is not None else 0.0,
            "injection_score": round(injection_score, 4) if injection_score is not None else 0.0,
        },
        "features": features or {},
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(audit_entry) + "\n")