"""Structured JSON logging for SentinelAI requests and security signals.

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
    latency: float,
    risk_score: float,
    action: str,
    anomaly_score: Optional[float] = None,
    deviation_score: Optional[float] = None,
    features: Optional[Dict[str, Any]] = None,
    reasoning: str = "N/A",
) -> None:
    """Audit a single request and its security metadata to the log file.

    Parameters
    ----------
    latency : float
        End-to-end processing time in seconds.
    risk_score : float
        Aggregated risk score [0, 1].
    action : str
        Final decision: "allow" | "throttle" | "block".
    anomaly_score : float | None
        ML anomaly detection score.
    deviation_score : float | None
        Behavioral fingerprinting deviation score.
    features : dict | None
        Raw behavioral features (frequency, interval, etc.).
    reasoning : str
        Human-readable text explaining the Decision Engine's action.
    """
    audit_entry = {
        "timestamp": time.time(),
        "latency_sec": round(latency, 4),
        "verdict": {
            "action": action,
            "risk_score": round(risk_score, 4),
            "reasoning": reasoning,
        },
        "signals": {
            "anomaly_score": round(anomaly_score, 4) if anomaly_score is not None else 0.0,
            "deviation_score": round(deviation_score, 4) if deviation_score is not None else 0.0,
        },
        "features": features or {},
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(audit_entry) + "\n")