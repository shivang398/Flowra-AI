"""Backward-compatible shim.

The real logic now lives in :mod:`app.risk_engine` + :mod:`app.feature_extractor`.
Existing imports like ``from app.security import compute_risk, decide_action``
will continue to work, but new code should use ``RiskEngine`` directly.
"""

from app.risk_engine import RiskEngine

_engine = RiskEngine()


def compute_risk(ip: str) -> float:
    """Legacy API — returns a single float risk score."""
    verdict = _engine.evaluate({"ip": ip})
    return verdict.risk_score


def decide_action(risk: float) -> str:
    """Legacy API — maps a risk float to an action string."""
    if risk >= 0.7:
        return "block"
    if risk >= 0.3:
        return "throttle"
    return "allow"