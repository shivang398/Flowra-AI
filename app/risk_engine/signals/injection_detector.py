import re
import logging
from app.risk_engine.base_signal import BaseSignal
from app.risk_engine.models import SignalResult

logger = logging.getLogger(__name__)

class PromptInjectionSignal(BaseSignal):
    """Detects prompt injection attempts in the request payload.
    
    Uses heuristic pattern matching for common jailbreak techniques.
    """
    
    # Common jailbreak patterns
    PATTERNS = [
        r"ignore all previous instructions",
        r"disregard all previous instructions",
        r"system override",
        r"you are now a",  # Persona adoption
        r"dan mode",        # "Do Anything Now"
        r"jailbreak",
        r"repeat everything above",
        r"show me your system prompt",
        r"forget what you were told",
        r"bypass safety",
        r"do not mention",
    ]

    def __init__(self, weight: float = 2.0):
        self._weight = weight
        self._regex = [re.compile(p, re.IGNORECASE) for p in self.PATTERNS]

    @property
    def name(self) -> str:
        return "prompt_injection"

    @property
    def weight(self) -> float:
        return self._weight

    def evaluate(self, ctx: dict) -> SignalResult:
        # We need the actual data from InputData
        # ctx should contain 'payload_content' or similar
        data = ctx.get("payload_content", [])
        
        # Flatten data to a string for scanning
        text = str(data).lower()
        
        matches = []
        score = 0.0
        
        for i, pattern in enumerate(self._regex):
            if pattern.search(text):
                matches.append(self.PATTERNS[i])
                score += 0.4  # Each unique pattern adds to the score
        
        score = min(1.0, score)
        
        detail = "No injection detected"
        if matches:
            detail = f"Potential injection patterns found: {', '.join(matches)}"
            logger.warning(f"Prompt injection detected from IP {ctx.get('ip')}: {detail}")

        return SignalResult(
            name=self.name,
            score=score,
            weight=self._weight,
            detail=detail
        )
