import time
import math
import asyncio
import os
import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class TokenBucket:
    """Per-IP Token Bucket for rate limiting.
    
    Tokens regenerate at a fixed rate. Burst capacity allows for brief spikes.
    """
    def __init__(self, rate: float = 10.0, capacity: float = 20.0):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        # In-memory storage: {ip: (tokens, last_update)}
        self._buckets: Dict[str, Tuple[float, float]] = {}

    def consume(self, ip: str, amount: float = 1.0) -> bool:
        now = time.time()
        tokens, last_update = self._buckets.get(ip, (self.capacity, now))
        
        # Regenerate tokens based on elapsed time
        elapsed = now - last_update
        tokens = min(self.capacity, tokens + elapsed * self.rate)
        
        if tokens >= amount:
            tokens -= amount
            self._buckets[ip] = (tokens, now)
            return True
        
        self._buckets[ip] = (tokens, now)
        return False

class ExponentialBackoff:
    """Tracks consecutive throttle hits per-IP and computes escalating delays."""
    def __init__(self, base_delay: float = 1.0, max_delay: float = 30.0, window_sec: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.window_sec = window_sec
        # {ip: (consecutive_hits, last_hit_ts)}
        self._hits: Dict[str, Tuple[int, float]] = {}

    def get_delay(self, ip: str, is_throttle_hit: bool) -> float:
        now = time.time()
        hits, last_ts = self._hits.get(ip, (0, 0.0))
        
        # Reset if the window has passed without a hit
        if now - last_ts > self.window_sec:
            hits = 0

        if is_throttle_hit:
            hits += 1
            delay = min(self.max_delay, self.base_delay * (2**(hits - 1)))
            self._hits[ip] = (hits, now)
            return delay
        
        # If it's not a throttle hit (i.e. 'allow'), slowly decay or reset hits
        # For simplicity, we just reset on a successful 'allow' in this version
        self._hits[ip] = (0, now)
        return 0.0

class RateLimitEnforcer:
    """Orchestrates token bucket and exponential backoff."""
    def __init__(self):
        self.bucket = TokenBucket()
        self.backoff = ExponentialBackoff()

    async def enforce(self, ip: str, action: str) -> str:
        """Enforces rate limiting and backoff.
        
        Returns the final action (might override 'throttle' with 'block' if backoff is extreme).
        """
        # 1. Check Token Bucket (Sustained Rate)
        if not self.bucket.consume(ip):
            logger.warning(f"Rate limit exceeded for IP {ip}")
            return "rate_limit"

        # 2. Check Exponential Backoff for 'throttle' actions
        if action == "throttle":
            delay = self.backoff.get_delay(ip, True)
            logger.info(f"Throttling IP {ip} for {delay:.2f}s (exponential backoff)")
            await asyncio.sleep(delay)
            return "throttle"
        
        # Reset backoff on 'allow'
        if action == "allow":
            self.backoff.get_delay(ip, False)

        return action

# Global instance for the app
rate_enforcer = RateLimitEnforcer()
