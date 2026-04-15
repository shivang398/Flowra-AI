"""Pluggable storage backends for behavioral fingerprints."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict

from app.fingerprint.models import FingerprintBaseline


class BaseFingerprintStore(ABC):
    """Abstract interface for storing per-IP behavioral baselines."""

    @abstractmethod
    def get(self, ip: str) -> FingerprintBaseline:
        """Retrieve the current baseline for *ip*."""

    @abstractmethod
    def set(self, ip: str, baseline: FingerprintBaseline) -> None:
        """Update the stored baseline for *ip*."""


class InMemoryFingerprintStore(BaseFingerprintStore):
    """Dictionary-backed baseline store."""

    def __init__(self) -> None:
        self._data: Dict[str, FingerprintBaseline] = {}

    def get(self, ip: str) -> FingerprintBaseline:
        return self._data.get(ip, FingerprintBaseline())

    def set(self, ip: str, baseline: FingerprintBaseline) -> None:
        self._data[ip] = baseline


class RedisFingerprintStore(BaseFingerprintStore):
    """Redis-backed baseline store for distributed deployments."""

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        import redis
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = "fingerprint_store:"

    def get(self, ip: str) -> FingerprintBaseline:
        import json
        import redis
        key = f"{self._prefix}{ip}"
        try:
            data = self._client.get(key)
            if data:
                return FingerprintBaseline(**json.loads(data))
        except redis.RedisError as e:
            # Fallback smoothly on failure
            pass
        return FingerprintBaseline()

    def set(self, ip: str, baseline: FingerprintBaseline) -> None:
        import json
        import redis
        from dataclasses import asdict
        key = f"{self._prefix}{ip}"
        try:
            self._client.set(key, json.dumps(asdict(baseline)))
        except redis.RedisError as e:
            pass
