"""Pluggable storage backends for request tracking.

The default :class:`InMemoryStore` uses plain dicts—swap in
:class:`RedisStore` (or any other :class:`BaseStore` subclass) when
you need cross-process / distributed state.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict


class BaseStore(ABC):
    """Contract for a request-tracking store.

    Every backend must support three operations:
    1. **append** — record a timestamp for an IP.
    2. **prune** — discard entries older than a cutoff.
    3. **get_timestamps** — return the surviving timestamps (sorted).
    """

    @abstractmethod
    def append(self, ip: str, timestamp: float) -> None:
        """Record a new request timestamp for *ip*."""

    @abstractmethod
    def prune(self, ip: str, cutoff: float) -> None:
        """Remove all timestamps for *ip* that are ≤ *cutoff*."""

    @abstractmethod
    def get_timestamps(self, ip: str) -> list[float]:
        """Return timestamps for *ip*, oldest-first."""


class InMemoryStore(BaseStore):
    """Dictionary-backed store.  Fast, single-process, zero dependencies.

    Suitable for development and single-worker deployments.  For
    multi-worker or distributed setups, replace with a Redis-backed
    implementation that follows the same :class:`BaseStore` interface.
    """

    def __init__(self) -> None:
        self._data: dict[str, list[float]] = defaultdict(list)

    def append(self, ip: str, timestamp: float) -> None:
        self._data[ip].append(timestamp)

    def prune(self, ip: str, cutoff: float) -> None:
        self._data[ip] = [t for t in self._data[ip] if t > cutoff]

    def get_timestamps(self, ip: str) -> list[float]:
        return self._data[ip]

    # --- Housekeeping (optional, useful for monitoring) ---

    @property
    def tracked_ips(self) -> int:
        """Number of IPs currently tracked."""
        return len(self._data)

    def clear(self, ip: str | None = None) -> None:
        """Drop tracking data for *ip*, or all IPs if *ip* is None."""
        if ip is None:
            self._data.clear()
        else:
            self._data.pop(ip, None)


class RedisStore(BaseStore):
    """Redis-backed store for distributed deployments."""

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        import redis
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = "feature_store:"

    def append(self, ip: str, timestamp: float) -> None:
        key = f"{self._prefix}{ip}"
        self._client.zadd(key, {str(timestamp): timestamp})

    def prune(self, ip: str, cutoff: float) -> None:
        key = f"{self._prefix}{ip}"
        self._client.zremrangebyscore(key, "-inf", cutoff)

    def get_timestamps(self, ip: str) -> list[float]:
        key = f"{self._prefix}{ip}"
        results = self._client.zrange(key, 0, -1)
        return [float(x) for x in results]

