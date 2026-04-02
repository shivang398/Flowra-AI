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
