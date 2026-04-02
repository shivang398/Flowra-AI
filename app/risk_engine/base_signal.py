"""Abstract base class for all risk signals."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.risk_engine.models import SignalResult


class BaseSignal(ABC):
    """Every risk signal must subclass this and implement :meth:`evaluate`.

    A signal receives a *context* dict (IP, payload, timestamps, etc.)
    and returns a :class:`SignalResult` with a score between 0 and 1.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this signal."""

    @property
    def weight(self) -> float:
        """Relative weight of this signal during aggregation (default 1.0)."""
        return 1.0

    @abstractmethod
    def evaluate(self, ctx: dict) -> SignalResult:
        """Compute the signal score for the given request context.

        Parameters
        ----------
        ctx : dict
            Must contain at minimum ``ip`` (str).
            Signals may also read ``payload_bytes`` (int),
            ``timestamp`` (float), and any future keys.
        """
