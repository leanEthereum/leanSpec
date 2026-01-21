"""
Slot Clock
==========

Time-to-slot conversion for Lean Consensus.

The slot clock bridges wall-clock time to the discrete slot-based time
model used by consensus. Every node must agree on slot boundaries to
coordinate block proposals and attestations.
"""

from dataclasses import dataclass
from time import time as wall_time
from typing import Callable

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Uint64

from .config import SECONDS_PER_INTERVAL, SECONDS_PER_SLOT

Interval = Uint64
"""Interval count since genesis (matches ``Store.time``)."""


@dataclass(frozen=True, slots=True)
class SlotClock:
    """
    Converts wall-clock time to consensus slots and intervals.

    All time values are in seconds (Unix timestamps).
    """

    genesis_time: Uint64
    """Unix timestamp (seconds) when slot 0 began."""

    _time_fn: Callable[[], float] = wall_time
    """Time source function (injectable for testing)."""

    def _seconds_since_genesis(self) -> Uint64:
        """Seconds elapsed since genesis (0 if before genesis)."""
        now = Uint64(int(self._time_fn()))
        if now < self.genesis_time:
            return Uint64(0)
        return now - self.genesis_time

    def current_slot(self) -> Slot:
        """Get the current slot number (0 if before genesis)."""
        return Slot(self._seconds_since_genesis() // SECONDS_PER_SLOT)

    def current_interval(self) -> Interval:
        """Get the current interval within the slot (0-3)."""
        seconds_into_slot = self._seconds_since_genesis() % SECONDS_PER_SLOT
        return seconds_into_slot // SECONDS_PER_INTERVAL

    def total_intervals(self) -> Interval:
        """
        Get total intervals elapsed since genesis.

        This is the value expected by our store time type.
        """
        return self._seconds_since_genesis() // SECONDS_PER_INTERVAL
