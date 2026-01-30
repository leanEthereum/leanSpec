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

from .config import MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT

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

    time_fn: Callable[[], float] = wall_time
    """Time source function (injectable for testing)."""

    def _seconds_since_genesis(self) -> Uint64:
        """Seconds elapsed since genesis (0 if before genesis)."""
        now = self.current_time()
        if now < self.genesis_time:
            return Uint64(0)
        return now - self.genesis_time

    def _milliseconds_since_genesis(self) -> Uint64:
        """Milliseconds elapsed since genesis (0 if before genesis)."""
        return self._seconds_since_genesis() * Uint64(1000)

    def current_slot(self) -> Slot:
        """Get the current slot number (0 if before genesis)."""
        return Slot(self._milliseconds_since_genesis() // MILLISECONDS_PER_SLOT)

    def current_interval(self) -> Interval:
        """Get the current interval within the slot (0-3)."""
        milliseconds_into_slot = self._milliseconds_since_genesis() % MILLISECONDS_PER_SLOT
        return milliseconds_into_slot // MILLISECONDS_PER_INTERVAL

    def total_intervals(self) -> Interval:
        """
        Get total intervals elapsed since genesis.

        This is the value expected by our store time type.
        """
        return self._milliseconds_since_genesis() // MILLISECONDS_PER_INTERVAL

    def current_time(self) -> Uint64:
        """Get current wall-clock time as Uint64 (Unix timestamp in seconds)."""
        return Uint64(int(self.time_fn()))

    def seconds_until_next_interval(self) -> float:
        """
        Calculate seconds until the next interval boundary.

        Returns time until genesis if before genesis.
        Returns 0.0 if exactly at an interval boundary.
        """
        now = self.time_fn()
        genesis = int(self.genesis_time)
        elapsed = now - genesis

        if elapsed < 0:
            # Before genesis - return time until genesis.
            return -elapsed

        # Convert to milliseconds and find time into current interval.
        elapsed_ms = int(elapsed * 1000)
        time_into_interval_ms = elapsed_ms % int(MILLISECONDS_PER_INTERVAL)

        # Time until next boundary (may be 0 if exactly at boundary).
        ms_until_next = int(MILLISECONDS_PER_INTERVAL) - time_into_interval_ms
        return ms_until_next / 1000.0
