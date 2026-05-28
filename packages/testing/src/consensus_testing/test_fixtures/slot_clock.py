"""Slot clock test fixture for timing conformance testing.

Generates JSON test vectors that verify slot/interval computation from
wall-clock timestamps. Every client must compute identical slot boundaries
to coordinate block proposals and attestations.
"""

from typing import Any, ClassVar

from lean_spec.node.chain.clock import Interval, SlotClock
from lean_spec.node.chain.config import (
    INTERVALS_PER_SLOT,
    MILLISECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.spec.forks import Slot
from lean_spec.spec.ssz import Uint64

from .base import BaseConsensusFixture


class SlotClockTest(BaseConsensusFixture):
    """Fixture for slot clock timing conformance.

    Tests time-to-slot and time-to-interval conversions that every
    consensus client must implement identically.

    JSON output: operation, input, config, output.
    """

    format_name: ClassVar[str] = "slot_clock"
    description: ClassVar[str] = "Tests slot clock time-to-slot/interval conversion"

    operation: str
    """Operation under test: from_unix_time, from_slot, current_slot,
    current_interval, or total_intervals."""

    input: dict[str, Any]
    """Operation-specific input parameters."""

    output: dict[str, Any] = {}
    """Computed output. Filled by make_fixture."""

    def make_fixture(self) -> "SlotClockTest":
        """Dispatch to the operation handler and produce computed output."""
        config = {
            "secondsPerSlot": int(SECONDS_PER_SLOT),
            "intervalsPerSlot": int(INTERVALS_PER_SLOT),
            "millisecondsPerInterval": int(MILLISECONDS_PER_INTERVAL),
        }
        match self.operation:
            case "from_unix_time":
                result = self._make_from_unix_time()
            case "from_slot":
                result = self._make_from_slot()
            case "current_slot":
                result = self._make_current_slot()
            case "current_interval":
                result = self._make_current_interval()
            case "total_intervals":
                result = self._make_total_intervals()
            case _:
                raise ValueError(f"Unknown operation: {self.operation}")
        self.output = {"config": config, **result}
        return self

    def _make_from_unix_time(self) -> dict[str, Any]:
        """Convert unix timestamp to interval count since genesis."""
        unix_seconds = Uint64(self.input["unixSeconds"])
        genesis_time = Uint64(self.input["genesisTime"])
        interval = Interval.from_unix_time(unix_seconds, genesis_time)
        return {"interval": int(interval)}

    def _make_from_slot(self) -> dict[str, Any]:
        """Convert slot number to interval at that slot's start."""
        slot = Slot(self.input["slot"])
        interval = Interval.from_slot(slot)
        return {"interval": int(interval)}

    def _make_current_slot(self) -> dict[str, Any]:
        """Compute current slot from genesis time and current timestamp."""
        genesis_time = Uint64(self.input["genesisTime"])
        current_time = float(self.input["currentTimeMs"]) / 1000.0
        clock = SlotClock(genesis_time=genesis_time, time_fn=lambda: current_time)
        return {"slot": int(clock.current_slot())}

    def _make_current_interval(self) -> dict[str, Any]:
        """Compute current interval within the slot (0-4)."""
        genesis_time = Uint64(self.input["genesisTime"])
        current_time = float(self.input["currentTimeMs"]) / 1000.0
        clock = SlotClock(genesis_time=genesis_time, time_fn=lambda: current_time)
        return {"interval": int(clock.current_interval())}

    def _make_total_intervals(self) -> dict[str, Any]:
        """Compute total intervals elapsed since genesis."""
        genesis_time = Uint64(self.input["genesisTime"])
        current_time = float(self.input["currentTimeMs"]) / 1000.0
        clock = SlotClock(genesis_time=genesis_time, time_fn=lambda: current_time)
        return {"totalIntervals": int(clock.total_intervals())}
