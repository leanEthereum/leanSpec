"""Slot clock test fixture for timing conformance testing."""

from typing import Annotated, ClassVar, Literal

from pydantic import Field

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.base import StrictBaseModel
from lean_spec.node.chain.clock import SlotClock
from lean_spec.spec.forks import Interval, Slot
from lean_spec.spec.forks.lstar.config import (
    INTERVALS_PER_SLOT,
    MILLISECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.spec.ssz import Uint64


class SlotClockConfig(StrictBaseModel):
    """Timing constants every conversion in the vector assumes."""

    seconds_per_slot: int
    """Wall-clock seconds per slot."""

    intervals_per_slot: int
    """Sub-slot intervals per slot."""

    milliseconds_per_interval: int
    """Wall-clock milliseconds per interval."""


class IntervalOutput(StrictBaseModel):
    """Computed interval count."""

    interval: int
    """Interval count the client must reproduce."""


class SlotOutput(StrictBaseModel):
    """Computed slot number."""

    slot: int
    """Slot number the client must reproduce."""


class TotalIntervalsOutput(StrictBaseModel):
    """Computed total interval count since genesis."""

    total_intervals: int
    """Total intervals elapsed since genesis."""


class FromUnixTime(StrictBaseModel):
    """Convert a unix timestamp to the interval count since genesis."""

    kind: Literal["from_unix_time"] = "from_unix_time"
    """Discriminator field for serialization."""

    genesis_time: int
    """Unix genesis timestamp in seconds."""

    unix_seconds: float
    """Wall-clock timestamp to convert."""

    def run(self) -> IntervalOutput:
        """Compute intervals since genesis at the given timestamp."""
        clock = SlotClock(genesis_time=Uint64(self.genesis_time), time_fn=lambda: self.unix_seconds)
        return IntervalOutput(interval=int(clock.total_intervals()))


class FromSlot(StrictBaseModel):
    """Convert a slot number to the interval at that slot's start."""

    kind: Literal["from_slot"] = "from_slot"
    """Discriminator field for serialization."""

    slot: int
    """Slot number to convert."""

    def run(self) -> IntervalOutput:
        """Compute the interval at the slot's start."""
        return IntervalOutput(interval=int(Interval.from_slot(Slot(self.slot))))


class CurrentSlot(StrictBaseModel):
    """Compute the current slot from genesis time and a wall-clock timestamp."""

    kind: Literal["current_slot"] = "current_slot"
    """Discriminator field for serialization."""

    genesis_time: int
    """Unix genesis timestamp in seconds."""

    current_time_milliseconds: float
    """Wall-clock timestamp in milliseconds."""

    def run(self) -> SlotOutput:
        """Compute the current slot at the given timestamp."""
        clock = SlotClock(
            genesis_time=Uint64(self.genesis_time),
            time_fn=lambda: self.current_time_milliseconds / 1000.0,
        )
        return SlotOutput(slot=int(clock.current_slot()))


class CurrentInterval(StrictBaseModel):
    """Compute the current interval within the slot."""

    kind: Literal["current_interval"] = "current_interval"
    """Discriminator field for serialization."""

    genesis_time: int
    """Unix genesis timestamp in seconds."""

    current_time_milliseconds: float
    """Wall-clock timestamp in milliseconds."""

    def run(self) -> IntervalOutput:
        """Compute the in-slot interval at the given timestamp."""
        clock = SlotClock(
            genesis_time=Uint64(self.genesis_time),
            time_fn=lambda: self.current_time_milliseconds / 1000.0,
        )
        return IntervalOutput(interval=int(clock.current_interval()))


class TotalIntervals(StrictBaseModel):
    """Compute the total intervals elapsed since genesis."""

    kind: Literal["total_intervals"] = "total_intervals"
    """Discriminator field for serialization."""

    genesis_time: int
    """Unix genesis timestamp in seconds."""

    current_time_milliseconds: float
    """Wall-clock timestamp in milliseconds."""

    def run(self) -> TotalIntervalsOutput:
        """Compute total intervals since genesis at the given timestamp."""
        clock = SlotClock(
            genesis_time=Uint64(self.genesis_time),
            time_fn=lambda: self.current_time_milliseconds / 1000.0,
        )
        return TotalIntervalsOutput(total_intervals=int(clock.total_intervals()))


SlotClockOperation = Annotated[
    FromUnixTime | FromSlot | CurrentSlot | CurrentInterval | TotalIntervals,
    Field(discriminator="kind"),
]
"""Discriminated union of every slot clock conversion under test."""

SlotClockOutput = IntervalOutput | SlotOutput | TotalIntervalsOutput
"""Union of the computed results, paired with the operation kind."""


class SlotClockFixture(BaseConsensusFixture):
    """
    Emitted vector for slot clock timing conformance.

    JSON output: operation, config, output.
    """

    operation: SlotClockOperation
    """Conversion under test, with its typed inputs."""

    config: SlotClockConfig
    """Timing constants the conversion assumes."""

    output: SlotClockOutput
    """Computed result the client must reproduce."""


class SlotClockTest(BaseTestSpec):
    """
    Spec for slot clock timing conformance.

    Tests time-to-slot and time-to-interval conversions that every
    consensus client must implement identically.
    """

    format_name: ClassVar[str] = "slot_clock_test"
    description: ClassVar[str] = "Tests slot clock time-to-slot/interval conversion"

    operation: SlotClockOperation
    """Conversion to run, with its typed inputs."""

    def generate(self) -> SlotClockFixture:
        """Run the conversion and emit the vector."""
        return SlotClockFixture(
            operation=self.operation,
            config=SlotClockConfig(
                seconds_per_slot=int(SECONDS_PER_SLOT),
                intervals_per_slot=int(INTERVALS_PER_SLOT),
                milliseconds_per_interval=int(MILLISECONDS_PER_INTERVAL),
            ),
            output=self.operation.run(),
        )
