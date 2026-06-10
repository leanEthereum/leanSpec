"""Interval time unit for the Lean consensus specification."""

from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT
from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import Uint64


class Interval(Uint64):
    """Interval count since genesis."""

    @classmethod
    def from_slot(cls, slot: Slot) -> "Interval":
        """
        Convert a slot number to the interval at that slot's start.

        Each slot spans a fixed number of intervals.
        This gives the first interval of the given slot.

        Args:
            slot: Slot number since genesis.

        Returns:
            Interval count at the start of the given slot.
        """
        # Slot boundaries fall on exact multiples of the interval count.
        #
        # The two values are distinct unsigned types, so drop to plain ints to multiply.
        return cls(int(slot) * int(INTERVALS_PER_SLOT))
