"""Slot primitive shared by the consensus and crypto layers."""

import math
from typing import Final

from lean_spec.spec.ssz import Uint64

IMMEDIATE_JUSTIFICATION_WINDOW: Final = 5
"""First N slots after finalization are always justifiable."""


class Slot(Uint64):
    """A slot number, as a 64-bit unsigned integer."""

    def justified_index_after(self, finalized_slot: "Slot") -> int | None:
        """
        Return the relative bitfield index for justification tracking.

        Slots at or before the finalized boundary are treated as justified.
        Those slots do not have an index in the tracked bitfield.
        """
        if self <= finalized_slot:
            return None

        # Slot (finalized_slot + 1) maps to index 0.
        return int(self - finalized_slot) - 1

    def is_justifiable_after(self, finalized_slot: "Slot") -> bool:
        """
        Whether this slot is a valid justification candidate after a given finalized slot.

        According to the 3SF-mini specification, a slot is justifiable if its
        distance (delta) from the last finalized slot is:
          1. Less than or equal to 5.
          2. A perfect square (e.g., 9, 16, 25...).
          3. A pronic number (of the form x^2 + x, e.g., 6, 12, 20...).

        Args:
            finalized_slot: The last slot that was finalized.

        Returns:
            True if the slot is justifiable, False otherwise.

        Raises:
            AssertionError: If this slot is earlier than the finalized slot.
        """
        # Ensure the candidate slot is not before the finalized slot.
        assert self >= finalized_slot, "Candidate slot must not be before finalized slot"

        # Calculate the distance in slots from the last finalized slot.
        # Convert to int for pure arithmetic operations below.
        delta = int(self - finalized_slot)

        # Rule 1: The first N slots after finalization are always justifiable.
        #
        # Examples: delta = 0, 1, 2, 3, 4, 5
        # Most justifiable slots fall here, so check it before any square root.
        if delta <= IMMEDIATE_JUSTIFICATION_WINDOW:
            return True

        # Rule 2: Slots at perfect square distances are justifiable.
        #
        # Examples: delta = 1, 4, 9, 16, 25, 36, 49, 64, ...
        # Check: integer square root squared equals delta
        if math.isqrt(delta) ** 2 == delta:
            return True

        # Rule 3: Slots at pronic number distances are justifiable.
        #
        # Pronic numbers have the form n(n+1): 2, 6, 12, 20, 30, 42, 56, ...
        # Mathematical insight: For pronic delta = n(n+1), we have:
        #   4*delta + 1 = 4n(n+1) + 1 = (2n+1)^2
        # Check: 4*delta+1 is an odd perfect square
        pronic_discriminant = 4 * delta + 1
        discriminant_root = math.isqrt(pronic_discriminant)
        return discriminant_root**2 == pronic_discriminant and discriminant_root % 2 == 1
