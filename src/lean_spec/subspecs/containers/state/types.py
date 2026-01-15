"""State-specific SSZ types for the Lean Ethereum consensus specification."""

from __future__ import annotations

from lean_spec.subspecs.chain.config import DEVNET_CONFIG
from lean_spec.types import Boolean, Bytes32, SSZList
from lean_spec.types.bitfields import BaseBitlist

from ..slot import Slot
from ..validator import Validator


class HistoricalBlockHashes(SSZList[Bytes32]):
    """List of historical block root hashes up to historical_roots_limit."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustificationRoots(SSZList[Bytes32]):
    """List of justified block roots up to historical_roots_limit."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustifiedSlots(BaseBitlist):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)

    def is_slot_justified(self, finalized_slot: Slot, target_slot: Slot) -> bool:
        """
        Check whether a slot is justified, relative to a finalized boundary.

        Slots at or before the finalized boundary are treated as justified.
        """
        idx = target_slot.justified_index_after(finalized_slot)
        if idx is None:
            return True

        if idx >= len(self):
            raise IndexError(
                "Justified slot index out of bounds "
                f"(idx={idx}, len={len(self)}, slot={target_slot}, finalized_slot={finalized_slot})"
            )

        return bool(self[idx])

    def set_justified(self, finalized_slot: Slot, target_slot: Slot, value: bool | Boolean) -> None:
        """
        Set justification status for a slot, relative to a finalized boundary.

        Writes to slots at or before the finalized boundary are ignored.
        """
        idx = target_slot.justified_index_after(finalized_slot)
        if idx is None:
            return

        if idx >= len(self):
            raise IndexError(
                "Justified slot index out of bounds "
                f"(idx={idx}, len={len(self)}, slot={target_slot}, finalized_slot={finalized_slot})"
            )

        self[idx] = value

    def extend_to_slot(self, finalized_slot: Slot, target_slot: Slot) -> JustifiedSlots:
        """
        Extend the tracking capacity to cover a new target slot.

        This prepares the state to process a new block by ensuring the
        bitfield is long enough to store its justification status.
        Gaps are filled with False (unjustified).

        Args:
            finalized_slot: The anchor point for the tracking window.
            target_slot: The slot that must be addressable.

        Returns:
            A new instance with sufficient capacity.
        """
        # Calculate the index required to store the status of the target.
        #
        # If the target is already finalized, no extension is needed because
        # we don't track finalized data.
        if (relative_index := target_slot.justified_index_after(finalized_slot)) is None:
            return self

        # Calculate how many new entries we need to append.
        #
        # Since indices are zero-based, the required capacity is index + 1.
        # If we already have enough capacity, the gap will be zero or negative.
        required_capacity = relative_index + 1
        if (gap_size := required_capacity - len(self)) <= 0:
            return self

        # Return a new instance with the extended data list.
        #
        # We extend the existing data with False values to bridge the gap.
        return self.model_copy(
            update={"data": list(self.data) + [Boolean(False)] * gap_size}
        )

    def shift_window(self, delta: int) -> JustifiedSlots:
        """
        Advance the tracking window by dropping slots that became finalized.

        A non-positive delta keeps the tracking window unchanged.
        """
        if delta <= 0:
            return self

        return JustifiedSlots(data=self.data[delta:])


class JustificationValidators(BaseBitlist):
    """Bitlist for tracking validator justifications per historical root."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit) * int(DEVNET_CONFIG.validator_registry_limit)


class Validators(SSZList[Validator]):
    """Validator registry tracked in the state."""

    LIMIT = int(DEVNET_CONFIG.validator_registry_limit)
