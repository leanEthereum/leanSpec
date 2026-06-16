"""Consensus state and the justification/finalization accounting it tracks."""

from typing import Self

from lean_spec.spec.forks.lstar.config import HISTORICAL_ROOTS_LIMIT, VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.block import BlockHeader
from lean_spec.spec.forks.lstar.containers.checkpoint import Checkpoint
from lean_spec.spec.forks.lstar.containers.genesis import GenesisConfig
from lean_spec.spec.forks.lstar.containers.validator import Validators
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import Boolean, Bytes32, Container, SSZList
from lean_spec.spec.ssz.bitfields import BaseBitlist


class HistoricalBlockHashes(SSZList[Bytes32]):
    """List of historical block root hashes up to historical roots limit."""

    LIMIT = int(HISTORICAL_ROOTS_LIMIT)


class JustificationRoots(SSZList[Bytes32]):
    """List of justified block roots up to historical roots limit."""

    LIMIT = int(HISTORICAL_ROOTS_LIMIT)


class JustifiedSlots(BaseBitlist):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = int(HISTORICAL_ROOTS_LIMIT)

    def is_slot_justified(self, finalized_slot: Slot, target_slot: Slot) -> Boolean:
        """
        Determine if a specific slot is considered justified.

        The check follows these rules:
        - Slots at or before the finalized boundary are implicitly justified.
        - Future slots are checked against the tracked bitfield.

        Args:
            finalized_slot: The anchor point for the tracking window.
            target_slot: The slot to query.

        Returns:
            True if the slot is justified or finalized, False otherwise.

        Raises:
            SpecRejectionError: JUSTIFIED_SLOT_OUT_OF_RANGE if the target slot is active
                but outside the tracked range.
        """
        # First, determine the position of the target relative to the anchor.
        #
        # If the result is None, the slot is behind the finalized boundary.
        # By definition, finalized slots are justified.
        if (relative_index := target_slot.justified_index_after(finalized_slot)) is None:
            return Boolean(True)

        # Check the tracked bitfield for the slot's status.
        #
        # We assume the slot is within the tracked range.
        #
        # If the caller asks for a slot too far in the future, it indicates a logic error.
        # Surface it as a domain rejection so the uniform rejection funnel catches it,
        # rather than a bare index error escaping a block-processing path.
        try:
            return self[relative_index]
        except IndexError as exception:
            raise SpecRejectionError(
                RejectionReason.JUSTIFIED_SLOT_OUT_OF_RANGE,
                f"Slot {target_slot} is outside the tracked range "
                f"(finalized_boundary={finalized_slot}, tracked_length={len(self)})",
            ) from exception

    def extend_to_slot(self, finalized_slot: Slot, target_slot: Slot) -> Self:
        """
        Extend the tracking capacity to cover a new target slot.

        Slots between the old end and the target are filled with False.

        Args:
            finalized_slot: The anchor point for the tracking window.
            target_slot: The slot that must be addressable.

        Returns:
            A new instance with sufficient capacity.
        """
        # A finalized target has no tracked index, so nothing to extend.
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
        return type(self)(data=list(self.data) + [Boolean(False)] * gap_size)


class JustificationValidators(BaseBitlist):
    """Per-root validator vote bitfields, concatenated into one flat bitlist."""

    LIMIT = int(HISTORICAL_ROOTS_LIMIT) * int(VALIDATOR_REGISTRY_LIMIT)
    """One bit per tracked-root and registered-validator pair."""


class State(Container):
    """The main consensus state object."""

    # Configuration
    config: GenesisConfig
    """The chain's configuration parameters."""

    # Slot and block tracking
    slot: Slot
    """The current slot number."""

    latest_block_header: BlockHeader
    """The header of the most recent block."""

    # Checkpoints
    latest_justified: Checkpoint
    """The latest justified checkpoint."""

    latest_finalized: Checkpoint
    """The latest finalized checkpoint."""

    # Historical data
    historical_block_hashes: HistoricalBlockHashes
    """A list of historical block root hashes."""

    justified_slots: JustifiedSlots
    """A bitfield indicating which historical slots were justified."""

    validators: Validators
    """Registry of validators tracked by the state."""

    # Justification tracking (flattened for SSZ compatibility)
    justifications_roots: JustificationRoots
    """Roots of justified blocks."""

    justifications_validators: JustificationValidators
    """A bitlist of validators who participated in justifications."""
