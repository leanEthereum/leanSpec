"""The container types for the Lean consensus specification."""

import math
from typing import Final, Self

from lean_spec.spec.ssz import Boolean, ByteList512KiB, Bytes32, Bytes52, Container, SSZList, Uint64
from lean_spec.spec.ssz.bitfields import BaseBitlist

VALIDATOR_REGISTRY_LIMIT: Final = Uint64(2**12)
"""The maximum number of validators that can be in the registry."""

IMMEDIATE_JUSTIFICATION_WINDOW: Final = 5
"""First N slots after finalization are always justifiable."""


class Slot(Uint64):
    """Represents a slot number as a 64-bit unsigned integer."""

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
        Checks if this slot is a valid candidate for justification after a given finalized slot.

        According to the 3SF-mini specification, a slot is justifiable if its
        distance (`delta`) from the last finalized slot is:
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

        return (
            # Rule 1: The first N slots after finalization are always justifiable.
            #
            # Examples: delta = 0, 1, 2, 3, 4, 5
            delta <= IMMEDIATE_JUSTIFICATION_WINDOW
            # Rule 2: Slots at perfect square distances are justifiable.
            #
            # Examples: delta = 1, 4, 9, 16, 25, 36, 49, 64, ...
            # Check: integer square root squared equals delta
            or math.isqrt(delta) ** 2 == delta
            # Rule 3: Slots at pronic number distances are justifiable.
            #
            # Pronic numbers have the form n(n+1): 2, 6, 12, 20, 30, 42, 56, ...
            # Mathematical insight: For pronic delta = n(n+1), we have:
            #   4*delta + 1 = 4n(n+1) + 1 = (2n+1)^2
            # Check: 4*delta+1 is an odd perfect square
            or (
                math.isqrt(4 * delta + 1) ** 2 == 4 * delta + 1
                and math.isqrt(4 * delta + 1) % 2 == 1
            )
        )


class SubnetId(Uint64):
    """Subnet identifier (0-63) for attestation subnet partitioning."""


class ValidatorIndex(Uint64):
    """Represents a validator's unique index as a 64-bit unsigned integer."""

    @classmethod
    def proposer_for_slot(cls, slot: Slot, num_validators: Uint64) -> "ValidatorIndex":
        """Return the validator index responsible for proposing at the given slot.

        Round-robin selection: the proposer is slot modulo registry size.
        """
        return cls(int(slot) % int(num_validators))

    def is_proposer_for(self, slot: Slot, num_validators: Uint64) -> bool:
        """Check if this validator is the proposer for the given slot."""
        return self == ValidatorIndex.proposer_for_slot(slot, num_validators)

    def is_valid(self, num_validators: Uint64) -> bool:
        """Check if this index is within valid bounds for a registry of given size."""
        return int(self) < int(num_validators)

    def compute_subnet_id(self, num_committees: Uint64) -> SubnetId:
        """Compute the attestation subnet id for this validator.

        Args:
            num_committees: Positive number of committees.

        Returns:
            A SubnetId in 0..(num_committees-1).
        """
        return SubnetId(int(self) % int(num_committees))


class AggregationBits(BaseBitlist):
    """Bitlist representing validator participation in an attestation or signature."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def to_validator_indices(self) -> "ValidatorIndices":
        """
        Extract all validator indices encoded in these aggregation bits.

        Returns:
            `ValidatorIndices` containing the indices, sorted in ascending order.

        Raises:
            `AssertionError`: If no bits are set.
        """
        # Extract indices where bit is set; fail if none found.
        indices = [ValidatorIndex(i) for i, bit in enumerate(self.data) if bit]
        if not indices:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        return ValidatorIndices(data=indices)


class ValidatorIndices(SSZList[ValidatorIndex]):
    """List of validator indices up to the registry limit."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def to_aggregation_bits(self) -> AggregationBits:
        """
        Convert to aggregation bits marking which validators are present.

        Returns:
            `AggregationBits` with the corresponding indices set to True.

        Raises:
            `AssertionError`: If no indices are provided.
            `AssertionError`: If any index is outside the supported LIMIT.
        """
        index_list = self.data

        # Require at least one validator for a valid aggregation.
        if not index_list:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        # Convert to a set of native ints.
        #
        # This combines int conversion and deduplication in a single O(N) pass.
        ids = {int(i) for i in index_list}

        # Validate bounds: max index must be within registry limit.
        if (max_id := max(ids)) >= AggregationBits.LIMIT:
            raise AssertionError("Validator index out of range for aggregation bits")

        # Build bit list:
        # - True at positions present in indices,
        # - False elsewhere.
        return AggregationBits(data=[Boolean(i in ids) for i in range(max_id + 1)])


# Deferred until after Slot, ValidatorIndex(es), and AggregationBits are defined.
# Each downstream module imports those types from this file at module-load time.
from lean_spec.node.chain.config import HISTORICAL_ROOTS_LIMIT  # noqa: E402
from lean_spec.spec.crypto.xmss.aggregation import TypeOneMultiSignature  # noqa: E402
from lean_spec.spec.crypto.xmss.containers import PublicKey, Signature  # noqa: E402


class Config(Container):
    """
    Holds temporary configuration properties for simplified consensus.

    Note: These fields support a simplified round-robin block production
    in the absence of more complex mechanisms like RANDAO or deposits.
    """

    genesis_time: Uint64
    """The timestamp of the genesis block."""


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    attestation_pubkey: Bytes52
    """XMSS public key for signing attestations."""

    proposal_pubkey: Bytes52
    """XMSS public key for signing proposer attestations in blocks."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_attestation_pubkey(self) -> PublicKey:
        """Get the XMSS public key used for attestation verification."""
        return PublicKey.decode_bytes(bytes(self.attestation_pubkey))

    def get_proposal_pubkey(self) -> PublicKey:
        """Get the XMSS public key used for proposer attestation verification."""
        return PublicKey.decode_bytes(bytes(self.proposal_pubkey))


class Validators(SSZList[Validator]):
    """Validator registry tracked in the state."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class Checkpoint(Container):
    """
    Represents a checkpoint in the chain's history.

    A checkpoint marks a specific moment in the chain.

    It combines a block identifier with a slot number.

    Checkpoints are used for justification and finalization.
    """

    model_config = Container.model_config | {"frozen": True}

    root: Bytes32
    """The root hash of the checkpoint's block."""

    slot: Slot
    """The slot number of the checkpoint's block."""

    def advance_to(self, candidate: "Checkpoint") -> "Checkpoint":
        """
        Return the later of two checkpoints, keeping self on a slot tie.

        Forward-only progression for justified and finalized checkpoints.

        The candidate replaces the receiver only when its slot is strictly higher.
        """
        return candidate if candidate.slot > self.slot else self


class AttestationData(Container):
    """Attestation content describing the validator's observed chain view."""

    model_config = Container.model_config | {"frozen": True}

    slot: Slot
    """The slot for which the attestation is made."""

    head: Checkpoint
    """The checkpoint representing the head block as observed by the validator."""

    target: Checkpoint
    """The checkpoint representing the target block as observed by the validator."""

    source: Checkpoint
    """The checkpoint representing the source block as observed by the validator."""


class Attestation(Container):
    """Validator specific attestation wrapping shared attestation data."""

    model_config = Container.model_config | {"frozen": True}

    validator_id: ValidatorIndex
    """The index of the validator making the attestation."""

    data: AttestationData
    """The attestation data produced by the validator."""


class SignedAttestation(Attestation):
    """Validator attestation bundled with its signature."""

    signature: Signature
    """Signature aggregation produced by the leanVM (SNARKs in the future)."""


class AggregatedAttestation(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    """Bitfield indicating which validators participated in the aggregation."""

    data: AttestationData
    """Combined attestation data similar to the beacon chain format.

    Multiple validator attestations are aggregated here without the complexity of
    committee assignments.
    """


class SignedAggregatedAttestation(Container):
    """
    A signed aggregated attestation for broadcasting.

    Contains the attestation data and the aggregated signature proof.
    """

    data: AttestationData
    """Combined attestation data similar to the beacon chain format."""

    proof: TypeOneMultiSignature
    """Aggregated single-message proof covering all participating validators."""


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class BlockBody(Container):
    """Payload of a block containing attestations."""

    attestations: AggregatedAttestations
    """Attestations in the block. Signatures are folded into the block-level proof."""


class BlockHeader(Container):
    """
    Metadata summarizing a block.

    Contains parent reference, state root, and body hash.
    Smaller than full blocks.
    """

    slot: Slot
    """The slot in which the block was proposed."""

    proposer_index: ValidatorIndex
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body_root: Bytes32
    """The root of the block body."""


class Block(Container):
    """A complete block including header and body."""

    slot: Slot
    """The slot in which the block was proposed."""

    proposer_index: ValidatorIndex
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body: BlockBody
    """The block's payload."""


class SignedBlock(Container):
    """Envelope carrying a block with a single aggregated proof for all signatures.

    The proof is the SSZ-encoded form of a Type-2 multi-message proof that
    binds every attestation in the body plus the proposer's signature over
    the block root.
    """

    block: Block
    """The block being signed."""

    proof: ByteList512KiB
    """Single full-block proof covering attestations and the proposer signature."""


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
            IndexError: If the target slot is active but outside the tracked range.
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
        try:
            return self[relative_index]
        except IndexError as e:
            raise IndexError(
                f"Slot {target_slot} is outside the tracked range "
                f"(finalized_boundary={finalized_slot}, tracked_length={len(self)})"
            ) from e

    def with_justified(
        self,
        finalized_slot: Slot,
        target_slot: Slot,
        value: Boolean,
    ) -> Self:
        """
        Return a new bitfield with the justification status updated.

        This method follows the immutable pattern:
        - Returns 'self' if the slot is finalized (immutable).
        - Returns a clone with the specific bit updated for active slots.

        Args:
            finalized_slot: The anchor point for the tracking window.
            target_slot: The slot to update.
            value: The new justification status.

        Returns:
            A new, updated JustifiedSlots instance.

        Raises:
            IndexError: If the target slot is active but outside the tracked range.
        """
        # Determine the position of the target relative to the anchor.
        #
        # If the slot is behind the finalized boundary, we return 'self' unchanged.
        # We cannot modify the status of finalized history, and treating it as a
        # no-op preserves the immutability of the conceptual chain history.
        if (relative_index := target_slot.justified_index_after(finalized_slot)) is None:
            return self

        # Ensure we are not trying to write to a future slot that does not exist
        # in our tracking list yet. The state must be explicitly extended first.
        if relative_index >= len(self):
            raise IndexError(
                f"Slot {target_slot} is outside the tracked range "
                f"(finalized_boundary={finalized_slot}, tracked_length={len(self)})"
            )

        # Clone and update in one smooth operation.
        #
        # 1. Create a shallow copy of the data list to avoid mutating the original.
        # 2. Update the specific bit in the copy.
        # 3. Construct a new instance with the updated data.
        new_data = list(self.data)
        new_data[relative_index] = value

        return type(self)(data=new_data)

    def extend_to_slot(self, finalized_slot: Slot, target_slot: Slot) -> Self:
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
        return type(self)(data=list(self.data) + [Boolean(False)] * gap_size)

    def shift_window(self, delta: int) -> Self:
        """
        Advance the tracking window by dropping slots that became finalized.

        A non-positive delta keeps the tracking window unchanged.
        """
        # If the boundary hasn't moved forward, the window stays the same.
        if delta <= 0:
            return self

        # Return a new instance containing only the relevant subset of data.
        return type(self)(data=self.data[delta:])


class JustificationValidators(BaseBitlist):
    """Per-root validator vote bitfields, concatenated into one flat bitlist.

    Each tracked root contributes one bit per registered validator.
    The cap is the maximum tracked roots times the validator registry limit.

    Why this product: a larger cap inflates the bitlist's merkle tree depth.
    That changes the state root for identical data, so this limit is consensus-critical.
    """

    LIMIT = int(HISTORICAL_ROOTS_LIMIT) * int(VALIDATOR_REGISTRY_LIMIT)


class State(Container):
    """The main consensus state object."""

    # Configuration
    config: Config
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
