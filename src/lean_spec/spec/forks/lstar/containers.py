"""The container types for the Lean consensus specification."""

from collections.abc import Iterable
from typing import Final, NamedTuple, Self

from lean_multisig_py import (
    aggregate_type_1,
    merge_many_type_1,
    split_type_2_by_msg,
    verify_type_1,
    verify_type_2_with_messages,
)
from pydantic import Field

from lean_spec.base import StrictBaseModel
from lean_spec.config import LEAN_ENV
from lean_spec.node.chain.clock import Interval
from lean_spec.node.chain.config import HISTORICAL_ROOTS_LIMIT
from lean_spec.spec.crypto.xmss.containers import PublicKey, Signature
from lean_spec.spec.ssz import Boolean, ByteList512KiB, Bytes32, Bytes52, Container, SSZList, Uint64
from lean_spec.spec.ssz.bitfields import BaseBitlist

from .slot import IMMEDIATE_JUSTIFICATION_WINDOW, Slot

__all__ = [
    # Re-exports from the slot module so downstream callers can keep
    # importing these names from .containers.
    "IMMEDIATE_JUSTIFICATION_WINDOW",
    "Slot",
]

VALIDATOR_REGISTRY_LIMIT: Final = Uint64(2**12)
"""The maximum number of validators that can be in the registry."""

LOG_INV_RATE: int = 1 if LEAN_ENV == "test" else 2
"""Inverse-rate exponent forwarded to the SNARK backend.

A smaller rate trades verifier cost for prover speed.
Test mode favors prover speed.
"""


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

    @classmethod
    def from_indices(cls, indices: Iterable[ValidatorIndex]) -> "AggregationBits":
        """
        Build aggregation bits from validator indices.

        Returns:
            Aggregation bits with exactly the given indices set to True.

        Raises:
            AssertionError: If no indices are provided.
            AssertionError: If any index is outside the supported LIMIT.
        """
        # Convert to native ints once for bounds checking and membership tests.
        #
        # This also deduplicates and lets any iterable be passed in.
        ids = {int(i) for i in indices}

        # Require at least one validator for a valid aggregation.
        if not ids:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        # Validate bounds: max index must be within registry limit.
        if (max_id := max(ids)) >= cls.LIMIT:
            raise AssertionError("Validator index out of range for aggregation bits")

        # Build bit list:
        # - True at positions present in indices,
        # - False elsewhere.
        return cls(data=[Boolean(i in ids) for i in range(max_id + 1)])

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


class AggregationError(Exception):
    """Raised when aggregation, merging, splitting, or verification fails."""


class SingleMessageAggregate(Container):
    """Single-message proof aggregating signatures from many validators.

    Every validator signs the same message for the same slot.

    The message and slot stay outside the proof.
    The verifier rederives them from the block body it already trusts.
    """

    model_config = Container.model_config | {"frozen": True}

    participants: AggregationBits
    """Bitfield indicating which validators contributed signatures."""

    proof: ByteList512KiB
    """Aggregated proof bytes in compact public-key-free representation."""

    @classmethod
    def aggregate(
        cls,
        children: list[tuple["SingleMessageAggregate", list[PublicKey]]],
        raw_xmss: list[tuple[ValidatorIndex, PublicKey, Signature]],
        message: Bytes32,
        slot: Slot,
    ) -> "SingleMessageAggregate":
        """Fold fresh signatures and child proofs into one single-message proof.

        # Overview

        Two kinds of contribution merge into one proof.

        - A fresh signer contributes a single raw signature.
        - A child proof contributes an already-aggregated bundle of signers.

        The result names the union of every contributing validator.
        The prover compresses all contributions into one proof over the shared message.

        # Why the index travels with each fresh signer

        A public key carries no validator index on its own.
        Pairing the index with each fresh entry lets the bitfield be derived, not passed in.
        An empty list of fresh signers simply contributes no indices.

        Args:
            children: Child proofs, each paired with the public keys it names.
            raw_xmss: Fresh entries, each carrying its validator index, public key, and signature.
            message: The 32-byte message every signer signed.
            slot: The slot every signer signed for.

        Returns:
            A single-message proof covering the union of all participants.

        Raises:
            AggregationError: When the prover rejects the inputs.
        """
        # Phase 1: union every contributing validator index.
        #
        # Fresh signers bring their own index.
        # Child proofs expose theirs through the participant bitfield.
        all_indices = {validator_index for validator_index, _, _ in raw_xmss}.union(
            *(child.participants.to_validator_indices() for child, _ in children)
        )
        participants = AggregationBits.from_indices(all_indices)

        # Phase 2: serialize inputs to the prover's wire format.
        raw_public_keys_ssz = [public_key.encode_bytes() for _, public_key, _ in raw_xmss]
        raw_signatures_ssz = [signature.encode_bytes() for _, _, signature in raw_xmss]
        children_bytes = [
            ([public_key.encode_bytes() for public_key in public_keys], bytes(child.proof.data))
            for child, public_keys in children
        ]

        # Phase 3: hand off to the Rust prover.
        # The mode argument routes the call to the matching backend bytecode.
        try:
            _, single_message_aggregate_wire = aggregate_type_1(
                raw_public_keys_ssz,
                raw_signatures_ssz,
                bytes(message),
                int(slot),
                LOG_INV_RATE,
                children_bytes or None,
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(str(exception)) from exception

        return cls(
            participants=participants,
            proof=ByteList512KiB(data=single_message_aggregate_wire),
        )

    def verify(
        self,
        public_keys: list[PublicKey],
        message: Bytes32,
        slot: Slot,
    ) -> None:
        """Verify this single-message single-message aggregate proof against a public_key set.

        Args:
            public_keys: PublicKeys for the validators named by participants.
            message: Message bound by the proof.
            slot: Slot bound by the proof.

        Raises:
            AggregationError: When the public_key count does not match the bitfield
                or the Rust verifier rejects the proof.
        """
        # The bitfield names one validator per set bit.
        # The caller must supply exactly that many keys, in the same order.
        # A miscount would otherwise fail deep in the verifier with an opaque error.
        expected = len(self.participants.to_validator_indices())
        if len(public_keys) != expected:
            raise AggregationError(
                f"single-message aggregate verify expected {expected} pubkeys for participants, "
                f"got {len(public_keys)}"
            )

        # Hand the resolved keys, message, and slot to the Rust verifier.
        # The mode argument selects the matching backend bytecode.
        try:
            verify_type_1(
                [public_key.encode_bytes() for public_key in public_keys],
                bytes(message),
                int(slot),
                bytes(self.proof.data),
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(
                f"single-message aggregate verification failed: {exception}"
            ) from exception

    def __hash__(self) -> int:
        """Content-deterministic hash via SSZ encoding."""
        return hash(self.encode_bytes())


class MultiMessageAggregate(Container):
    """Merged proof covering many distinct messages.

    Each component is a single-message proof over its own message.
    Merging binds the components into one proof the block can carry whole.
    """

    model_config = Container.model_config | {"frozen": True}

    proof: ByteList512KiB
    """Compact public-key-free serialized multi-message aggregate proof bytes."""

    @classmethod
    def aggregate(
        cls,
        parts: list[SingleMessageAggregate],
        public_keys_per_part: list[list[PublicKey]],
    ) -> "MultiMessageAggregate":
        """Merge several single-message proofs over distinct messages into one.

        # Why the public keys are passed in

        - A merged proof stores no public keys.
        - The prover needs them as external context to fold the components together.
        - They cannot be recovered from the proofs, so the caller supplies them.

        Args:
            parts: The single-message proofs to merge, one per distinct message.
            public_keys_per_part: Public keys for each component, in the same order as the proofs.

        Returns:
            A merged proof binding every component to its own message.

        Raises:
            AggregationError: When no proofs are given, a public_key list disagrees
                with its participant count, or the prover rejects the inputs.
        """
        if not parts:
            raise AggregationError(
                "multi-message aggregate requires at least one single-message aggregate input"
            )

        # Each component carries the public keys named by its bitfield, in the same order.
        #
        # A miscount would otherwise fail deep in the prover with an opaque error.
        single_message_aggregate_entries: list[tuple[list[bytes], bytes]] = []
        for index, (part, public_keys) in enumerate(zip(parts, public_keys_per_part, strict=True)):
            expected = len(part.participants.to_validator_indices())
            if len(public_keys) != expected:
                raise AggregationError(
                    f"multi-message aggregate entry {index} "
                    f"expected {expected} pubkeys, got {len(public_keys)}"
                )
            single_message_aggregate_entries.append(
                ([public_key.encode_bytes() for public_key in public_keys], bytes(part.proof.data))
            )

        # Hand the per-component keys and proof bytes to the Rust prover.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            _, multi_message_aggregate_wire = merge_many_type_1(
                single_message_aggregate_entries,
                LOG_INV_RATE,
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(str(exception)) from exception

        return cls(proof=ByteList512KiB(data=multi_message_aggregate_wire))

    def split_by_message(
        self,
        message: Bytes32,
        public_keys_per_message: list[list[PublicKey]],
        participants: AggregationBits,
    ) -> SingleMessageAggregate:
        """Recover the single-message aggregate proof bound to one message.

        Splits this multi-message aggregate to extract the component
        bound to the given message.

        # Why the layout and participants are passed in

        - A merged proof stores neither the public keys nor the participant bitfields.
        - The prover needs the original key layout to isolate one component.
        - The caller supplies both, drawn from the block attestation this component binds.

        Args:
            message: Message that selects the single-message aggregate component.
            public_keys_per_message: PublicKey layout this multi-message aggregate was built with.
            participants: Bitfield naming the validators of the recovered component.

        Returns:
            The single-message aggregate proof bound to the message.

        Raises:
            AggregationError: When the Rust binding rejects the split.
        """
        # Each component carries the public keys named by its bitfield, in the same order.
        public_keys_per_component_ssz: list[list[bytes]] = [
            [public_key.encode_bytes() for public_key in public_keys]
            for public_keys in public_keys_per_message
        ]

        # Hand the key layout, merged proof, and selector message to the Rust prover.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            _, single_message_aggregate_wire = split_type_2_by_msg(
                public_keys_per_component_ssz,
                bytes(self.proof.data),
                bytes(message),
                LOG_INV_RATE,
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(
                f"multi-message aggregate split failed: {exception}"
            ) from exception

        return SingleMessageAggregate(
            participants=participants,
            proof=ByteList512KiB(data=single_message_aggregate_wire),
        )

    def verify(
        self,
        public_keys_per_message: list[list[PublicKey]],
        messages: list[tuple[Bytes32, Slot]],
    ) -> None:
        """Verify this multi-message proof against its per-component bindings.

        # The message bindings

        Each component is checked against one message and slot supplied by the caller.
        Without that binding the proof would accept attacker-chosen data resolving to the same keys.
        The parallel lists pin every component to the message it actually signed.

        Args:
            public_keys_per_message: Public keys for each component, in component order.
            messages: Message-slot pair each component is bound to, parallel to the keys.

        Raises:
            AggregationError: When the two lists disagree in length, or the verifier rejects.
        """
        # Each component needs exactly one message-slot binding.
        #
        # A length mismatch would leave components unbound or misaligned.
        if len(messages) != len(public_keys_per_message):
            raise AggregationError(
                f"multi-message aggregate verify expected "
                f"{len(public_keys_per_message)} message bindings, "
                f"got {len(messages)}"
            )

        # Serialize the key layout and the per-component message bindings.
        public_keys_per_component_ssz: list[list[bytes]] = [
            [public_key.encode_bytes() for public_key in public_keys]
            for public_keys in public_keys_per_message
        ]
        expected_messages = [(bytes(message), int(slot)) for message, slot in messages]

        # Hand the layout, bindings, and merged proof to the Rust verifier.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            verify_type_2_with_messages(
                public_keys_per_component_ssz,
                expected_messages,
                bytes(self.proof.data),
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(
                f"multi-message aggregate verification failed: {exception}"
            ) from exception

    def __hash__(self) -> int:
        """Content-deterministic hash via SSZ encoding."""
        return hash(self.encode_bytes())


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

    attestation_public_key: Bytes52
    """XMSS public key for signing attestations."""

    proposal_public_key: Bytes52
    """XMSS public key for signing proposer attestations in blocks."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_attestation_public_key(self) -> PublicKey:
        """Get the XMSS public key used for attestation verification."""
        return PublicKey.decode_bytes(bytes(self.attestation_public_key))

    def get_proposal_public_key(self) -> PublicKey:
        """Get the XMSS public key used for proposer attestation verification."""
        return PublicKey.decode_bytes(bytes(self.proposal_public_key))


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

    validator_index: ValidatorIndex
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

    proof: SingleMessageAggregate
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

    The proof is a multi-message aggregate multi-message proof.
    It binds every attestation in the body plus the proposer's signature
    over the block root.
    """

    block: Block
    """The block being signed."""

    proof: MultiMessageAggregate
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


class AttestationSignatureEntry(NamedTuple):
    """
    Single validator's XMSS signature for an attestation.

    Used as an element in the attestation_signatures map: one entry per validator
    that attested to the same AttestationData.
    """

    validator_index: ValidatorIndex
    signature: Signature


class Store[StateT: Container, BlockT: Container](StrictBaseModel):
    """
    Forkchoice store tracking chain state and validator attestations.

    This is the "local view" that a node uses to run LMD GHOST. It contains:

    - which blocks and states are known,
    - which checkpoints are justified and finalized,
    - which block is currently considered the head,
    - and, for each validator, their latest attestation that should influence fork choice.

    The `Store` is updated whenever:
    - a new block is processed,
    - an attestation is received (via a block or gossip),
    - an interval tick occurs (activating new attestations),
    - or when the head is recomputed.
    """

    time: Interval
    """Current time in intervals since genesis."""

    config: Config
    """Chain configuration parameters."""

    head: Bytes32
    """
    Root of the current canonical chain head block.

    This is the result of running the fork choice algorithm on the current contents of the `Store`.
    """

    safe_target: Bytes32
    """
    Root of the current safe target for attestation.

    This can be used by higher-level logic to restrict which blocks are
    considered safe to attest to, based on additional safety conditions.
    """

    latest_justified: Checkpoint
    """
    Highest slot justified checkpoint known to the store.

    LMD GHOST starts from this checkpoint when computing the head.

    Only descendants of this checkpoint are considered viable.
    """

    latest_finalized: Checkpoint
    """
    Highest slot finalized checkpoint known to the store.

    Everything strictly before this checkpoint can be considered immutable.

    Fork choice will never revert finalized history.
    """

    blocks: dict[Bytes32, BlockT] = Field(default_factory=dict)
    """
    Mapping from block root to Block objects.

    This is the set of blocks that the node currently knows about.

    Every block that might participate in fork choice must appear here.
    """

    states: dict[Bytes32, StateT] = Field(default_factory=dict)
    """
    Mapping from block root to State objects.

    For each known block, we keep its post-state.

    These states carry justified and finalized checkpoints that we use to update the
    `Store`'s latest justified and latest finalized checkpoints.
    """

    validator_index: ValidatorIndex | None
    """Index of the validator running this store instance."""

    attestation_signatures: dict[AttestationData, set[AttestationSignatureEntry]] = Field(
        default_factory=dict
    )
    """
    Per-validator XMSS signatures learned from committee attesters.

    Keyed by AttestationData.
    """

    latest_new_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """
    Aggregated signature proofs pending processing.

    These payloads are "new" and do not yet contribute to fork choice.
    They migrate to known payloads via interval ticks.
    Populated from gossip aggregated attestations.
    Block import does not feed individual proofs into this map directly.
    The block-level proof is a merged multi-message aggregate blob verified as a whole.
    On gossip-block import, any validator deconstructs that multi-message aggregate into
    per-message proofs, writes them back here, and gossips the aggregate.
    """

    latest_known_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """
    Aggregated signature proofs that have been processed.

    These payloads are "known" and contribute to fork choice weights.
    Used for recursive signature aggregation when building blocks.
    """
