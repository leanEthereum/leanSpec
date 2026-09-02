"""Lightweight attestation specifications for test definitions."""

from __future__ import annotations

from ssz import hash_tree_root

from consensus_testing.keys import XmssKeyManager, create_dummy_signature
from consensus_testing.test_types.utils import resolve_checkpoint
from lean_spec.base import CamelModel
from lean_spec.spec.forks import AggregationBits, Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    SignedAggregatedAttestation,
    SignedAttestation,
    SingleMessageAggregate,
    State,
    Store,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz_types import ByteList512KiB, Bytes32


class AttestationSpec(CamelModel):
    """Shared core for attestation specifications."""

    slot: Slot
    """The slot for which the attestation is made (required)."""

    target_slot: Slot
    """The slot of the target block being attested to (required)."""

    target_root_label: str | None = None
    """Label of a previously created block to use as the target."""

    target_root: Bytes32 | None = None
    """Optional explicit target root (bypasses label lookup)."""

    head_root_label: str | None = None
    """Optional label for the head checkpoint."""

    head_root: Bytes32 | None = None
    """Optional explicit head root."""

    head_slot: Slot | None = None
    """Optional override for the head checkpoint slot."""

    source_root_label: str | None = None
    """Optional label for the source checkpoint."""

    source_root: Bytes32 | None = None
    """Optional explicit source root."""

    source_slot: Slot | None = None
    """Optional override for the source checkpoint slot."""

    valid_signature: bool = True
    """Flag whether the generated attestation signatures should be valid."""

    def build_attestation_data(
        self,
        block_registry: dict[str, Block],
        default_source: Checkpoint,
    ) -> AttestationData:
        """
        Build attestation data by resolving the target, head, and source checkpoints.

        Args:
            block_registry: Labeled blocks for checkpoint resolution.
            default_source: Source checkpoint used when neither an explicit
                root nor a label overrides the source.

        Returns:
            Attestation data with all three checkpoints resolved.

        Raises:
            ValueError: If the target has neither an explicit root nor a label.
        """
        # Resolve the target: explicit root, else label lookup.
        # Unlike the other two checkpoints, the target is mandatory.
        if self.target_root is not None:
            target = Checkpoint(root=self.target_root, slot=self.target_slot)
        elif self.target_root_label is not None:
            target = resolve_checkpoint(self.target_root_label, self.target_slot, block_registry)
        else:
            raise ValueError("attestation spec requires a target root")

        # Resolve the head: explicit root, else label, else mirror the target.
        # An explicit root without a slot borrows the target slot.
        # Mirroring the target when unset matches honest validator behavior.
        if self.head_root is not None:
            head = Checkpoint(
                root=self.head_root,
                slot=self.head_slot if self.head_slot is not None else self.target_slot,
            )
        elif self.head_root_label is not None:
            head = resolve_checkpoint(self.head_root_label, self.head_slot, block_registry)
        else:
            head = Checkpoint(
                root=target.root,
                slot=self.head_slot if self.head_slot is not None else target.slot,
            )

        # Resolve the source: explicit root, else label, else the caller default.
        # The source is the most recent justified checkpoint the attester knows.
        if self.source_root is not None:
            source = Checkpoint(
                root=self.source_root,
                slot=self.source_slot if self.source_slot is not None else default_source.slot,
            )
        elif self.source_root_label is not None:
            source = resolve_checkpoint(self.source_root_label, self.source_slot, block_registry)
        else:
            source = Checkpoint(
                root=default_source.root,
                slot=self.source_slot if self.source_slot is not None else default_source.slot,
            )

        return AttestationData(
            slot=self.slot,
            head=head,
            target=target,
            source=source,
        )


class AggregatedAttestationSpec(AttestationSpec):
    """Aggregated attestation specification for test definitions."""

    validator_indices: list[ValidatorIndex]
    """The indices of validators making the attestation (required)."""

    signer_indices: list[ValidatorIndex] | None = None
    """
    Validators that actually sign, when different from the claimed participants.

    A set differing from the claimed participants forces a signer mismatch to test rejection.
    """

    aggregation_bits: AggregationBits | None = None
    """Raw aggregation bits used verbatim, honored only on the unsigned forced-attestation path."""

    def resolve_aggregation_bits(self) -> AggregationBits:
        """Return the bit override when present, else bits derived from the validator indices."""
        if self.aggregation_bits is not None:
            return self.aggregation_bits
        return AggregationBits.from_indices(self.validator_indices)

    def build_signed(
        self,
        block_registry: dict[str, Block],
        state: State,
        key_manager: XmssKeyManager,
    ) -> SignedAggregatedAttestation:
        """
        Build a signed aggregated attestation, valid or adversarial per this spec's config.

        Args:
            block_registry: Labeled blocks for checkpoint resolution.
            state: Head state providing the latest justified checkpoint as source fallback.
            key_manager: XMSS key manager for signing attestation data.

        Returns:
            Signed aggregated attestation ready for gossip processing.
        """
        attestation_data = self.build_attestation_data(block_registry, state.latest_justified)

        # Claimed validators fill the proof's participant bitfield.
        # Actual signers produce the cryptographic material.
        # They are the same set for honest attestations.
        validator_indices = self.validator_indices
        signer_indices = self.signer_indices or self.validator_indices

        # Path 0/1: placeholder proof bytes, two adversarial cases sharing one branch.
        # Path 0 is a raw bit override: an honest aggregate can never carry zero
        # participants, so this is the only way to feed the gossip path an adversarial
        # empty-bit aggregate, with the override used verbatim as the participant bitfield.
        # Path 1 is an invalid signature: the correct participant bitfield derived from the
        # validator indices, with zeroed-out proof bytes to exercise rejection.
        # The participants check is explicit `is not None`: an AggregationBits may be falsy.
        if self.aggregation_bits is not None or not self.valid_signature:
            participants = (
                self.aggregation_bits
                if self.aggregation_bits is not None
                else AggregationBits.from_indices(validator_indices)
            )
            proof = SingleMessageAggregate(
                participants=participants,
                proof=ByteList512KiB(data=b"\x00" * 32),
            )
            return SignedAggregatedAttestation(data=attestation_data, proof=proof)

        # Path 2: Valid signature.
        proof = key_manager.sign_and_aggregate(signer_indices, attestation_data)

        # Path 3: participant mismatch.
        # Swap in different claimed participants but keep the original proof bytes.
        # The proof stays valid for the real signers, so the store must reject the inconsistency.
        if self.signer_indices and self.signer_indices != self.validator_indices:
            proof = SingleMessageAggregate(
                participants=AggregationBits.from_indices(validator_indices),
                proof=proof.proof,
            )

        return SignedAggregatedAttestation(data=attestation_data, proof=proof)

    def build_invalid_proof(
        self,
        block_registry: dict[str, Block],
        state: State,
        key_manager: XmssKeyManager,
        block: Block,
    ) -> tuple[Block, SingleMessageAggregate]:
        """
        Build an invalid attestation proof and append it to the block body.

        Args:
            block_registry: Labeled blocks for checkpoint resolution.
            state: State for attestation data building.
            key_manager: XMSS key manager for signing (mismatch scenario).
            block: Current block to append the invalid attestation to.

        Returns:
            Tuple of (updated block with appended attestation, invalid proof).
        """
        attestation_data = self.build_attestation_data(block_registry, state.latest_justified)

        aggregation_bits = AggregationBits.from_indices(self.validator_indices)
        invalid_aggregated = AggregatedAttestation(
            aggregation_bits=aggregation_bits,
            data=attestation_data,
        )

        # Empty proof bytes signal "no real aggregate here".
        # The caller treats any such entry as a placeholder and bypasses real binding merges.
        placeholder = ByteList512KiB(data=b"")

        if not self.valid_signature:
            invalid_proof = SingleMessageAggregate(participants=aggregation_bits, proof=placeholder)
        elif self.signer_indices is not None:
            # Valid proof from wrong validators (participant mismatch).
            valid_proof = key_manager.sign_and_aggregate(self.signer_indices, attestation_data)
            invalid_proof = SingleMessageAggregate(
                participants=aggregation_bits, proof=valid_proof.proof
            )
        else:
            invalid_proof = SingleMessageAggregate(participants=aggregation_bits, proof=placeholder)

        block = block.model_copy(
            update={
                "body": block.body.model_copy(
                    update={
                        "attestations": AggregatedAttestations(
                            data=[*block.body.attestations.data, invalid_aggregated]
                        )
                    }
                )
            }
        )

        return block, invalid_proof


class GossipAttestationSpec(AttestationSpec):
    """
    Single validator attesting via the gossip network.

    The source defaults to the anchor block, not the latest justified checkpoint.
    """

    validator_index: ValidatorIndex
    """The index of the validator making the attestation (required)."""

    @property
    def has_overrides(self) -> bool:
        """Whether any checkpoint field is explicitly overridden."""
        return (
            self.head_root_label is not None
            or self.head_slot is not None
            or self.source_root_label is not None
            or self.source_slot is not None
            or self.target_root is not None
            or self.head_root is not None
            or self.source_root is not None
        )

    def build_signed(
        self,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
        store: Store,
        anchor_block: Block,
        expected_valid: bool,
    ) -> SignedAttestation:
        """
        Build a signed attestation from this specification.

        Valid attestations without overrides use honest data from the store, otherwise this spec's
        checkpoint fields with the anchor block as default source.

        Args:
            block_registry: Labeled blocks for target resolution.
            key_manager: XMSS key manager for signing.
            store: Fork choice store for honest attestation data production.
            anchor_block: Genesis/anchor block for source checkpoint default.
            expected_valid: Whether the step expects this attestation to succeed.

        Returns:
            Signed attestation ready for gossip processing.
        """
        if not expected_valid or self.has_overrides:
            anchor_source = Checkpoint(root=hash_tree_root(anchor_block), slot=anchor_block.slot)
            attestation_data = self.build_attestation_data(block_registry, anchor_source)
        else:
            # Honest path: use the Store's own attestation data production.
            attestation_data = LstarSpec().produce_attestation_data(store, self.slot)

        signature = (
            key_manager.sign_attestation_data(self.validator_index, attestation_data)
            if self.valid_signature
            else create_dummy_signature()
        )

        return SignedAttestation(
            validator_index=self.validator_index,
            data=attestation_data,
            signature=signature,
        )
