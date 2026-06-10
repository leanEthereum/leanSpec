"""Lightweight attestation specifications for test definitions."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager, create_dummy_signature
from consensus_testing.test_types.utils import resolve_checkpoint
from lean_spec.base import CamelModel
from lean_spec.spec.crypto.merkleization import hash_tree_root
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
from lean_spec.spec.ssz import ByteList512KiB, Bytes32


class AttestationSpec(CamelModel):
    """Shared core for attestation specifications."""

    slot: Slot
    """The slot for which the attestation is made (required)."""

    target_slot: Slot
    """The slot of the target block being attested to (required)."""

    target_root_label: str | None = None
    """
    Label referencing a previously created block as the target.

    The block must exist in the block registry with this label.
    """

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
        Build attestation data by resolving the three checkpoints (target, head, source).

        Args:
            block_registry: Labeled blocks for checkpoint resolution.
            default_source: Source checkpoint used when neither an explicit
                root nor a label overrides the source.

        Returns:
            Attestation data with all three checkpoints resolved.

        Raises:
            ValueError: If the target has neither an explicit root nor a label.
        """
        # Resolve the target checkpoint.
        #
        # An explicit root takes highest priority.
        # A label triggers lookup in the block registry.
        # Unlike the other two checkpoints, the target is mandatory.
        if self.target_root is not None:
            target = Checkpoint(root=self.target_root, slot=self.target_slot)
        elif self.target_root_label is not None:
            target = resolve_checkpoint(self.target_root_label, self.target_slot, block_registry)
        else:
            raise ValueError("attestation spec requires a target root")

        # Resolve the head checkpoint.
        #
        # Priority: explicit root > label > target checkpoint.
        # - When using an explicit root without a slot, the target slot is used.
        # - When no head information is provided at all, the head mirrors the target.
        #
        # This matches honest validator behavior.
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

        # Resolve the source checkpoint.
        #
        # Priority: explicit root > label > the provided default.
        # The source represents the most recent justified checkpoint the attester is aware of.
        # When not overridden, the caller-provided default supplies the correct value.
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
    Override which validators actually sign the attestation.

    - When None (default), signatures are generated using the validators in validator_indices.
    - When specified, signatures are generated using these validator indices instead.

    This creates a mismatch between claimed participants and actual signers.
    Useful for testing that verification rejects attestations where valid signatures
    don't correspond to the claimed validators.

    Must have same length as validator_indices when specified.
    """

    aggregation_bits: AggregationBits | None = None
    """
    Raw aggregation bits placed into the block body verbatim.

    When None (default), the bits are derived from the validator indices,
    producing the tightest bitfield that covers the highest set index.
    Set this to author bit patterns the derivation cannot express:
    a zero-length bitfield, all-false bits, or trailing padding past the
    validator registry.

    Only honored by the state transition format's forced-attestation
    path, which bypasses signing. Signed paths derive their bits from
    the validator indices so proofs match the claimed participants.
    """

    def resolve_aggregation_bits(self) -> AggregationBits:
        """Return the explicit bits override, or bits derived from the validator indices."""
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
        Build a complete signed aggregated attestation from this specification.

        Supports valid, invalid, and participant-mismatch scenarios
        depending on the spec's signature and signer configuration.

        Args:
            block_registry: Labeled blocks for checkpoint resolution.
            state: Head state providing the latest justified checkpoint as source fallback.
            key_manager: XMSS key manager for signing attestation data.

        Returns:
            Signed aggregated attestation ready for gossip processing.
        """
        attestation_data = self.build_attestation_data(block_registry, state.latest_justified)

        # Separate "claimed" from "actual" participants.
        #
        # - Claimed validators appear in the proof's participant bitfield.
        # - Actual signers produce the cryptographic material.
        # They default to the same set for honest attestations.
        validator_indices = self.validator_indices
        signer_indices = self.signer_indices or self.validator_indices

        # Path 1: Invalid signature.
        #
        # Correct participant bitfield but zeroed-out proof bytes.
        # Exercises signature verification rejection.
        if not self.valid_signature:
            placeholder = ByteList512KiB(data=b"\x00" * 32)
            proof = SingleMessageAggregate(
                participants=AggregationBits.from_indices(validator_indices),
                proof=placeholder,
            )
            return SignedAggregatedAttestation(data=attestation_data, proof=proof)

        # Path 2: Valid signature.
        proof = key_manager.sign_and_aggregate(signer_indices, attestation_data)

        # Path 3: Participant mismatch.
        #
        # Replace the participant bitfield with different validator indices
        # while keeping the original proof bytes intact.
        # The proof is cryptographically valid for the actual signers,
        # but the claimed participants no longer match.
        # The store must detect and reject this inconsistency.
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

        Handles two invalidity scenarios:

        - Invalid signature: correct participant bitfield, zeroed-out proof bytes
        - Signer mismatch: valid proof from wrong validators, claimed participants differ

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

        # Empty proof bytes flag "no real single-message aggregate here" — the caller treats
        # any such entry as a placeholder and bypasses real binding merges.
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

        # Append invalid attestation to the block body.
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
    Gossip attestation specification for test definitions.

    Specifies a single validator attesting via the gossip network.
    The source defaults to the anchor (genesis) block instead of the
    latest justified checkpoint.
    Honest attestations without overrides use data produced by the Store.
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
        Build a complete signed attestation from this specification.

        Valid attestations without overrides use honest data from the Store.
        Invalid or overridden attestations use this spec's checkpoint fields,
        with the anchor block as the default source.

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
