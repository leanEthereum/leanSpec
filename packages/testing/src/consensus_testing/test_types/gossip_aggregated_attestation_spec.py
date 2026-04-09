"""Lightweight aggregated-gossip attestation specification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.subspecs.containers.attestation import AttestationData
from lean_spec.subspecs.containers.attestation.attestation import SignedAggregatedAttestation
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import ByteListMiB, Bytes32, CamelModel

from .utils import resolve_checkpoint

if TYPE_CHECKING:
    from lean_spec.subspecs.containers.block.block import Block
    from lean_spec.subspecs.containers.state.state import State

    from ..keys import XmssKeyManager


class GossipAggregatedAttestationSpec(CamelModel):
    """
    Specification for an aggregated attestation received via gossip.

    The spec allows overriding head/source checkpoints to exercise validation logic.
    """

    validator_ids: list[ValidatorIndex]
    """Claimed validators participating in the aggregation."""

    slot: Slot
    """Slot of the attestation."""

    target_slot: Slot
    """Slot of the attestation target checkpoint."""

    target_root_label: str | None = None
    """Label referencing the target block root."""

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
    """Whether the aggregated proof should be generated with valid signatures."""

    signer_ids: list[ValidatorIndex] | None = None
    """Optional override for which validators actually produce the signatures."""

    def build_attestation_data(
        self,
        block_registry: dict[str, Block],
        state: State,
    ) -> AttestationData:
        """
        Build attestation data by resolving the three checkpoints (target, head, source).

        The state provides fallback values for the source checkpoint
        when neither an explicit root nor a label is specified.

        Args:
            block_registry: Labeled blocks for checkpoint resolution.
            state: Head state providing the latest justified checkpoint as source fallback.

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
            raise ValueError("gossip aggregated attestation spec requires a target root")

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
        # Priority: explicit root > label > latest justified from state.
        # The source represents the most recent justified checkpoint the attester is aware of.
        # When not overridden, the state's latest justified checkpoint provides the correct default.
        if self.source_root is not None:
            source = Checkpoint(
                root=self.source_root,
                slot=(
                    self.source_slot
                    if self.source_slot is not None
                    else state.latest_justified.slot
                ),
            )
        elif self.source_root_label is not None:
            source = resolve_checkpoint(self.source_root_label, self.source_slot, block_registry)
        else:
            source = Checkpoint(
                root=state.latest_justified.root,
                slot=(
                    self.source_slot
                    if self.source_slot is not None
                    else state.latest_justified.slot
                ),
            )

        return AttestationData(
            slot=self.slot,
            head=head,
            target=target,
            source=source,
        )

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
            state: Head state for checkpoint resolution fallbacks.
            key_manager: XMSS key manager for signing attestation data.

        Returns:
            Signed aggregated attestation ready for gossip processing.
        """
        attestation_data = self.build_attestation_data(block_registry, state)

        # Separate "claimed" from "actual" participants.
        #
        # - Claimed validators appear in the proof's participant bitfield.
        # - Actual signers produce the cryptographic material.
        # They default to the same set for honest attestations.
        validator_ids = self.validator_ids
        signer_ids = self.signer_ids or self.validator_ids

        # Path 1: Invalid signature.
        #
        # Correct participant bitfield but zeroed-out proof bytes.
        # Exercises signature verification rejection.
        if not self.valid_signature:
            proof = AggregatedSignatureProof(
                participants=ValidatorIndices(data=validator_ids).to_aggregation_bits(),
                proof_data=ByteListMiB(data=b"\x00" * 32),
            )
            return SignedAggregatedAttestation(data=attestation_data, proof=proof)

        # Path 2: Valid signature.
        proof = key_manager.sign_and_aggregate(signer_ids, attestation_data)

        # Path 3: Participant mismatch.
        #
        # Replace the participant bitfield with different validator indices
        # while keeping the original proof bytes intact.
        # The proof is cryptographically valid for the actual signers,
        # but the claimed participants no longer match.
        # The store must detect and reject this inconsistency.
        if self.signer_ids and self.signer_ids != self.validator_ids:
            proof = AggregatedSignatureProof(
                participants=ValidatorIndices(data=validator_ids).to_aggregation_bits(),
                proof_data=proof.proof_data,
            )

        return SignedAggregatedAttestation(data=attestation_data, proof=proof)
