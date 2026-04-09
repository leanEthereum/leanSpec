"""Lightweight aggregated attestation specification for test definitions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.subspecs.containers.attestation import AggregatedAttestation, AttestationData
from lean_spec.subspecs.containers.block.block import Block
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import ByteListMiB, CamelModel

from .utils import resolve_checkpoint

if TYPE_CHECKING:
    from lean_spec.subspecs.containers.state.state import State

    from ..keys import XmssKeyManager


class AggregatedAttestationSpec(CamelModel):
    """
    Aggregated attestation specification for test definitions.

    Specifies multiple validators attesting to the same data.
    Head and source are automatically derived from target.
    """

    validator_ids: list[ValidatorIndex]
    """The indices of validators making the attestation (required)."""

    slot: Slot
    """The slot for which the attestation is made (required)."""

    target_slot: Slot
    """The slot of the target block being attested to (required)."""

    target_root_label: str
    """
    Label referencing a previously created block as the target (required).

    The block must exist in the block registry with this label.
    """

    valid_signature: bool = True
    """
    Flag whether the generated attestation signatures should be valid.

    Used for testing that verification properly rejects invalid attestation signatures.
    When False, structurally valid but cryptographically invalid signatures
    (all zeros) will be generated for all attestations instead of proper XMSS signatures.

    Defaults to True (valid signatures).
    """

    signer_ids: list[ValidatorIndex] | None = None
    """
    Override which validators actually sign the attestation.

    When None (default), signatures are generated using the validators in validator_ids.
    When specified, signatures are generated using these validator indices instead.

    This creates a mismatch between claimed participants and actual signers.
    Useful for testing that verification rejects attestations where valid signatures
    don't correspond to the claimed validators.

    Must have same length as validator_ids when specified.
    """

    def build_attestation_data(
        self,
        block_registry: dict[str, Block],
        state: State,
    ) -> AttestationData:
        """
        Build attestation data from this specification.

        Args:
            block_registry: Labeled blocks for target resolution.
            state: State for source checkpoint lookup.

        Returns:
            Attestation data shared by all validators in the aggregation.

        Raises:
            ValueError: If target label not found in registry.
        """
        target = resolve_checkpoint(self.target_root_label, self.target_slot, block_registry)

        return AttestationData(
            slot=self.slot,
            head=target,
            target=target,
            source=state.latest_justified,
        )

    def build_invalid_proof(
        self,
        block_registry: dict[str, Block],
        state: State,
        key_manager: XmssKeyManager,
        block: Block,
    ) -> tuple[Block, AggregatedSignatureProof]:
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
        attestation_data = self.build_attestation_data(block_registry, state)

        aggregation_bits = ValidatorIndices(data=self.validator_ids).to_aggregation_bits()
        invalid_aggregated = AggregatedAttestation(
            aggregation_bits=aggregation_bits,
            data=attestation_data,
        )

        if not self.valid_signature:
            # Cryptographically invalid proof (zeroed-out bytes).
            invalid_proof = AggregatedSignatureProof(
                participants=ValidatorIndices(data=self.validator_ids).to_aggregation_bits(),
                proof_data=ByteListMiB(data=b"\x00" * 32),
            )
        elif self.signer_ids is not None:
            # Valid proof from wrong validators (participant mismatch).
            valid_proof = key_manager.sign_and_aggregate(self.signer_ids, attestation_data)
            invalid_proof = AggregatedSignatureProof(
                participants=aggregation_bits,
                proof_data=valid_proof.proof_data,
            )
        else:
            invalid_proof = AggregatedSignatureProof(
                participants=ValidatorIndices(data=self.validator_ids).to_aggregation_bits(),
                proof_data=ByteListMiB(data=b"\x00" * 32),
            )

        # Append invalid attestation to the block body.
        updated_block = block.model_copy(
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

        return updated_block, invalid_proof
