"""Signature aggregation for the Lean Ethereum consensus specification."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Self

from lean_multisig_py import (
    aggregate_signatures,
    setup_prover,
    setup_verifier,
    verify_aggregated_signatures,
)

from lean_spec.config import LEAN_ENV, LeanEnvMode
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.types import ByteListMiB, Bytes32, Container

from .containers import PublicKey, Signature

INVERSE_PROOF_SIZE = 2
"""Protocol-level inverse proof size parameter for aggregation (range 1-4)."""


class AggregationError(Exception):
    """Raised when signature aggregation or verification fails."""


class AggregatedSignatureProof(Container):
    """
    Cryptographic proof that a set of validators signed a message.

    This container encapsulates the output of the leanVM signature aggregation,
    combining the participant set with the proof bytes. This design ensures
    the proof is self-describing: it carries information about which validators
    it covers.

    The proof can verify that all participants signed the same message in the
    same slot, using a single verification operation instead of checking
    each signature individually.
    """

    participants: AggregationBits
    """Bitfield indicating which validators' signatures are included."""

    proof_data: ByteListMiB
    """The raw aggregated proof bytes from leanVM."""

    # TODO: Add bytecode-point claim data from recursive aggregation.
    # bytecode_point: ByteListMiB | None = None
    # """
    # Serialized bytecode-point claim data from recursive aggregation.

    # If the bytecode point is not provided, the proof is not recursive.
    # """

    @classmethod
    def aggregate(
        cls,
        xmss_participants: AggregationBits | None,
        children: Sequence[Self],
        raw_xmss: Sequence[tuple[PublicKey, Signature]],
        message: Bytes32,
        slot: Slot,
        mode: LeanEnvMode | None = None,
    ) -> Self:
        """
        Aggregate raw_xmss signatures and children proofs into a single proof.

        The API supports recursive aggregation but the bindings currently do not.

        Args:
            xmss_participants: Bitfield of validators whose raw_signatures are provided.
            children: Sequence of child proofs to aggregate.
            raw_xmss: Sequence of (public key, signature) tuples to aggregate.
            message: The 32-byte message that was signed.
            slot: The slot in which the signatures were created.
            mode: The mode to use for the aggregation (test or prod).

        Returns:
            An aggregated signature proof covering raw signers and all child participants.

        Raises:
            AggregationError: If aggregation fails.
        """
        if not raw_xmss and not children:
            raise AggregationError("At least one raw signature or child proof is required")

        if raw_xmss and xmss_participants is None:
            raise AggregationError("xmss_participants is required when raw_xmss is provided")

        if not raw_xmss and len(children) < 2:
            raise AggregationError(
                "At least two child proofs are required when no raw signatures are provided"
            )

        aggregated_validator_ids: set[ValidatorIndex] = set()
        if xmss_participants is not None:
            aggregated_validator_ids.update(xmss_participants.to_validator_indices())

        if len(aggregated_validator_ids) != len(raw_xmss):
            raise AggregationError("Raw signature count does not match XMSS participant count")

        # Include child participants in the aggregated participants
        for child in children:
            aggregated_validator_ids.update(child.participants.to_validator_indices())
        participants = AggregationBits.from_validator_indices(
            ValidatorIndices(data=sorted(aggregated_validator_ids))
        )

        mode = mode or LEAN_ENV
        setup_prover(mode=mode)
        try:
            proof_bytes = aggregate_signatures(
                [pk.encode_bytes() for pk, _ in raw_xmss],
                [sig.encode_bytes() for _, sig in raw_xmss],
                message,
                slot,
                mode=mode,
            )
            return cls(
                participants=participants,
                proof_data=ByteListMiB(data=proof_bytes),
            )
        except Exception as exc:
            raise AggregationError(f"Signature aggregation failed: {exc}") from exc

    def verify(
        self,
        public_keys: Sequence[PublicKey],
        message: Bytes32,
        slot: Slot,
        mode: LeanEnvMode | None = None,
    ) -> None:
        """
        Verify this aggregated signature proof.

        Args:
            public_keys: Public keys of the participants (order must match participants bitfield).
            message: The 32-byte message that was signed.
            slot: The slot in which the signatures were created.
            mode: The mode to use for the verification (test or prod).

        Raises:
            AggregationError: If verification fails.
        """
        mode = mode or LEAN_ENV
        setup_verifier(mode=mode)
        try:
            verify_aggregated_signatures(
                [pk.encode_bytes() for pk in public_keys],
                message,
                self.proof_data.encode_bytes(),
                slot,
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Signature verification failed: {exc}") from exc
