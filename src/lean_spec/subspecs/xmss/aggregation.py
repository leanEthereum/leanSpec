"""Signature aggregation for the Lean Ethereum consensus specification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self, Sequence

from lean_multisig_py import (
    aggregate_signatures,
    setup_prover,
    setup_verifier,
    verify_aggregated_signatures,
)

from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.byte_arrays import ByteListMiB
from lean_spec.types.container import Container

from .constants import LEAN_ENV
from .containers import PublicKey, Signature


@dataclass(frozen=True, slots=True)
class SignatureKey:
    """
    Key for looking up individual validator signatures.

    Used to index signature caches by (validator, message) pairs.
    """

    _validator_id: ValidatorIndex
    """The validator who produced the signature."""

    data_root: Bytes32
    """The hash of the signed data (e.g., attestation data root)."""

    def __init__(self, validator_id: int | ValidatorIndex, data_root: Bytes32) -> None:
        """Create a SignatureKey with the given validator_id and data_root."""
        object.__setattr__(self, "_validator_id", ValidatorIndex(validator_id))
        object.__setattr__(self, "data_root", data_root)

    @property
    def validator_id(self) -> ValidatorIndex:
        """The validator who produced the signature."""
        return self._validator_id


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
    same epoch, using a single verification operation instead of checking
    each signature individually.
    """

    participants: AggregationBits
    """Bitfield indicating which validators' signatures are included."""

    proof_data: ByteListMiB
    """The raw aggregated proof bytes from leanVM."""

    @classmethod
    def aggregate(
        cls,
        participants: AggregationBits,
        public_keys: Sequence[PublicKey],
        signatures: Sequence[Signature],
        message: Bytes32,
        epoch: Uint64,
        mode: str | None = None,
    ) -> Self:
        """
        Aggregate individual XMSS signatures into a single proof.

        Args:
            participants: Bitfield of validators whose signatures are included.
            public_keys: Public keys of the signers (must match signatures order).
            signatures: Individual XMSS signatures to aggregate.
            message: The 32-byte message that was signed.
            epoch: The epoch in which the signatures were created.
            mode: The mode to use for the aggregation (test or prod).

        Returns:
            An aggregated signature proof covering all participants.

        Raises:
            AggregationError: If aggregation fails.
        """
        mode = mode or LEAN_ENV
        setup_prover(mode=mode)
        try:
            proof_bytes = aggregate_signatures(
                [pk.encode_bytes() for pk in public_keys],
                [sig.encode_bytes() for sig in signatures],
                message,
                epoch,
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
        epoch: Uint64,
        mode: str | None = None,
    ) -> None:
        """
        Verify this aggregated signature proof.

        Args:
            public_keys: Public keys of the participants (order must match participants bitfield).
            message: The 32-byte message that was signed.
            epoch: The epoch in which the signatures were created.
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
                epoch,
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Signature verification failed: {exc}") from exc
