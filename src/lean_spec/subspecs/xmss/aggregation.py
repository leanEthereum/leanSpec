"""Signature aggregation for the Lean Ethereum consensus specification."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Self

# from lean_multisig_py import (
#     aggregate_signatures,
#     setup_prover,
#     setup_verifier,
#     verify_aggregated_signatures,
# )

from lean_spec.config import LEAN_ENV, LeanEnvMode
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.types import ByteListMiB, Bytes32, Container

from .containers import PublicKey, Signature
from .types import BytecodePointOption

INV_PROOF_SIZE: int = 2
"""Protocol-level inverse proof size parameter for aggregation (range 1-4)."""


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
    same slot, using a single verification operation instead of checking
    each signature individually.
    """

    participants: AggregationBits
    """Bitfield indicating which validators' signatures are included."""

    proof_data: ByteListMiB
    """The raw aggregated proof bytes from leanVM."""

    bytecode_point: BytecodePointOption = BytecodePointOption(selector=0, value=None)
    """
    Serialized bytecode-point claim data from recursive aggregation.

    Union: selector 0 = None (non-recursive), selector 1 = ByteListMiB (recursive).
    """

    @classmethod
    def aggregate(
        cls,
        participants: AggregationBits | None,
        children: Sequence[Self],
        raw_xmss: Sequence[tuple[PublicKey, Signature]],
        message: Bytes32,
        slot: Slot,
        mode: LeanEnvMode | None = None,
        dummy: bool = True,
    ) -> Self:
        """
        Aggregate individual XMSS signatures into a single proof.

        Args:
            participants: Bitfield for validator IDs represented by `raw_xmss`.
            children: Already-aggregated child proofs to recursively aggregate.
            raw_xmss: Raw `(public_key, signature)` pairs for this aggregation step.
            message: The 32-byte message that was signed.
            slot: The slot in which the signatures were created.
            mode: The mode to use for the aggregation (test or prod).
            dummy: If True, return a minimal dummy proof for local/test usage.

        Returns:
            An aggregated signature proof covering raw signers and all child participants.

        Raises:
            AggregationError: If aggregation fails.
        """
        if not raw_xmss and not children:
            raise AggregationError("At least one raw signature or child proof is required")

        if raw_xmss and participants is None:
            raise AggregationError("participants is required when raw_xmss is provided")

        if not raw_xmss and len(children) < 2:
            raise AggregationError(
                "At least two child proofs are required when no raw signatures are provided"
            )

        if dummy:
            all_indices: set[ValidatorIndex] = set()
            if participants is not None:
                all_indices.update(participants.to_validator_indices().data)
            for child in children:
                all_indices.update(child.participants.to_validator_indices().data)

            merged_participants = AggregationBits.from_validator_indices(
                ValidatorIndices(data=list(all_indices))
            )

            bytecode_point = (
                BytecodePointOption(selector=1, value=ByteListMiB(data=b"\x00" * 1))
                if children
                else BytecodePointOption(selector=0, value=None)
            )

            return cls(
                participants=merged_participants,
                proof_data=ByteListMiB(data=b"\x00" * 1),
                bytecode_point=bytecode_point,
            )

        raise AggregationError("recursive aggregation is unavailable in current lean_multisig_py bindings")

        # mode = mode or LEAN_ENV
        # setup_prover(mode=mode)
        # try:
        #     proof_bytes = aggregate_signatures(
        #         [pk.encode_bytes() for pk, _ in raw_xmss],
        #         [sig.encode_bytes() for _, sig in raw_xmss],
        #         message,
        #         slot,
        #         mode=mode,
        #     )
        #     if participants is None:
        #         participants = AggregationBits.from_validator_indices(ValidatorIndices(data=[]))
        #     return cls(
        #         participants=participants,
        #         proof_data=ByteListMiB(data=proof_bytes),
        #     )
        # except Exception as exc:
        #     raise AggregationError(f"Signature aggregation failed: {exc}") from e

    def verify(
        self,
        public_keys: Sequence[PublicKey],
        message: Bytes32,
        slot: Slot,
        mode: LeanEnvMode | None = None,
        dummy: bool = True,
    ) -> None:
        """
        Verify this aggregated signature proof.

        Args:
            public_keys: Public keys of the participants (order must match participants bitfield).
            message: The 32-byte message that was signed.
            slot: The slot in which the signatures were created.
            mode: The mode to use for the verification (test or prod).
            dummy: If True, use lightweight local validation checks only.

        Raises:
            AggregationError: If verification fails.
        """
        if dummy:
            if len(self.participants.to_validator_indices()) == len(public_keys):
                return
            raise AggregationError(
                "Dummy proof verification requires the number of public keys "
                "to match the number of participants"
            )
    
        raise AggregationError("recursive aggregation verification is unavailable in current lean_multisig_py bindings")

        # mode = mode or LEAN_ENV
        # setup_verifier(mode=mode)
        # try:
        #     verify_aggregated_signatures(
        #         [pk.encode_bytes() for pk in public_keys],
        #         message,
        #         self.proof_data.encode_bytes(),
        #         slot,
        #         mode=mode,
        #     )
        # except Exception as exc:
        #     raise AggregationError(f"Signature verification failed: {exc}") from exc
