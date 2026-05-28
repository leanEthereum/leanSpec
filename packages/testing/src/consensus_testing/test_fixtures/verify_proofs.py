"""Multi-signature proof verification fixture format.

Generates JSON test vectors for the Type-1 multi-signature primitive.
Each vector emits the public inputs and proof bytes a conformant
client must verify, plus the attestation data the message hash is
derived from so SSZ hashing agreement is exercised on the same path.
"""

from typing import Any, ClassVar, Literal

from pydantic import Field

from lean_spec.forks.lstar.containers import AttestationData
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import (
    AggregationError,
    TypeOneMultiSignature,
)
from lean_spec.subspecs.xmss.containers import PublicKey
from lean_spec.types import (
    AggregationBits,
    ByteList512KiB,
    Bytes32,
    Checkpoint,
    Slot,
    ValidatorIndex,
    ValidatorIndices,
)

from ..keys import XmssKeyManager
from .base import BaseConsensusFixture


class VerifyProofsTest(BaseConsensusFixture):
    """Fixture for primitive multi-signature proof verification.

    Generates a Type-1 proof for the configured validators signing the
    attestation data and emits the public inputs alongside the proof
    bytes.

    To consume a vector, clients parse the SSZ containers, confirm
    that the recomputed attestation root matches the message field,
    run their Type-1 verifier against the emitted public keys,
    message, slot, and proof, and check that the outcome matches
    expect_exception (None means verify must succeed; a class name
    means verify must reject).
    """

    format_name: ClassVar[str] = "verify_proofs_test"
    description: ClassVar[str] = (
        "Tests multi-signature proof verification against precomputed proof bytes."
    )

    proof_type: Literal["type_1"] = "type_1"
    """Proof shape under test.

    Type-1 covers many validators signing one message.
    """

    validator_ids: list[ValidatorIndex] = Field(exclude=True)
    """Validators contributing raw signatures to the aggregate.

    Used only during generation.
    The resolved public keys, bitfield, and proof bytes are emitted
    instead so clients consume a self-contained vector.
    """

    attestation_data: AttestationData
    """The signed object.

    Clients re-derive its hash tree root and must match the message
    field below.
    """

    tamper: dict[str, Any] | None = Field(default=None, exclude=True)
    """Optional post-generation mutation that produces a rejection vector.

    Each operation rewrites part of how the spec binds inputs to the
    proof.

    Supported operations:

    - ``{"operation": "rebind_with_alt_head_root"}``
      Generate the proof bound to a different head root inside the
      attestation data while emitting the honest attestation data,
      message, slot, pubkeys, and bits.
      The proof binding then disagrees with the emitted message.

    - ``{"operation": "shift_emitted_slot"}``
      Increment the emitted slot field by one while leaving the proof
      bound to the original slot.
      A client verifying against the emitted slot must reject.

    - ``{"operation": "swap_public_key", "index": int,``
      ``"with_validator_id": int}``
      Replace the emitted public key at the given index with another
      validator's attestation public key.
      The proof was generated honestly, so the emitted set no longer
      matches the keys the proof was bound to.
    """

    # Output fields below are populated by make_fixture and complete
    # the client-visible portion of the JSON vector.

    public_keys: list[PublicKey] | None = None
    """Attestation public keys for the participating validators.

    Ordered by validator_ids order, matching the aggregation_bits mask.
    """

    aggregation_bits: AggregationBits | None = None
    """Participation bitfield derived from validator_ids."""

    message: Bytes32 | None = None
    """Hash tree root of attestation_data, bound into the proof."""

    slot: Slot | None = None
    """Slot bound into the proof."""

    proof: ByteList512KiB | None = None
    """Aggregated proof bytes for clients to verify."""

    def make_fixture(self) -> "VerifyProofsTest":
        """Generate a Type-1 proof, optionally tamper, and self-verify.

        Returns:
            A copy with the computed output fields populated.

        Raises:
            AssertionError: If the verifier outcome on the emitted
                bundle disagrees with expect_exception.
            ValueError: If the tamper operation is unknown or
                misconfigured.
        """
        key_manager = XmssKeyManager.shared()

        emitted = self._generate(key_manager, self.attestation_data, self.validator_ids)
        if self.tamper is not None:
            emitted = self._apply_tamper(key_manager, emitted)

        self._assert_verify_matches_expectation(emitted)

        return self.model_copy(
            update={
                "attestation_data": emitted["attestation_data"],
                "public_keys": emitted["public_keys"],
                "aggregation_bits": emitted["aggregation_bits"],
                "message": emitted["message"],
                "slot": emitted["slot"],
                "proof": emitted["proof_bytes"],
            }
        )

    def _generate(
        self,
        key_manager: XmssKeyManager,
        attestation_data: AttestationData,
        validator_ids: list[ValidatorIndex],
    ) -> dict[str, Any]:
        """Generate an honest Type-1 proof bundle for the given inputs."""
        message = hash_tree_root(attestation_data)
        slot = attestation_data.slot
        public_keys = [key_manager.get_public_keys(vid)[0] for vid in validator_ids]
        bits = ValidatorIndices(data=validator_ids).to_aggregation_bits()
        signatures = [
            key_manager.sign_attestation_data(vid, attestation_data) for vid in validator_ids
        ]
        proof_obj = TypeOneMultiSignature.aggregate(
            children=[],
            raw_xmss=list(zip(validator_ids, public_keys, signatures, strict=True)),
            message=message,
            slot=slot,
        )
        return {
            "attestation_data": attestation_data,
            "message": message,
            "slot": slot,
            "public_keys": public_keys,
            "aggregation_bits": bits,
            "proof_bytes": proof_obj.proof,
        }

    def _apply_tamper(
        self,
        key_manager: XmssKeyManager,
        emitted: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply the configured tamper to the honest bundle."""
        assert self.tamper is not None
        operation = self.tamper.get("operation")

        match operation:
            case "rebind_with_alt_head_root":
                return self._tamper_rebind_with_alt_head_root(key_manager, emitted)
            case "shift_emitted_slot":
                return self._tamper_shift_emitted_slot(emitted)
            case "swap_public_key":
                return self._tamper_swap_public_key(key_manager, emitted)
            case _:
                raise ValueError(f"Unknown tamper operation: {operation!r}")

    def _tamper_rebind_with_alt_head_root(
        self,
        key_manager: XmssKeyManager,
        emitted: dict[str, Any],
    ) -> dict[str, Any]:
        """Regenerate the proof against an alternate head root.

        The emitted attestation data, message, slot, pubkeys, and bits
        stay honest.
        Only the proof bytes carry a binding to the alternate root, so
        the verifier rejects on the message mismatch.
        """
        honest_data: AttestationData = emitted["attestation_data"]
        alt_head_root = Bytes32(b"\xee" * 32)
        alt_data = honest_data.model_copy(
            update={"head": Checkpoint(root=alt_head_root, slot=honest_data.slot)}
        )
        alt_bundle = self._generate(key_manager, alt_data, self.validator_ids)
        return {**emitted, "proof_bytes": alt_bundle["proof_bytes"]}

    def _tamper_shift_emitted_slot(self, emitted: dict[str, Any]) -> dict[str, Any]:
        """Increment the emitted slot field while leaving the proof bound to the original."""
        return {**emitted, "slot": Slot(int(emitted["slot"]) + 1)}

    def _tamper_swap_public_key(
        self,
        key_manager: XmssKeyManager,
        emitted: dict[str, Any],
    ) -> dict[str, Any]:
        """Replace the emitted pubkey at index i with another validator's."""
        index = int(self.tamper["index"])  # type: ignore[index]
        with_validator_id = ValidatorIndex(int(self.tamper["with_validator_id"]))  # type: ignore[index]

        public_keys: list[PublicKey] = list(emitted["public_keys"])
        if not 0 <= index < len(public_keys):
            raise ValueError(
                f"swap_public_key index {index} out of range for {len(public_keys)} keys"
            )

        replacement = key_manager.get_public_keys(with_validator_id)[0]
        public_keys[index] = replacement
        return {**emitted, "public_keys": public_keys}

    def _assert_verify_matches_expectation(self, emitted: dict[str, Any]) -> None:
        """Verify the emitted bundle and check the outcome against expect_exception.

        Honest vectors expect verification to succeed (expect_exception is None).
        Tampered vectors expect a specific exception type to be raised.
        """
        candidate = TypeOneMultiSignature(
            participants=emitted["aggregation_bits"],
            proof=emitted["proof_bytes"],
        )
        exception_raised: Exception | None = None
        try:
            candidate.verify(
                emitted["public_keys"],
                emitted["message"],
                emitted["slot"],
            )
        except AggregationError as exc:
            exception_raised = exc

        if self.expect_exception is None:
            if exception_raised is not None:
                raise AssertionError(f"Verifier rejected an honest bundle: {exception_raised}")
            return

        if exception_raised is None:
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but verification succeeded"
            )
        if not isinstance(exception_raised, self.expect_exception):
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but got "
                f"{type(exception_raised).__name__}: {exception_raised}"
            )
