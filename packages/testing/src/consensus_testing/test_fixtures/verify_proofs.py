"""Fixture format for single-message aggregate proof verification vectors."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, Field

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks import (
    AggregationBits,
    Checkpoint,
    Slot,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz import ByteList512KiB, Bytes32

from ..keys import XmssKeyManager
from .base import BaseConsensusFixture

ALTERNATE_HEAD_ROOT: Bytes32 = Bytes32(b"\xee" * 32)
"""Sentinel head root used by the rebind tamper to bind the proof off-target."""


class RebindToAlternateHeadRoot(BaseModel):
    """
    Rebind the proof to an alternate head root inside the attestation data.

    The honest attestation data is still emitted.
    Only the proof bytes carry a binding to the alternate root.
    """


class IncrementEmittedSlot(BaseModel):
    """Bump the emitted slot field while the proof stays bound to the original slot."""


class SwapParticipantPublicKey(BaseModel):
    """Replace one participant's public key with another validator's attestation key."""

    index: int
    """Position in the participant list whose key is replaced."""

    with_validator_index: ValidatorIndex
    """Validator whose attestation key replaces the original."""


Tamper = RebindToAlternateHeadRoot | IncrementEmittedSlot | SwapParticipantPublicKey
"""Discriminated union of post-generation mutations that produce a rejection vector."""


class VerifyProofsTest(BaseConsensusFixture):
    """Verify a single-message aggregate proof against precomputed bytes."""

    format_name: ClassVar[str] = "verify_proofs_test"

    description: ClassVar[str] = (
        "Tests multi-signature proof verification against precomputed proof bytes."
    )

    validator_indices: list[ValidatorIndex] = Field(exclude=True)
    """Validators contributing raw signatures to the aggregate."""

    attestation_data: AttestationData
    """The signed object."""

    tamper: Tamper | None = Field(default=None, exclude=True)
    """Optional post-generation mutation that produces a rejection vector."""

    # Fields below are populated during generation.
    #
    # Together they form the client-visible portion of the JSON vector.

    public_keys: list[PublicKey] | None = None
    """Attestation public keys for the participating validators.

    Ordered consistently with the participation bitfield.
    """

    aggregation_bits: AggregationBits | None = None
    """Participation bitfield naming the contributing validators."""

    message: Bytes32 | None = None
    """Hash tree root of the signed object, bound into the proof."""

    slot: Slot | None = None
    """Slot bound into the proof."""

    proof: ByteList512KiB | None = None
    """Aggregated proof bytes for clients to verify."""

    def make_fixture(self) -> VerifyProofsTest:
        """Generate the proof, optionally tamper, self-verify, and return the populated copy.

        Raises:
            AssertionError: If the verifier outcome disagrees with the configured expectation.
            ValueError: If the tamper is misconfigured.
        """
        key_manager = XmssKeyManager.shared()

        # Phase 1: derive the honest bundle.
        message = hash_tree_root(self.attestation_data)
        slot = self.attestation_data.slot
        public_keys = [key_manager.get_public_keys(i)[0] for i in self.validator_indices]
        aggregation_bits = ValidatorIndices(data=self.validator_indices).to_aggregation_bits()
        proof = self._aggregate_proof(
            key_manager, self.attestation_data, self.validator_indices, public_keys
        )

        # Phase 2: optionally mutate exactly one binding of that bundle.
        match self.tamper:
            case RebindToAlternateHeadRoot():
                # Regenerate the proof against an alternate head root.
                # - The honest attestation data, message, slot, keys, and bits stay emitted.
                # - Only the proof bytes carry the alternate binding.
                honest = self.attestation_data
                alt_data = AttestationData(
                    slot=honest.slot,
                    head=Checkpoint(root=ALTERNATE_HEAD_ROOT, slot=honest.slot),
                    target=honest.target,
                    source=honest.source,
                )
                proof = self._aggregate_proof(
                    key_manager, alt_data, self.validator_indices, public_keys
                )

            case IncrementEmittedSlot():
                slot = slot + Slot(1)

            case SwapParticipantPublicKey(index=index, with_validator_index=replacement_index):
                if not 0 <= index < len(public_keys):
                    raise ValueError(
                        f"swap_public_key index {index} out of range for {len(public_keys)} keys"
                    )
                replacement = key_manager.get_public_keys(replacement_index)[0]
                # A replacement matching the original key would leave the bundle honest.
                # The verifier would then accept and the rejection would be a false positive.
                if replacement == public_keys[index]:
                    raise ValueError(
                        f"swap_public_key replacement at index {index} matches the original; "
                        f"pick a with_validator_index distinct from the participant there"
                    )
                public_keys[index] = replacement

        # Phase 3: self-verify and assert the outcome against the configured expectation.
        candidate = SingleMessageAggregate(participants=aggregation_bits, proof=proof)
        exception_raised: Exception | None = None
        # Catch any exception so a verifier raising the wrong type still produces
        # a comparable "expected X got Y" message instead of crashing the filler.
        try:
            candidate.verify(public_keys, message, slot)
        except Exception as exc:
            exception_raised = exc

        if self.expect_exception is None:
            if exception_raised is not None:
                raise AssertionError(f"Verifier rejected an honest bundle: {exception_raised}")
        elif exception_raised is None:
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but verification succeeded"
            )
        elif not isinstance(exception_raised, self.expect_exception):
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but got "
                f"{type(exception_raised).__name__}: {exception_raised}"
            )

        # Phase 4: publish the client-visible outputs and return self.
        self.message = message
        self.slot = slot
        self.public_keys = public_keys
        self.aggregation_bits = aggregation_bits
        self.proof = proof
        return self

    def _aggregate_proof(
        self,
        key_manager: XmssKeyManager,
        attestation_data: AttestationData,
        validator_indices: list[ValidatorIndex],
        public_keys: list[PublicKey],
    ) -> ByteList512KiB:
        """Aggregate raw signatures from each validator into proof bytes for the bundle."""
        signatures = [
            key_manager.sign_attestation_data(i, attestation_data) for i in validator_indices
        ]
        aggregate = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=list(zip(validator_indices, public_keys, signatures, strict=True)),
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )
        return aggregate.proof
