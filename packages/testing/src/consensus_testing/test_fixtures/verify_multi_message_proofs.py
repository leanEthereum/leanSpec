"""Fixture format for multi-message aggregate proof verification vectors."""

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
    MultiMessageAggregate,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz import ByteList512KiB, Bytes32

from ..keys import XmssKeyManager
from .base import BaseConsensusFixture

ALTERNATE_HEAD_ROOT: Bytes32 = Bytes32(b"\xee" * 32)
"""Sentinel head root used by the rebind tamper to bind one component off-target."""


class RebindComponentToAlternateHeadRoot(BaseModel):
    """Rebind one component's proof to an alternate head root.

    The honest attestation data is still emitted for every component.
    Only the targeted component's proof bytes carry the alternate binding.
    """

    component_index: int
    """Index of the component whose proof is rebound."""


class IncrementComponentSlot(BaseModel):
    """Bump one component's emitted slot while its proof stays bound to the original slot."""

    component_index: int
    """Index of the component whose emitted slot is bumped."""


class SwapComponentParticipantPublicKey(BaseModel):
    """Replace one participant's public key with another validator's attestation key.

    The honest proof is still emitted.
    Only the targeted component's public key layout carries the swap.
    """

    component_index: int
    """Index of the component whose participant list is edited."""

    index: int
    """Position in that component's participant list whose key is replaced."""

    with_validator_index: ValidatorIndex
    """Validator whose attestation key replaces the original."""


Tamper = (
    RebindComponentToAlternateHeadRoot | IncrementComponentSlot | SwapComponentParticipantPublicKey
)
"""Discriminated union of post-generation mutations that produce a rejection vector."""


class VerifyMultiMessageProofsTest(BaseConsensusFixture):
    """Verify a multi-message aggregate proof against precomputed bytes."""

    format_name: ClassVar[str] = "verify_multi_message_proofs_test"

    description: ClassVar[str] = (
        "Tests multi-message aggregate proof verification against precomputed proof bytes."
    )

    validator_indices_per_message: list[list[ValidatorIndex]] = Field(exclude=True)
    """Per-component validator lists contributing raw signatures."""

    attestation_data_per_message: list[AttestationData]
    """Signed object for each component."""

    tamper: Tamper | None = Field(default=None, exclude=True)
    """Optional post-generation mutation that produces a rejection vector."""

    # Fields below are populated during generation.
    #
    # Together they form the client-visible portion of the JSON vector.

    public_keys_per_message: list[list[PublicKey]] | None = None
    """Attestation public keys per component, parallel to the participation bits."""

    aggregation_bits_per_message: list[AggregationBits] | None = None
    """Per-component participation bitfields naming each component's contributors."""

    messages: list[Bytes32] | None = None
    """Hash tree root per component, bound into the proof."""

    slots: list[Slot] | None = None
    """Slot per component, bound into the proof."""

    proof: ByteList512KiB | None = None
    """Aggregated multi-message proof bytes for clients to verify."""

    def make_fixture(self) -> VerifyMultiMessageProofsTest:
        """Generate the merged proof, optionally tamper one binding, self-verify, return self.

        Raises:
            AssertionError: If the verifier outcome disagrees with the configured expectation.
            ValueError: If the tamper is misconfigured or the input has no components.
        """
        key_manager = XmssKeyManager.shared()
        component_count = len(self.attestation_data_per_message)
        if component_count == 0:
            raise ValueError("at least one component is required for a multi-message vector")
        if len(self.validator_indices_per_message) != component_count:
            raise ValueError(
                f"validator_indices_per_message length {len(self.validator_indices_per_message)} "
                f"does not match attestation_data_per_message length {component_count}"
            )

        # Phase 1: derive the honest bundle for each component.
        messages: list[Bytes32] = []
        slots: list[Slot] = []
        public_keys_per_message: list[list[PublicKey]] = []
        aggregation_bits_per_message: list[AggregationBits] = []
        components: list[SingleMessageAggregate] = []

        for validator_indices, attestation_data in zip(
            self.validator_indices_per_message,
            self.attestation_data_per_message,
            strict=True,
        ):
            messages.append(hash_tree_root(attestation_data))
            slots.append(attestation_data.slot)
            public_keys = [key_manager.get_public_keys(i)[0] for i in validator_indices]
            public_keys_per_message.append(public_keys)
            aggregation_bits_per_message.append(
                ValidatorIndices(data=validator_indices).to_aggregation_bits()
            )
            components.append(
                self._single_message_aggregate(
                    key_manager, attestation_data, validator_indices, public_keys
                )
            )

        # Phase 2: honest merge.
        merged = MultiMessageAggregate.aggregate(
            components,
            public_keys_per_part=public_keys_per_message,
        )

        # Phase 3: optionally mutate exactly one component's binding.
        match self.tamper:
            case RebindComponentToAlternateHeadRoot(component_index=component_index):
                if not 0 <= component_index < component_count:
                    raise ValueError(
                        f"component_index {component_index} out of range "
                        f"for {component_count} components"
                    )
                # Regenerate the targeted component against an alternate head root and re-merge.
                # The emitted attestation data, message, slot, keys, and bits stay honest.
                # Only the merged proof bytes carry the alternate binding for this component.
                honest = self.attestation_data_per_message[component_index]
                alt_data = AttestationData(
                    slot=honest.slot,
                    head=Checkpoint(root=ALTERNATE_HEAD_ROOT, slot=honest.slot),
                    target=honest.target,
                    source=honest.source,
                )
                components[component_index] = self._single_message_aggregate(
                    key_manager,
                    alt_data,
                    self.validator_indices_per_message[component_index],
                    public_keys_per_message[component_index],
                )
                merged = MultiMessageAggregate.aggregate(
                    components,
                    public_keys_per_part=public_keys_per_message,
                )

            case IncrementComponentSlot(component_index=component_index):
                if not 0 <= component_index < component_count:
                    raise ValueError(
                        f"component_index {component_index} out of range "
                        f"for {component_count} components"
                    )
                slots[component_index] = slots[component_index] + Slot(1)

            case SwapComponentParticipantPublicKey(
                component_index=component_index,
                index=position,
                with_validator_index=replacement_index,
            ):
                if not 0 <= component_index < component_count:
                    raise ValueError(
                        f"component_index {component_index} out of range "
                        f"for {component_count} components"
                    )
                public_keys = public_keys_per_message[component_index]
                if not 0 <= position < len(public_keys):
                    raise ValueError(
                        f"swap_public_key index {position} out of range "
                        f"for component {component_index} with {len(public_keys)} keys"
                    )
                replacement = key_manager.get_public_keys(replacement_index)[0]
                # A replacement matching the original key would leave the bundle honest.
                # The verifier would then accept and the rejection would be a false positive.
                if replacement == public_keys[position]:
                    raise ValueError(
                        f"swap_public_key replacement at component {component_index} "
                        f"index {position} matches the original; "
                        f"pick a with_validator_index distinct from the participant there"
                    )
                public_keys[position] = replacement

        # Phase 4: self-verify and assert the outcome against the configured expectation.
        exception_raised: Exception | None = None
        # Catch any exception so a verifier raising the wrong type still produces
        # a comparable "expected X got Y" message instead of crashing the filler.
        try:
            merged.verify(
                public_keys_per_message=public_keys_per_message,
                messages=list(zip(messages, slots, strict=True)),
            )
        except Exception as exception:
            exception_raised = exception

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

        # Phase 5: publish the client-visible outputs and return self.
        self.messages = messages
        self.slots = slots
        self.public_keys_per_message = public_keys_per_message
        self.aggregation_bits_per_message = aggregation_bits_per_message
        self.proof = merged.proof
        return self

    def _single_message_aggregate(
        self,
        key_manager: XmssKeyManager,
        attestation_data: AttestationData,
        validator_indices: list[ValidatorIndex],
        public_keys: list[PublicKey],
    ) -> SingleMessageAggregate:
        """Aggregate raw signatures from each validator into a single-message component."""
        signatures = [
            key_manager.sign_attestation_data(i, attestation_data) for i in validator_indices
        ]
        return SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=list(zip(validator_indices, public_keys, signatures, strict=True)),
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )
