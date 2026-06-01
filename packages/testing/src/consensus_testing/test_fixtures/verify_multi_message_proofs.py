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

    participant_index: int
    """Position in that component's participant list whose key is replaced."""

    with_validator_index: ValidatorIndex
    """Validator whose attestation key replaces the original."""


class SwapComponentMessageBindings(BaseModel):
    """Swap the emitted message-slot bindings of two components.

    The merged proof and the per-component key layout stay honest.
    Each component's proof is then checked against the other component's binding.
    A conforming verifier rejects this transposition.
    """

    first_component_index: int
    """Index of one component whose emitted message-slot binding is swapped."""

    second_component_index: int
    """Index of the other component whose emitted message-slot binding is swapped."""


class DropComponentMessageBinding(BaseModel):
    """Drop one component's emitted message-slot binding while keeping its keys.

    The emitted binding list ends up shorter than the per-component key list.
    A conforming verifier rejects the length mismatch.
    """

    component_index: int
    """Index of the component whose emitted message-slot binding is removed."""


Tamper = (
    RebindComponentToAlternateHeadRoot
    | IncrementComponentSlot
    | SwapComponentParticipantPublicKey
    | SwapComponentMessageBindings
    | DropComponentMessageBinding
)
"""Union of post-generation mutations that each produce a rejection vector."""


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
            aggregation_bits_per_message.append(AggregationBits.from_indices(validator_indices))
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

        # Phase 3: optionally mutate exactly one binding of the bundle.
        match self.tamper:
            case RebindComponentToAlternateHeadRoot(component_index=component_index):
                self._check_component_index(component_index, component_count)
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
                self._check_component_index(component_index, component_count)
                bumped = slots[component_index] + Slot(1)
                # A bumped slot landing on another component's slot would make the rejection
                # ambiguous, since the verifier could then fail on the wrong binding.
                if any(
                    other_index != component_index and other_slot == bumped
                    for other_index, other_slot in enumerate(slots)
                ):
                    raise ValueError(
                        f"incremented slot {bumped} collides with another component's slot; "
                        f"pick component slots that stay distinct after the bump"
                    )
                slots[component_index] = bumped

            case SwapComponentParticipantPublicKey(
                component_index=component_index,
                participant_index=position,
                with_validator_index=replacement_index,
            ):
                self._check_component_index(component_index, component_count)
                public_keys = public_keys_per_message[component_index]
                if not 0 <= position < len(public_keys):
                    raise ValueError(
                        f"participant_index {position} out of range "
                        f"for component {component_index} with {len(public_keys)} keys"
                    )
                replacement = key_manager.get_public_keys(replacement_index)[0]
                # A replacement matching the original key would leave the bundle honest.
                # The verifier would then accept and the rejection would be a false positive.
                if replacement == public_keys[position]:
                    raise ValueError(
                        f"participant key replacement at component {component_index} "
                        f"position {position} matches the original; "
                        f"pick a with_validator_index distinct from the participant there"
                    )
                # The honest merge already bound the proof to the honest keys.
                # Editing the emitted key here without re-merging is what breaks verification.
                public_keys[position] = replacement

            case SwapComponentMessageBindings(
                first_component_index=first_index,
                second_component_index=second_index,
            ):
                self._check_component_index(first_index, component_count)
                self._check_component_index(second_index, component_count)
                if first_index == second_index:
                    raise ValueError("swap message bindings requires two distinct components")
                # Swap each component's emitted message and slot so its proof faces the other's
                # binding, while the merged proof and key layout stay honest.
                messages[first_index], messages[second_index] = (
                    messages[second_index],
                    messages[first_index],
                )
                slots[first_index], slots[second_index] = (
                    slots[second_index],
                    slots[first_index],
                )

            case DropComponentMessageBinding(component_index=component_index):
                self._check_component_index(component_index, component_count)
                # Remove one component's emitted message and slot but keep its keys.
                # The binding list is now shorter than the per-component key list.
                del messages[component_index]
                del slots[component_index]

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
        self.assert_expected_outcome(exception_raised)

        # Phase 5: publish the client-visible outputs and return self.
        self.messages = messages
        self.slots = slots
        self.public_keys_per_message = public_keys_per_message
        self.aggregation_bits_per_message = aggregation_bits_per_message
        self.proof = merged.proof
        return self

    @staticmethod
    def _check_component_index(component_index: int, component_count: int) -> None:
        """Reject a tamper that targets a component outside the bundle."""
        if not 0 <= component_index < component_count:
            raise ValueError(
                f"component_index {component_index} out of range for {component_count} components"
            )

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
