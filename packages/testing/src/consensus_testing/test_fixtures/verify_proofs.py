"""Fixture formats for aggregate proof verification vectors."""

from __future__ import annotations

from typing import ClassVar

from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.base import StrictBaseModel
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks import (
    AggregationBits,
    Checkpoint,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.forks.lstar.containers import (
    AggregationError,
    AttestationData,
    MultiMessageAggregate,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz import ByteList512KiB, Bytes32

ALTERNATE_HEAD_ROOT: Bytes32 = Bytes32(b"\xee" * 32)
"""Sentinel head root used by the rebind tamper to bind one component off-target."""


class RebindToAlternateHeadRoot(StrictBaseModel):
    """
    Rebind one component's proof to an alternate head root.

    The honest attestation data is still emitted.
    Only the targeted component's proof bytes carry the alternate binding.
    """

    component_index: int = 0
    """Index of the component whose proof is rebound (0 for single-message vectors)."""


class IncrementEmittedSlot(StrictBaseModel):
    """Bump one component's emitted slot while its proof stays bound to the original slot."""

    component_index: int = 0
    """Index of the component whose emitted slot is bumped (0 for single-message vectors)."""


class SwapParticipantPublicKey(StrictBaseModel):
    """
    Replace one participant's public key with another validator's attestation key.

    The honest proof is still emitted.
    Only the targeted component's public key layout carries the swap.
    """

    component_index: int = 0
    """Index of the component whose participant list is edited (0 for single-message vectors)."""

    participant_index: int
    """Position in that component's participant list whose key is replaced."""

    with_validator_index: ValidatorIndex
    """Validator whose attestation key replaces the original."""


class SwapMessageBindings(StrictBaseModel):
    """
    Swap the emitted message-slot bindings of two components.

    The merged proof and the per-component key layout stay honest.
    Each component's proof is then checked against the other component's binding.
    A conforming verifier rejects this transposition.
    """

    first_component_index: int
    """Index of one component whose emitted message-slot binding is swapped."""

    second_component_index: int
    """Index of the other component whose emitted message-slot binding is swapped."""


class DropMessageBinding(StrictBaseModel):
    """
    Drop one component's emitted message-slot binding while keeping its keys.

    The emitted binding list ends up shorter than the per-component key list.
    A conforming verifier rejects the length mismatch.
    """

    component_index: int
    """Index of the component whose emitted message-slot binding is removed."""


SingleMessageTamper = RebindToAlternateHeadRoot | IncrementEmittedSlot | SwapParticipantPublicKey
"""Mutations applicable to a single-message vector, the degenerate one-component case."""

MultiMessageTamper = (
    RebindToAlternateHeadRoot
    | IncrementEmittedSlot
    | SwapParticipantPublicKey
    | SwapMessageBindings
    | DropMessageBinding
)
"""Union of post-generation mutations that each produce a rejection vector."""


def _check_component_index(component_index: int, component_count: int) -> None:
    """Reject a tamper that targets a component outside the bundle."""
    if not 0 <= component_index < component_count:
        raise ValueError(
            f"component_index {component_index} out of range for {component_count} components"
        )


def _alternate_head_data(honest: AttestationData) -> AttestationData:
    """Return the honest attestation data rebound to the alternate sentinel head root."""
    return AttestationData(
        slot=honest.slot,
        head=Checkpoint(root=ALTERNATE_HEAD_ROOT, slot=honest.slot),
        target=honest.target,
        source=honest.source,
    )


def _swap_participant_public_key(
    key_manager: XmssKeyManager,
    public_keys: list[PublicKey],
    participant_index: int,
    replacement_validator_index: ValidatorIndex,
    component_index: int,
) -> None:
    """
    Replace one participant's emitted public key in place.

    Raises:
        ValueError: If the position is out of range, or the replacement matches
            the original key and would leave the bundle honest.
    """
    if not 0 <= participant_index < len(public_keys):
        raise ValueError(
            f"participant_index {participant_index} out of range "
            f"for component {component_index} with {len(public_keys)} keys"
        )
    replacement = key_manager.get_public_keys(replacement_validator_index)[0]
    # A replacement matching the original key would leave the bundle honest.
    # The verifier would then accept and the rejection would be a false positive.
    if replacement == public_keys[participant_index]:
        raise ValueError(
            f"participant key replacement at component {component_index} "
            f"position {participant_index} matches the original; "
            f"pick a with_validator_index distinct from the participant there"
        )
    public_keys[participant_index] = replacement


class VerifySingleMessageProofsFixture(BaseConsensusFixture):
    """
    Emitted vector for single-message aggregate proof verification.

    JSON output: attestationData, publicKeys, aggregationBits, message,
    slot, proof.
    """

    attestation_data: AttestationData
    """The signed object."""

    public_keys: list[PublicKey]
    """Attestation public keys for the participating validators.

    Ordered consistently with the participation bitfield.
    """

    aggregation_bits: AggregationBits
    """Participation bitfield naming the contributing validators."""

    message: Bytes32
    """Hash tree root of the signed object, bound into the proof."""

    slot: Slot
    """Slot bound into the proof."""

    proof: ByteList512KiB
    """Aggregated proof bytes for clients to verify."""


class VerifySingleMessageProofsTest(BaseTestSpec):
    """Verify a single-message aggregate proof against precomputed bytes."""

    format_name: ClassVar[str] = "verify_single_message_proofs_test"

    description: ClassVar[str] = (
        "Tests single-message aggregate proof verification against precomputed proof bytes."
    )

    validator_indices: list[ValidatorIndex]
    """Validators contributing raw signatures to the aggregate."""

    attestation_data: AttestationData
    """The signed object."""

    tamper: SingleMessageTamper | None = None
    """Optional post-generation mutation that produces a rejection vector."""

    child_groups: list[list[ValidatorIndex]] = []
    """Optional partition of the participating validators into pre-aggregated child subsets."""

    def generate(self) -> VerifySingleMessageProofsFixture:
        """
        Generate the proof, optionally tamper, self-verify, and emit the vector.

        Raises:
            AssertionError: If the verifier outcome disagrees with the configured expectation.
            ValueError: If the tamper is misconfigured.
        """
        key_manager = XmssKeyManager.shared()

        # A single-message vector carries exactly one component.
        # The shared tampers must therefore target component 0.
        if self.tamper is not None:
            _check_component_index(self.tamper.component_index, component_count=1)

        # Phase 1: derive the honest bundle.
        message = hash_tree_root(self.attestation_data)
        slot = self.attestation_data.slot
        public_keys = [key_manager.get_public_keys(i)[0] for i in self.validator_indices]
        aggregation_bits = AggregationBits.from_indices(self.validator_indices)
        proof = self._aggregate_proof(key_manager, self.attestation_data)

        # Phase 2: optionally mutate exactly one binding of that bundle.
        match self.tamper:
            case RebindToAlternateHeadRoot():
                # Regenerate the proof against an alternate head root.
                # - The honest attestation data, message, slot, keys, and bits stay emitted.
                # - Only the proof bytes carry the alternate binding.
                proof = self._aggregate_proof(
                    key_manager, _alternate_head_data(self.attestation_data)
                )

            case IncrementEmittedSlot():
                slot = slot + Slot(1)

            case SwapParticipantPublicKey(
                participant_index=participant_index,
                with_validator_index=replacement_index,
            ):
                _swap_participant_public_key(
                    key_manager, public_keys, participant_index, replacement_index, 0
                )

        # Phase 3: self-verify and assert the outcome against the configured expectation.
        candidate = SingleMessageAggregate(participants=aggregation_bits, proof=proof)
        exception_raised: Exception | None = None
        # The aggregation layer raises exactly one error type.
        # Anything else is a harness bug and propagates unswallowed.
        try:
            candidate.verify(public_keys, message, slot)
        except AggregationError as exception:
            exception_raised = exception
        self.assert_expected_outcome(exception_raised)

        # Phase 4: publish the client-visible outputs.
        # Every tamper breaks the proof's cryptographic binding.
        return VerifySingleMessageProofsFixture(
            attestation_data=self.attestation_data,
            public_keys=public_keys,
            aggregation_bits=aggregation_bits,
            message=message,
            slot=slot,
            proof=proof,
            rejection_reason=(
                self.expected_rejection.reason if self.expected_rejection is not None else None
            ),
        )

    def _aggregate_proof(
        self,
        key_manager: XmssKeyManager,
        attestation_data: AttestationData,
    ) -> ByteList512KiB:
        """Aggregate signatures into proof bytes, recursively when child subsets are provided."""
        if self.child_groups:
            return self._aggregate_recursive(key_manager, attestation_data)
        return key_manager.sign_and_aggregate(self.validator_indices, attestation_data).proof

    def _aggregate_recursive(
        self,
        key_manager: XmssKeyManager,
        attestation_data: AttestationData,
    ) -> ByteList512KiB:
        """
        Build a two-level proof so the verifier is exercised on the recursive path.

        Children are leaf-only sub-proofs, so the folded tree is exactly two levels deep.

        Raises:
            ValueError: If a child group names an unknown validator or reuses one.
            AggregationError: If the prover rejects the inputs.
        """
        # Phase 1: reject a malformed partition before signing anything.
        #
        # Every grouped index must name a participant the bundle already carries.
        # No validator may appear in more than one child group.
        grouped_indices = [i for group in self.child_groups for i in group]
        grouped_index_set = set(grouped_indices)
        unknown_indices = grouped_index_set - set(self.validator_indices)
        if unknown_indices:
            raise ValueError(
                "child_groups reference indices not in validator_indices: "
                f"{sorted(map(int, unknown_indices))}"
            )
        if len(grouped_indices) != len(grouped_index_set):
            raise ValueError("child_groups assign a validator to more than one child group")

        # Phase 2: pre-aggregate each child group into its own single-message proof.
        children = [
            (
                key_manager.sign_and_aggregate(group, attestation_data),
                [key_manager.get_public_keys(i)[0] for i in group],
            )
            for group in self.child_groups
        ]

        # Phase 3: collect leaf signatures from validators not in any child group.
        raw_indices = [i for i in self.validator_indices if i not in grouped_index_set]
        raw_xmss = [
            (
                i,
                key_manager.get_public_keys(i)[0],
                key_manager.sign_attestation_data(i, attestation_data),
            )
            for i in raw_indices
        ]

        # Phase 4: fold the child proofs and leaf signatures into one outer aggregate.
        aggregate = SingleMessageAggregate.aggregate(
            children=children,
            raw_xmss=raw_xmss,
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )
        return aggregate.proof


class VerifyMultiMessageProofsFixture(BaseConsensusFixture):
    """
    Emitted vector for multi-message aggregate proof verification.

    JSON output: attestationDataPerMessage, publicKeysPerMessage,
    aggregationBitsPerMessage, messages, slots, proof.
    """

    attestation_data_per_message: list[AttestationData]
    """Signed object for each component."""

    public_keys_per_message: list[list[PublicKey]]
    """Attestation public keys per component, parallel to the participation bits."""

    aggregation_bits_per_message: list[AggregationBits]
    """Per-component participation bitfields naming each component's contributors."""

    messages: list[Bytes32]
    """Hash tree root per component, bound into the proof."""

    slots: list[Slot]
    """Slot per component, bound into the proof."""

    proof: ByteList512KiB
    """Aggregated multi-message proof bytes for clients to verify."""


class VerifyMultiMessageProofsTest(BaseTestSpec):
    """Verify a multi-message aggregate proof against precomputed bytes."""

    format_name: ClassVar[str] = "verify_multi_message_proofs_test"

    description: ClassVar[str] = (
        "Tests multi-message aggregate proof verification against precomputed proof bytes."
    )

    validator_indices_per_message: list[list[ValidatorIndex]]
    """Per-component validator lists contributing raw signatures."""

    attestation_data_per_message: list[AttestationData]
    """Signed object for each component."""

    tamper: MultiMessageTamper | None = None
    """Optional post-generation mutation that produces a rejection vector."""

    def generate(self) -> VerifyMultiMessageProofsFixture:
        """
        Generate the merged proof, optionally tamper one binding, self-verify, emit the vector.

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
            public_keys_per_message.append(
                [key_manager.get_public_keys(i)[0] for i in validator_indices]
            )
            aggregation_bits_per_message.append(AggregationBits.from_indices(validator_indices))
            components.append(key_manager.sign_and_aggregate(validator_indices, attestation_data))

        # Phase 2: honest merge.
        merged = MultiMessageAggregate.aggregate(
            components,
            public_keys_per_aggregate=public_keys_per_message,
        )

        # Phase 3: optionally mutate exactly one binding of the bundle.
        match self.tamper:
            case RebindToAlternateHeadRoot(component_index=component_index):
                _check_component_index(component_index, component_count)
                # Regenerate the targeted component against an alternate head root and re-merge.
                # The emitted attestation data, message, slot, keys, and bits stay honest.
                # Only the merged proof bytes carry the alternate binding for this component.
                components[component_index] = key_manager.sign_and_aggregate(
                    self.validator_indices_per_message[component_index],
                    _alternate_head_data(self.attestation_data_per_message[component_index]),
                )
                merged = MultiMessageAggregate.aggregate(
                    components,
                    public_keys_per_aggregate=public_keys_per_message,
                )

            case IncrementEmittedSlot(component_index=component_index):
                _check_component_index(component_index, component_count)
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

            case SwapParticipantPublicKey(
                component_index=component_index,
                participant_index=participant_index,
                with_validator_index=replacement_index,
            ):
                _check_component_index(component_index, component_count)
                # The honest merge already bound the proof to the honest keys.
                # Editing the emitted key here without re-merging is what breaks verification.
                _swap_participant_public_key(
                    key_manager,
                    public_keys_per_message[component_index],
                    participant_index,
                    replacement_index,
                    component_index,
                )

            case SwapMessageBindings(
                first_component_index=first_index,
                second_component_index=second_index,
            ):
                _check_component_index(first_index, component_count)
                _check_component_index(second_index, component_count)
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

            case DropMessageBinding(component_index=component_index):
                _check_component_index(component_index, component_count)
                # Remove one component's emitted message and slot but keep its keys.
                # The binding list is now shorter than the per-component key list.
                del messages[component_index]
                del slots[component_index]

        # Phase 4: self-verify and assert the outcome against the configured expectation.
        exception_raised: Exception | None = None
        # The aggregation layer raises exactly one error type.
        # Anything else is a harness bug and propagates unswallowed.
        try:
            merged.verify(
                public_keys_per_message=public_keys_per_message,
                messages=list(zip(messages, slots, strict=True)),
            )
        except AggregationError as exception:
            exception_raised = exception
        self.assert_expected_outcome(exception_raised)

        # Phase 5: publish the client-visible outputs.
        # Every tamper breaks the proof's cryptographic binding.
        return VerifyMultiMessageProofsFixture(
            attestation_data_per_message=self.attestation_data_per_message,
            public_keys_per_message=public_keys_per_message,
            aggregation_bits_per_message=aggregation_bits_per_message,
            messages=messages,
            slots=slots,
            proof=merged.proof,
            rejection_reason=(
                self.expected_rejection.reason if self.expected_rejection is not None else None
            ),
        )
