"""Test vectors for gossip attestation validation."""

import pytest

from consensus_testing import (
    AttestationStep,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    GossipAttestationSpec,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import GOSSIP_DISPARITY_INTERVALS
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


SLOT_3_BOUNDARY_INTERVAL = int(Interval.from_slot(Slot(3))) - int(GOSSIP_DISPARITY_INTERVALS)
"""Latest local interval that still admits a slot-3 vote."""

SLOT_3_JUST_BEYOND_BOUNDARY_INTERVAL = SLOT_3_BOUNDARY_INTERVAL - 1
"""First local interval that rejects a slot-3 vote."""


def test_valid_gossip_attestation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A valid gossip attestation is accepted.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote for block_2 at slot 2.

    Then
    ----
    - the attestation is validated and stored.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
        ],
    )


def test_attestation_target_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose target slot disagrees with the target block is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote naming target slot 3 for block_2, which sits at slot 2.

    Then
    ----
    - validation fails with a target checkpoint slot mismatch.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(3),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.TARGET_SLOT_MISMATCH,
                    message_substring="Target checkpoint slot mismatch",
                ),
            ),
        ],
    )


def test_attestation_too_far_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose slot is two slots ahead of local time is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is at slot 2.

    When
    ----
    - V1 gossips a vote at slot 4, two slots in the future.

    Then
    ----
    - validation fails with attestation too far in future.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE,
                    message_substring="Attestation too far in future",
                ),
            ),
        ],
    )


def test_attestation_at_disparity_boundary_allowed(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote exactly at the disparity boundary is accepted.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is the latest interval that still admits a slot-3 vote.

    When
    ----
    - V1 gossips a vote at slot 3.

    Then
    ----
    - the attestation is validated.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            TickStep(interval=SLOT_3_BOUNDARY_INTERVAL),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
        ],
    )


def test_attestation_just_beyond_disparity_boundary_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote one interval beyond the disparity boundary is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is one interval before the boundary for a slot-3 vote.

    When
    ----
    - V1 gossips a vote at slot 3.

    Then
    ----
    - validation fails with attestation too far in future.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            TickStep(interval=SLOT_3_JUST_BEYOND_BOUNDARY_INTERVAL),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE,
                    message_substring="Attestation too far in future",
                ),
            ),
        ],
    )


def test_attestation_one_full_slot_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote a full slot ahead of local time is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is slot 2 interval 0.

    When
    ----
    - V1 gossips a vote at slot 3, five intervals ahead.

    Then
    ----
    - validation fails with attestation too far in future.

    Regression
    ----------
    - an earlier rule admitted votes up to a full slot ahead.
    - that window let an adversary pre-publish next-slot votes early.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE,
                    message_substring="Attestation too far in future",
                ),
            ),
        ],
    )


def test_multiple_gossip_attestations_from_different_validators(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Gossip votes from several validators are each accepted independently.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)

    When
    ----
    - V0 gossips a vote for block_5.
    - V1 gossips a vote for block_5.
    - V2 gossips a vote for block_5.

    Then
    ----
    - every vote is validated and stored.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), label="block_4"),
                checks=StoreChecks(head_slot=Slot(4)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), label="block_5"),
                checks=StoreChecks(head_slot=Slot(5)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(0),
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(2),
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                ),
            ),
        ],
    )


def test_gossip_attestation_with_invalid_signature(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote carrying an invalid signature is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote for block_2 with an invalid signature.

    Then
    ----
    - signature verification fails.
    - the attestation is rejected.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.INVALID_SIGNATURE,
                    message_substring="Signature verification failed",
                ),
            ),
        ],
    )


def test_gossip_attestation_with_unknown_validator(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote from a validator index outside the registry is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V999 gossips a vote for block_2.

    Then
    ----
    - the validator lookup fails.
    - the attestation is rejected.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(999),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.VALIDATOR_NOT_IN_STATE,
                    message_substring="not found in state",
                ),
            ),
        ],
    )


def test_attestation_source_slot_exceeds_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose source slot exceeds its target slot is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2) -> block_3(3)

    When
    ----
    - V1 gossips a vote with source block_3 at slot 3 and target block_2 at slot 2.

    Then
    ----
    - validation fails because source slot must not exceed target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.SOURCE_AFTER_TARGET,
                    message_substring="Source checkpoint slot must not exceed target",
                ),
            ),
        ],
    )


def test_attestation_head_older_than_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose head is older than its target is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2) -> block_3(3)

    When
    ----
    - V1 gossips a vote with target block_3 at slot 3 and head block_1 at slot 1.

    Then
    ----
    - validation fails because head must not be older than target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    head_root_label="block_1",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.HEAD_OLDER_THAN_TARGET,
                    message_substring="Head checkpoint must not be older than target",
                ),
            ),
        ],
    )


def test_attestation_source_slot_override_exceeds_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose overridden source slot exceeds its target slot is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote for target block_2 at slot 2 with source slot 5.

    Then
    ----
    - validation fails because source slot 5 exceeds target slot 2.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_slot=Slot(5),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.SOURCE_AFTER_TARGET,
                    message_substring="Source checkpoint slot must not exceed target",
                ),
            ),
        ],
    )


def test_attestation_source_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose source slot disagrees with the source block is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - the source block is the genesis anchor at slot 0.

    When
    ----
    - V1 gossips a vote for block_2 naming source slot 1.
    - source slot 1 still stays at or below target slot 2.

    Then
    ----
    - validation fails with a source checkpoint slot mismatch.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_slot=Slot(1),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.SOURCE_SLOT_MISMATCH,
                    message_substring="Source checkpoint slot mismatch",
                ),
            ),
        ],
    )


def test_attestation_head_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose head slot disagrees with the head block is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote naming head slot 5 for block_2, which sits at slot 2.

    Then
    ----
    - validation fails with a head checkpoint slot mismatch.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(5),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    head_slot=Slot(5),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.HEAD_SLOT_MISMATCH,
                    message_substring="Head checkpoint slot mismatch",
                ),
            ),
        ],
    )


def test_gossip_attestation_chain_extended_after_gossip(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The chain extends normally after gossip votes have been processed.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - V0 has gossiped a vote for block_2.
    - V1 has gossiped a vote for block_2.

    When
    ----
    - block_3 then block_4 extend the chain.

    Then
    ----
    - the gossip votes are preserved.
    - head advances to block_4.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(0),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), label="block_4"),
                checks=StoreChecks(head_slot=Slot(4)),
            ),
        ],
    )


FAKE_ROOT = Bytes32(b"\xde\xad" + b"\x00" * 30)
"""A root that will never appear in the store."""


def test_attestation_unknown_target_block_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose target root is absent from the store is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote whose target root does not exist in the store.

    Then
    ----
    - validation fails with an unknown target block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    target_root=FAKE_ROOT,
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.UNKNOWN_TARGET_BLOCK,
                    message_substring="Unknown target block",
                ),
            ),
        ],
    )


def test_attestation_unknown_head_block_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose head root is absent from the store is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote whose head root does not exist in the store.

    Then
    ----
    - validation fails with an unknown head block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    head_root=FAKE_ROOT,
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.UNKNOWN_HEAD_BLOCK,
                    message_substring="Unknown head block",
                ),
            ),
        ],
    )


def test_attestation_unknown_source_block_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose source root is absent from the store is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips a vote whose source root does not exist in the store.

    Then
    ----
    - validation fails with an unknown source block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root=FAKE_ROOT,
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.UNKNOWN_SOURCE_BLOCK,
                    message_substring="Unknown source block",
                ),
            ),
        ],
    )


def test_attestation_head_on_sibling_fork_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose head sits on a sibling fork of its target is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        base(1)
        - fork_left(2)
        - fork_right(3)
    - fork_left and fork_right are siblings of base.
    - distinct slots give the siblings distinct roots.

    When
    ----
    - V1 gossips a vote with source base, target fork_left, and head fork_right.
    - every slot and availability check passes.

    Then
    ----
    - validation fails because target must be an ancestor of head.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_left"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_right"),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="fork_left",
                    head_slot=Slot(3),
                    head_root_label="fork_right",
                    source_root_label="base",
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.TARGET_NOT_ANCESTOR_OF_HEAD,
                    message_substring="Target checkpoint must be ancestor of head",
                ),
            ),
        ],
    )


def test_attestation_source_on_sibling_fork_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose source sits on a sibling fork of its target is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        base(1)
        - fork_left(2)
        - fork_right(3) -> fork_right_head(4)
    - fork_left lies on a branch the vote does not extend.
    - distinct slots give the branches distinct roots.

    When
    ----
    - V1 gossips a vote with source fork_left, target fork_right_head, and head fork_right_head.
    - source slot 2 precedes the target slot 4.

    Then
    ----
    - validation fails because source must be an ancestor of target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_left"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_right"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_right", label="fork_right_head"),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(4),
                    target_slot=Slot(4),
                    target_root_label="fork_right_head",
                    head_root_label="fork_right_head",
                    source_root_label="fork_left",
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.SOURCE_NOT_ANCESTOR_OF_TARGET,
                    message_substring="Source checkpoint must be ancestor of target",
                ),
            ),
        ],
    )
