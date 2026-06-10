"""Fork choice ancestry climb branches in attestation validation."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    GossipAttestationSpec,
    StoreChecks,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_attestation_source_on_same_slot_fork_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A vote whose source shares its target chain's slot but not its root is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        base(1)
        - fork_a(2)
        - fork_b(2) -> head_3(3)
    - fork_a and fork_b both sit at slot 2 under base.
    - fork_a includes V0's vote for base.
    - fork_b includes V1's vote for base.
    - the differing votes give the same-slot siblings distinct roots.

    When
    ----
    - V1 gossips a vote with source fork_a, target head_3, and head head_3.
    - source slot 2 precedes the target slot 3.
    - climbing the target chain lands on fork_b at slot 2, the source slot.

    Then
    ----
    - the landed root fork_b differs from the source root fork_a.
    - validation fails because source must be an ancestor of target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="base",
                    label="fork_a",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="base",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="base",
                    label="fork_b",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="base",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_b", label="head_3"),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(3),
                    target_root_label="head_3",
                    head_root_label="head_3",
                    source_root_label="fork_a",
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
