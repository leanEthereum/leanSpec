"""Test vectors for gossip attestation validation."""

import pytest
from consensus_testing import (
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAttestationSpec,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_valid_gossip_attestation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Valid gossip attestation is processed successfully.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Submit a valid gossip attestation from validator 1 for slot 2.

    Expected:
        - Attestation is validated and stored successfully
        - Store head remains at slot 2
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
                    validator_id=ValidatorIndex(1),
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
    Attestation with target checkpoint slot mismatch is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Attempt to submit attestation where target_slot (3) does not match
    the target block's actual slot (2).

    Expected:
        - Validation fails with "Target checkpoint slot mismatch" error
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(3),
                    target_root_label="block_2",
                ),
                valid=False,
            ),
        ],
    )


def test_attestation_too_far_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation for slot too far in the future is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Attempt to submit attestation for slot 4 (2 slots in the future).

    Expected:
        - Validation fails with "Attestation too far in future" error
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
            ),
        ],
    )


def test_attestation_one_slot_in_future_allowed(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation exactly one slot in the future is allowed.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Submit attestation for slot 3 (one slot in future, allowed margin).

    Expected:
        - Attestation is validated successfully
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
        ],
    )


def test_multiple_gossip_attestations_from_different_validators(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Multiple gossip attestations from different validators are processed.

    Scenario
    --------
    Build a chain with blocks at slots 1-5.
    Submit gossip attestations from multiple validators.

    Expected:
        - All attestations are validated and stored
        - No conflicts between validators
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
                    validator_id=ValidatorIndex(0),
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(1),
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(2),
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
    Attestation with invalid signature is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Attempt to submit attestation with dummy (invalid) signature.

    Expected:
        - Signature verification fails
        - Attestation is rejected
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    valid_signature=False,
                ),
                valid=False,
            ),
        ],
    )


def test_gossip_attestation_with_unknown_validator(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation from unknown validator is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Attempt to submit attestation with validator index beyond registry.

    Expected:
        - Validator lookup fails
        - Attestation is rejected
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
                    validator_id=ValidatorIndex(999),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    valid_signature=False,
                ),
                valid=False,
            ),
        ],
    )


def test_attestation_source_slot_exceeds_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation where source slot exceeds target slot is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1, 2, and 3.
    Submit attestation with source at slot 3 and target at slot 2.

    Expected:
        - Validation fails with "Source checkpoint slot must not exceed target"
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
                valid=False,
            ),
        ],
    )


def test_attestation_head_older_than_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation where head slot is older than target slot is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1, 2, and 3.
    Submit attestation with target at slot 3 but head pointing to slot 1.

    Expected:
        - Validation fails with "Head checkpoint must not be older than target"
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    head_root_label="block_1",
                ),
                valid=False,
            ),
        ],
    )


def test_attestation_source_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation with source checkpoint slot mismatch is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Submit attestation where the source slot (5) does not match
    the source block's actual slot (0, the genesis/anchor block).

    Expected:
        - Validation fails with "Source checkpoint slot mismatch"
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_slot=Slot(5),
                ),
                valid=False,
            ),
        ],
    )


def test_attestation_head_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestation with head checkpoint slot mismatch is rejected.

    Scenario
    --------
    Build a chain with blocks at slots 1 and 2.
    Submit attestation where the head slot (5) does not match
    the head block's actual slot (2).

    Expected:
        - Validation fails with "Head checkpoint slot mismatch"
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
                    validator_id=ValidatorIndex(1),
                    slot=Slot(5),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    head_slot=Slot(5),
                ),
                valid=False,
            ),
        ],
    )


def test_gossip_attestation_chain_extended_after_gossip(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Chain can be extended after processing gossip attestations.

    Scenario
    --------
    Build a chain and submit gossip attestations.
    Extend the chain with new blocks.

    Expected:
        - Gossip attestations are preserved
        - Chain extension succeeds
        - Head advances to new block
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
                    validator_id=ValidatorIndex(0),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(1),
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
