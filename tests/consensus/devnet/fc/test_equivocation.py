"""Equivocating Proposer Tests."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    GossipAttestationSpec,
    StoreChecks,
    TickStep,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_equivocating_proposer_two_blocks_at_same_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Two blocks at the same slot from the same proposer are both accepted.

    Scenario
    --------
    - Slot 1: Build common ancestor
    - Slot 2: Proposer publishes first block with an attestation from validator 0
    - Slot 2: Same proposer publishes second block with an attestation from validator 1

    Both equivocating blocks include an attestation targeting the common ancestor.
    This ensures different block bodies (and therefore different roots) without
    giving either block an attestation-weight advantage over the other.

    Expected Behavior
    -----------------
    - Both blocks are accepted by the fork choice store.
    - After the first equivocating block, head is at slot 2.
    - After the second equivocating block, both have equal weight.
    - Head is chosen by lexicographic tiebreaker among the two equivocating roots.
    - Head remains at slot 2 throughout.
    """
    fork_choice_test(
        steps=[
            # Common ancestor at slot 1
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            # First equivocating block at slot 2
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="equivocation_a",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="equivocation_a",
                ),
            ),
            # Second equivocating block at slot 2 with different attestation
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="equivocation_b",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    lexicographic_head_among=["equivocation_a", "equivocation_b"],
                ),
            ),
        ],
    )


def test_equivocating_proposer_with_split_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Attestations split across equivocating forks; head follows weight.

    Scenario
    --------
    Six validators. An equivocating proposer produces two blocks at slot 2.
    Honest validators split their attestations across the two forks:

    - Slot 1: Common ancestor (block_1)
    - Slot 2: fork_a (equivocation with V0 in-block attestation for block_1)
    - Slot 2: fork_b (equivocation with V1 in-block attestation for block_1)

    Phase 1 -- 2 vs 2:
        V0, V1 gossip-attest to fork_a. V2, V3 gossip-attest to fork_b.
        Equal weight triggers the lexicographic tiebreaker.

    Phase 2 -- 3 vs 2:
        V4 gossip-attests to fork_b, breaking the tie.
        fork_b now has 3 attestations vs fork_a's 2.

    Both equivocating blocks carry a different in-block attestation targeting
    the common ancestor. This gives them different block roots without
    providing an attestation-weight advantage to either fork.

    Expected Behavior
    -----------------
    - Phase 1: Head is chosen by lexicographic tiebreaker among fork_a, fork_b.
    - Phase 2: Head is fork_b (3 > 2 attestation weight).
    - Both forks remain in the store throughout.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            # Common ancestor at slot 1
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            # First equivocating block at slot 2
            # In-block attestation from V0 targeting block_1 (differentiates body)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="fork_a",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a",
                ),
            ),
            # Second equivocating block at slot 2
            # In-block attestation from V1 targeting block_1 (differentiates body)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="fork_b",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
            ),
            # Phase 1: V0, V1 gossip-attest to fork_a (2 votes)
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(0),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_a",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_a",
                ),
            ),
            # Phase 1: V2, V3 gossip-attest to fork_b (2 votes)
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(2),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_b",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(3),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_b",
                ),
            ),
            # Tick to accept gossip attestations (interval 4 of slot 2 = interval 14)
            # time=12s -> 12000ms / 800 = interval 15, passing through interval 14
            TickStep(
                time=12,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
            ),
            # Phase 2: V4 gossip-attests to fork_b (now 3 vs 2)
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(4),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_b",
                ),
            ),
            # Tick to accept V4's attestation (interval 4 of slot 3 = interval 19)
            # time=16s -> 16000ms / 800 = interval 20, passing through interval 19
            TickStep(
                time=16,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_b",
                ),
            ),
        ],
    )


def test_same_slot_equivocating_attesters_count_once(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Same-slot conflicting attestations from the same validators count once.

    Scenario
    --------
    Eight validators. Two forks diverge from a common ancestor:

    - fork_a receives slot-3 votes from validators 0, 1, and 2
    - fork_b receives slot-3 votes from validators 0, 1, 3, and 4

    Validators 0 and 1 equivocate by signing both fork votes at the same
    attestation slot. Their later conflicting vote must not add weight to
    fork_b while still counting for fork_a.

    Expected Behavior
    -----------------
    1. fork_a has effective weight 3
    2. fork_b has effective weight 2
    3. Head stays on fork_a
    4. No checkpoint is justified by the below-threshold votes
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="fork_a"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="common", label="fork_b"),
                checks=StoreChecks(lexicographic_head_among=["fork_a", "fork_b"]),
            ),
            TickStep(interval=18),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="fork_a",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(3),
                        ValidatorIndex(4),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(3),
                    target_root_label="fork_b",
                ),
            ),
            TickStep(
                time=16,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a",
                    latest_justified_slot=Slot(0),
                    latest_finalized_slot=Slot(0),
                    latest_known_aggregated_target_slots=[Slot(2), Slot(3)],
                ),
            ),
        ],
    )
