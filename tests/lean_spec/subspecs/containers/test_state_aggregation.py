"""Tests for the State aggregation helpers introduced on the aggregation branch."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.forkchoice import GossipSignatureEntry
from lean_spec.subspecs.ssz.hash import hash_tree_root
from tests.lean_spec.helpers import (
    make_aggregated_proof,
    make_attestation_data_simple,
    make_bytes32,
    make_keyed_genesis_state,
)


def test_aggregated_signatures_prefers_full_gossip_payload(
    container_key_manager: XmssKeyManager,
) -> None:
    state = make_keyed_genesis_state(2, container_key_manager)
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(2), make_bytes32(3), make_bytes32(4), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]
    gossip_signatures = {
        att_data: {
            GossipSignatureEntry(
                ValidatorIndex(i),
                container_key_manager.sign_attestation_data(ValidatorIndex(i), att_data),
            )
            for i in range(2)
        }
    }

    results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    aggregated_atts, aggregated_proofs = (
        [att for att, _ in results],
        [proof for _, proof in results],
    )

    assert len(aggregated_atts) == 1
    assert len(aggregated_proofs) == 1
    assert set(aggregated_proofs[0].participants.to_validator_indices()) == {
        ValidatorIndex(0),
        ValidatorIndex(1),
    }

    public_keys = [container_key_manager.get_public_key(ValidatorIndex(i)) for i in range(2)]
    aggregated_proofs[0].verify(
        public_keys=public_keys,
        message=att_data.data_root_bytes(),
        slot=att_data.slot,
    )


def test_aggregate_signatures_splits_when_needed(
    container_key_manager: XmssKeyManager,
) -> None:
    """Test that gossip and aggregated proofs are kept separate."""
    state = make_keyed_genesis_state(3, container_key_manager)
    source = Checkpoint(root=make_bytes32(2), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(3), make_bytes32(5), make_bytes32(6), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]
    gossip_signatures = {
        att_data: {
            GossipSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            )
        }
    }

    block_proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1), ValidatorIndex(2)], att_data
    )

    aggregated_payloads = {
        att_data: {block_proof},
    }

    gossip_results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    payload_atts, payload_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )
    aggregated_atts = [att for att, _ in gossip_results] + payload_atts
    aggregated_proofs = [proof for _, proof in gossip_results] + payload_proofs

    seen_participants = [
        tuple(int(v) for v in att.aggregation_bits.to_validator_indices())
        for att in aggregated_atts
    ]
    assert (0,) in seen_participants
    assert (1, 2) in seen_participants
    proof_participants = [
        tuple(int(v) for v in p.participants.to_validator_indices()) for p in aggregated_proofs
    ]
    assert (0,) in proof_participants
    assert (1, 2) in proof_participants

    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        if participants == [ValidatorIndex(0)]:
            proof.verify(
                public_keys=[container_key_manager.get_public_key(ValidatorIndex(0))],
                message=att_data.data_root_bytes(),
                slot=att_data.slot,
            )


def test_build_block_collects_valid_available_attestations(
    container_key_manager: XmssKeyManager,
) -> None:
    state = make_keyed_genesis_state(2, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    head_root = make_bytes32(10)
    target = Checkpoint(root=make_bytes32(11), slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=head_root, slot=Slot(1)),
        target=target,
        source=source,
    )
    attestation = Attestation(validator_id=ValidatorIndex(0), data=att_data)
    data_root = att_data.data_root_bytes()

    proof = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data)
    aggregated_payloads = {att_data: {proof}}

    block, post_state, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        attestations=[],
        available_attestations=[attestation],
        known_block_roots={head_root},
        aggregated_payloads=aggregated_payloads,
    )

    assert post_state.latest_block_header.slot == Slot(1)
    assert list(block.body.attestations.data) == aggregated_atts
    assert len(aggregated_proofs) == 1
    assert aggregated_proofs[0].participants.to_validator_indices() == ValidatorIndices(
        data=[ValidatorIndex(0)]
    )
    assert block.body.attestations.data[0].aggregation_bits.to_validator_indices() == (
        ValidatorIndices(data=[ValidatorIndex(0)])
    )

    aggregated_proofs[0].verify(
        public_keys=[container_key_manager.get_public_key(ValidatorIndex(0))],
        message=data_root,
        slot=att_data.slot,
    )


def test_build_block_skips_attestations_without_signatures(
    container_key_manager: XmssKeyManager,
) -> None:
    state = make_keyed_genesis_state(1, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    head_root = make_bytes32(15)
    target = Checkpoint(root=make_bytes32(16), slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=head_root, slot=Slot(1)),
        target=target,
        source=source,
    )
    attestation = Attestation(validator_id=ValidatorIndex(0), data=att_data)

    block, post_state, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        attestations=[],
        available_attestations=[attestation],
        known_block_roots={head_root},
        aggregated_payloads={},
    )

    assert post_state.latest_block_header.slot == Slot(1)
    assert aggregated_atts == []
    assert aggregated_proofs == []
    assert list(block.body.attestations.data) == []


def test_aggregate_gossip_signatures_with_empty_attestations(
    container_key_manager: XmssKeyManager,
) -> None:
    """Empty attestations list should return empty results."""
    state = make_keyed_genesis_state(2, container_key_manager)

    results = state.aggregate_gossip_signatures(
        [],
        gossip_signatures={},
    )

    assert results == []


def test_aggregated_signatures_with_multiple_data_groups(
    container_key_manager: XmssKeyManager,
) -> None:
    """Multiple attestation data groups should be processed independently."""
    state = make_keyed_genesis_state(4, container_key_manager)
    source = Checkpoint(root=make_bytes32(22), slot=Slot(0))
    att_data1 = make_attestation_data_simple(
        Slot(9), make_bytes32(23), make_bytes32(24), source=source
    )
    att_data2 = make_attestation_data_simple(
        Slot(10), make_bytes32(25), make_bytes32(26), source=source
    )

    attestations = [
        Attestation(validator_id=ValidatorIndex(0), data=att_data1),
        Attestation(validator_id=ValidatorIndex(1), data=att_data1),
        Attestation(validator_id=ValidatorIndex(2), data=att_data2),
        Attestation(validator_id=ValidatorIndex(3), data=att_data2),
    ]

    gossip_signatures = {
        att_data1: {
            GossipSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data1),
            ),
            GossipSignatureEntry(
                ValidatorIndex(1),
                container_key_manager.sign_attestation_data(ValidatorIndex(1), att_data1),
            ),
        },
        att_data2: {
            GossipSignatureEntry(
                ValidatorIndex(2),
                container_key_manager.sign_attestation_data(ValidatorIndex(2), att_data2),
            ),
            GossipSignatureEntry(
                ValidatorIndex(3),
                container_key_manager.sign_attestation_data(ValidatorIndex(3), att_data2),
            ),
        },
    }

    results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    aggregated_atts, aggregated_proofs = (
        [att for att, _ in results],
        [proof for _, proof in results],
    )

    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    for agg_att, proof in zip(aggregated_atts, aggregated_proofs, strict=True):
        participants = proof.participants.to_validator_indices()
        public_keys = [container_key_manager.get_public_key(vid) for vid in participants]
        proof.verify(
            public_keys=public_keys,
            message=agg_att.data.data_root_bytes(),
            slot=agg_att.data.slot,
        )


def test_aggregated_signatures_falls_back_to_block_payload(
    container_key_manager: XmssKeyManager,
) -> None:
    """Should fall back to block payload when gossip is incomplete."""
    state = make_keyed_genesis_state(2, container_key_manager)
    source = Checkpoint(root=make_bytes32(27), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(11), make_bytes32(28), make_bytes32(29), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]

    gossip_signatures = {
        att_data: {
            GossipSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            )
        }
    }

    block_proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(0), ValidatorIndex(1)], att_data
    )

    aggregated_payloads = {att_data: {block_proof}}

    gossip_results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    payload_atts, payload_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )
    aggregated_atts = [att for att, _ in gossip_results] + payload_atts
    aggregated_proofs = [proof for _, proof in gossip_results] + payload_proofs

    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2
    proof_participants = [set(p.participants.to_validator_indices()) for p in aggregated_proofs]
    assert {ValidatorIndex(0)} in proof_participants
    assert {ValidatorIndex(0), ValidatorIndex(1)} in proof_participants

    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        if participants == [ValidatorIndex(0)]:
            proof.verify(
                public_keys=[container_key_manager.get_public_key(ValidatorIndex(0))],
                message=att_data.data_root_bytes(),
                slot=att_data.slot,
            )


def test_build_block_state_root_valid_when_signatures_split(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Verify state root validity when attestations split across signature sources.

    Signatures arrive through two channels in the protocol:

    1. Gossip network - individual validator signatures propagated in real-time
    2. Aggregated proofs - batched signatures from block payloads

    When both sources cover the same attestation data, they cannot always merge.
    Each source may cover different validator subsets.
    The aggregation process must split them into separate attestations.

    This creates a critical constraint: the block's state root must reflect
    the final attestation structure, not a preliminary grouping.

    Test scenario:

    - Three validators attest to identical data
    - One signature arrives via gossip (validator 0)
    - Two signatures arrive via aggregated proof (validators 1, 2)
    - Result: two attestations in the block, not one
    - The state transition must succeed with correct state root
    """
    num_validators = 4
    pre_state = make_keyed_genesis_state(num_validators, container_key_manager)

    parent_header_with_state_root = pre_state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(pre_state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)

    source = Checkpoint(root=parent_root, slot=Slot(0))
    head_root = make_bytes32(50)
    target = Checkpoint(root=make_bytes32(51), slot=Slot(0))

    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=head_root, slot=Slot(1)),
        target=target,
        source=source,
    )

    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]

    proof_0 = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data)

    fallback_proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1), ValidatorIndex(2)], att_data
    )
    aggregated_payloads = {att_data: {proof_0, fallback_proof}}

    block, post_state, aggregated_atts, _ = pre_state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        attestations=attestations,
        aggregated_payloads=aggregated_payloads,
    )

    assert len(aggregated_atts) == 2, "Expected split into 2 attestations"

    actual_bits = [set(att.aggregation_bits.to_validator_indices()) for att in aggregated_atts]
    assert {ValidatorIndex(0)} in actual_bits, "First attestation should cover only validator 0"
    assert {ValidatorIndex(1), ValidatorIndex(2)} in actual_bits, (
        "Fallback should cover validators 1,2"
    )

    result_state = pre_state.state_transition(block, valid_signatures=True)

    assert result_state.slot == Slot(1)
    assert result_state.latest_block_header.slot == Slot(1)
    assert result_state.latest_block_header.proposer_index == ValidatorIndex(1)
    assert result_state.latest_block_header.parent_root == parent_root
    assert block.state_root == hash_tree_root(result_state)
    assert len(block.body.attestations.data) == 2
    assert len(result_state.validators.data) == num_validators


def test_greedy_selects_proof_with_maximum_overlap(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Verify greedy algorithm selects the proof covering the most remaining validators.

    Scenario
    --------
    - 4 validators need coverage from fallback (no gossip)
    - Three available proofs:
        - Proof A: {0, 1} (covers 2)
        - Proof B: {1, 2, 3} (covers 3)
        - Proof C: {3} (covers 1)

    Expected Behavior
    -----------------
    - First iteration: B selected (largest overlap with remaining={0,1,2,3})
    - After B: remaining={0}
    - Second iteration: A selected (covers 0)
    - Result: 2 proofs instead of 3
    """
    state = make_keyed_genesis_state(4, container_key_manager)
    source = Checkpoint(root=make_bytes32(60), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(12), make_bytes32(61), make_bytes32(62), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(4)]

    proof_a = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(0), ValidatorIndex(1)], att_data
    )
    proof_b = make_aggregated_proof(
        container_key_manager,
        [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        att_data,
    )
    proof_c = make_aggregated_proof(container_key_manager, [ValidatorIndex(3)], att_data)

    aggregated_payloads = {att_data: {proof_a, proof_b, proof_c}}

    aggregated_atts, aggregated_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )

    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    all_participants: set[int] = set()
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        all_participants.update(int(v) for v in participants)
    assert all_participants == {0, 1, 2, 3}, f"All validators should be covered: {all_participants}"


def test_greedy_stops_when_no_useful_proofs_remain(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Verify algorithm terminates gracefully when no proofs can cover remaining validators.

    Scenario
    --------
    - 5 validators need attestations
    - Gossip covers {0, 1}
    - Available proofs only cover {2, 3} (no proof for validator 4)

    Expected Behavior
    -----------------
    - Gossip creates attestation for {0, 1}
    - Fallback finds proof for {2, 3}
    - Validator 4 remains uncovered (no infinite loop or crash)
    """
    state = make_keyed_genesis_state(5, container_key_manager)
    source = Checkpoint(root=make_bytes32(70), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(13), make_bytes32(71), make_bytes32(72), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(5)]

    gossip_signatures = {
        att_data: {
            GossipSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            ),
            GossipSignatureEntry(
                ValidatorIndex(1),
                container_key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
            ),
        }
    }

    proof_23 = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(2), ValidatorIndex(3)], att_data
    )

    aggregated_payloads = {att_data: {proof_23}}

    gossip_results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    payload_atts, payload_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )
    aggregated_atts = [att for att, _ in gossip_results] + payload_atts
    aggregated_proofs = [proof for _, proof in gossip_results] + payload_proofs

    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    all_participants: set[int] = set()
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        all_participants.update(int(v) for v in participants)

    assert 4 not in all_participants, "Validator 4 should not be covered"
    assert all_participants == {0, 1, 2, 3}, f"Expected {{0,1,2,3}} covered: {all_participants}"


def test_greedy_handles_overlapping_proof_chains(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test complex scenario with overlapping proofs requiring optimal selection.

    Scenario
    --------
    - 5 validators, gossip covers {0}
    - Remaining: {1, 2, 3, 4}
    - Available proofs:
        - Proof A: {1, 2} (covers 2)
        - Proof B: {2, 3} (covers 2, overlaps with A)
        - Proof C: {3, 4} (covers 2, overlaps with B)

    Expected Behavior
    -----------------
    Greedy may select: A, then C (covers {1,2,3,4} with 2 proofs)
    OR: B first, then needs A+C (suboptimal)

    The key is that all 4 remaining validators get covered.
    """
    state = make_keyed_genesis_state(5, container_key_manager)
    source = Checkpoint(root=make_bytes32(80), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(14), make_bytes32(81), make_bytes32(82), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(5)]

    gossip_signatures = {
        att_data: {
            GossipSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            ),
        }
    }

    proof_a = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1), ValidatorIndex(2)], att_data
    )
    proof_b = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(2), ValidatorIndex(3)], att_data
    )
    proof_c = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(3), ValidatorIndex(4)], att_data
    )

    aggregated_payloads = {att_data: {proof_a, proof_b, proof_c}}

    gossip_results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    payload_atts, payload_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )
    aggregated_atts = [att for att, _ in gossip_results] + payload_atts
    aggregated_proofs = [proof for _, proof in gossip_results] + payload_proofs

    assert len(aggregated_atts) >= 3
    assert len(aggregated_proofs) >= 3

    all_participants: set[int] = set()
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        all_participants.update(int(v) for v in participants)

    assert all_participants == {0, 1, 2, 3, 4}, (
        f"All 5 validators should be covered: {all_participants}"
    )


def test_greedy_single_validator_proofs(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test fallback when only single-validator proofs are available.

    Scenario
    --------
    - 3 validators need fallback coverage
    - Only single-validator proofs available

    Expected Behavior
    -----------------
    Each validator gets their own proof (3 proofs total).
    """
    state = make_keyed_genesis_state(3, container_key_manager)
    source = Checkpoint(root=make_bytes32(90), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(15), make_bytes32(91), make_bytes32(92), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]

    proofs = [
        make_aggregated_proof(container_key_manager, [ValidatorIndex(i)], att_data)
        for i in range(3)
    ]

    aggregated_payloads = {att_data: set(proofs)}

    aggregated_atts, aggregated_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )

    assert len(aggregated_atts) == 3
    assert len(aggregated_proofs) == 3

    seen_validators: set[int] = set()
    for proof in aggregated_proofs:
        participants = [int(v) for v in proof.participants.to_validator_indices()]
        assert len(participants) == 1, "Each proof should cover exactly 1 validator"
        seen_validators.update(participants)

    assert seen_validators == {0, 1, 2}


def test_validator_in_both_gossip_and_fallback_proof(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test behavior when a validator appears in both gossip signatures AND fallback proof.

    Scenario
    --------
    - Validator 0 has a gossip signature
    - Validator 1 needs fallback coverage
    - The only available fallback proof covers BOTH validators {0, 1}

    Current Behavior
    ----------------
    - Gossip creates attestation for {0}
    - Fallback uses the proof for {0, 1} to cover validator 1
    - Both attestations are included in the block

    This test documents the current behavior. Validator 0 appears in both:
    - The gossip attestation (participants={0})
    - The fallback attestation (participants={0, 1})

    Note: This could be considered duplicate coverage, but the fallback proof
    cannot be "split" - it must be used as-is.
    """
    state = make_keyed_genesis_state(2, container_key_manager)
    source = Checkpoint(root=make_bytes32(100), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(16), make_bytes32(101), make_bytes32(102), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]

    gossip_signatures = {
        att_data: {
            GossipSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            ),
        }
    }

    fallback_proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(0), ValidatorIndex(1)], att_data
    )

    aggregated_payloads = {att_data: {fallback_proof}}

    gossip_results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    payload_atts, payload_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )
    aggregated_atts = [att for att, _ in gossip_results] + payload_atts
    aggregated_proofs = [proof for _, proof in gossip_results] + payload_proofs

    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    proof_participants = [
        {int(v) for v in p.participants.to_validator_indices()} for p in aggregated_proofs
    ]

    assert {0} in proof_participants, "Gossip attestation should cover validator 0"
    assert {0, 1} in proof_participants, "Fallback proof should cover {0, 1}"

    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        public_keys = [container_key_manager.get_public_key(vid) for vid in participants]
        proof.verify(
            public_keys=public_keys,
            message=att_data.data_root_bytes(),
            slot=att_data.slot,
        )


def test_gossip_none_and_aggregated_payloads_none(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test edge case where both gossip_signatures and aggregated_payloads are None.

    Expected Behavior
    -----------------
    Returns empty results (no attestations can be aggregated without signatures).
    """
    state = make_keyed_genesis_state(2, container_key_manager)
    source = Checkpoint(root=make_bytes32(110), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(17), make_bytes32(111), make_bytes32(112), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]

    results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=None,
    )

    assert results == []


def test_aggregated_payloads_only_no_gossip(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test aggregation with aggregated_payloads only (no gossip signatures).

    Scenario
    --------
    - 3 validators need attestation
    - No gossip signatures available
    - Aggregated proof available covering all 3

    Expected Behavior
    -----------------
    Single attestation from the fallback proof.
    """
    state = make_keyed_genesis_state(3, container_key_manager)
    source = Checkpoint(root=make_bytes32(120), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(18), make_bytes32(121), make_bytes32(122), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]
    data_root = att_data.data_root_bytes()

    proof = make_aggregated_proof(
        container_key_manager,
        [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
        att_data,
    )

    aggregated_payloads = {att_data: {proof}}

    aggregated_atts, aggregated_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )

    assert len(aggregated_atts) == 1
    assert len(aggregated_proofs) == 1

    participants = {int(v) for v in aggregated_proofs[0].participants.to_validator_indices()}
    assert participants == {0, 1, 2}

    public_keys = [container_key_manager.get_public_key(ValidatorIndex(i)) for i in range(3)]
    aggregated_proofs[0].verify(public_keys=public_keys, message=data_root, slot=att_data.slot)


def test_proof_with_extra_validators_beyond_needed(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test that fallback proof including extra validators works correctly.

    Scenario
    --------
    - 2 validators attest (indices 0 and 1)
    - Gossip covers validator 0
    - Fallback proof covers {0, 1, 2, 3} (includes validators not in attestation)

    Expected Behavior
    -----------------
    - Gossip attestation for {0}
    - Fallback proof used as-is (includes extra validators 2, 3)

    The proof cannot be "trimmed" to exclude extra validators.
    """
    state = make_keyed_genesis_state(4, container_key_manager)
    source = Checkpoint(root=make_bytes32(130), slot=Slot(0))
    att_data = make_attestation_data_simple(
        Slot(19), make_bytes32(131), make_bytes32(132), source=source
    )
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]

    gossip_signatures = {
        att_data: {
            GossipSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            ),
        }
    }

    proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(i) for i in range(4)], att_data
    )

    aggregated_payloads = {att_data: {proof}}

    gossip_results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    payload_atts, payload_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )
    aggregated_atts = [att for att, _ in gossip_results] + payload_atts
    aggregated_proofs = [proof for _, proof in gossip_results] + payload_proofs

    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    proof_participants = [
        {int(v) for v in p.participants.to_validator_indices()} for p in aggregated_proofs
    ]
    assert {0} in proof_participants
    assert {0, 1, 2, 3} in proof_participants
