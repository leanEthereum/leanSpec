"""Tests for the State aggregation helpers introduced on the aggregation branch."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.containers.attestation import AttestationData
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.forkchoice import AttestationSignatureEntry
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
    attestation_signatures = {
        att_data: {
            AttestationSignatureEntry(
                ValidatorIndex(i),
                container_key_manager.sign_attestation_data(ValidatorIndex(i), att_data),
            )
            for i in range(2)
        }
    }

    results = state.aggregate(attestation_signatures=attestation_signatures)
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

    public_keys = [container_key_manager[ValidatorIndex(i)].attestation_public for i in range(2)]
    aggregated_proofs[0].verify(
        public_keys=public_keys,
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
    target = Checkpoint(root=parent_root, slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=target,
        source=source,
    )
    data_root = att_data.data_root_bytes()

    proof = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data)
    aggregated_payloads = {att_data: {proof}}

    block, post_state, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
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
        public_keys=[container_key_manager[ValidatorIndex(0)].attestation_public],
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

    block, post_state, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={},
    )

    assert post_state.latest_block_header.slot == Slot(1)
    assert aggregated_atts == []
    assert aggregated_proofs == []
    assert list(block.body.attestations.data) == []


def test_aggregate_attestation_signatures_with_empty_attestations(
    container_key_manager: XmssKeyManager,
) -> None:
    """Empty attestations list should return empty results."""
    state = make_keyed_genesis_state(2, container_key_manager)

    results = state.aggregate(attestation_signatures={})

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

    attestation_signatures = {
        att_data1: {
            AttestationSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), att_data1),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(1),
                container_key_manager.sign_attestation_data(ValidatorIndex(1), att_data1),
            ),
        },
        att_data2: {
            AttestationSignatureEntry(
                ValidatorIndex(2),
                container_key_manager.sign_attestation_data(ValidatorIndex(2), att_data2),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(3),
                container_key_manager.sign_attestation_data(ValidatorIndex(3), att_data2),
            ),
        },
    }

    results = state.aggregate(attestation_signatures=attestation_signatures)
    aggregated_atts, aggregated_proofs = (
        [att for att, _ in results],
        [proof for _, proof in results],
    )

    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    for agg_att, proof in zip(aggregated_atts, aggregated_proofs, strict=True):
        participants = proof.participants.to_validator_indices()
        public_keys = [container_key_manager[vid].attestation_public for vid in participants]
        proof.verify(
            public_keys=public_keys,
            message=agg_att.data.data_root_bytes(),
            slot=agg_att.data.slot,
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
    target = Checkpoint(root=parent_root, slot=Slot(0))

    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=target,
        source=source,
    )

    proof_0 = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data)

    fallback_proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1), ValidatorIndex(2)], att_data
    )
    aggregated_payloads = {att_data: {proof_0, fallback_proof}}

    block, _, aggregated_atts, _ = pre_state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
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


def test_build_block_greedy_selects_minimum_proofs(
    container_key_manager: XmssKeyManager,
) -> None:
    """Greedy selection picks the minimum set of proofs to cover all validators."""
    state = make_keyed_genesis_state(4, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    target = Checkpoint(root=parent_root, slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=target,
        source=source,
    )

    # Three overlapping proofs: {0,1,2}, {1,2,3}, {2,3}
    # Greedy should pick {0,1,2} first (covers 3), then {1,2,3} (covers 1 new: validator 3)
    proof_012 = make_aggregated_proof(
        container_key_manager,
        [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
        att_data,
    )
    proof_123 = make_aggregated_proof(
        container_key_manager,
        [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        att_data,
    )
    proof_23 = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(2), ValidatorIndex(3)], att_data
    )
    aggregated_payloads = {att_data: {proof_012, proof_123, proof_23}}

    _, _, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads=aggregated_payloads,
    )

    all_covered = set()
    for proof in aggregated_proofs:
        all_covered |= set(proof.participants.to_validator_indices())

    assert all_covered == {ValidatorIndex(i) for i in range(4)}
    assert len(aggregated_proofs) == 2
    assert len(aggregated_atts) == 2


def test_build_block_greedy_selects_all_single_validator_proofs(
    container_key_manager: XmssKeyManager,
) -> None:
    """Greedy selection should keep all disjoint single-validator proofs."""
    state = make_keyed_genesis_state(3, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=source,
    )

    aggregated_payloads = {
        att_data: {
            make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data),
            make_aggregated_proof(container_key_manager, [ValidatorIndex(1)], att_data),
            make_aggregated_proof(container_key_manager, [ValidatorIndex(2)], att_data),
        }
    }

    _, _, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads=aggregated_payloads,
    )

    expected_participant_sets = {(0,), (1,), (2,)}
    proof_participant_sets = {
        tuple(sorted(int(v) for v in proof.participants.to_validator_indices()))
        for proof in aggregated_proofs
    }
    att_participant_sets = {
        tuple(sorted(int(v) for v in att.aggregation_bits.to_validator_indices()))
        for att in aggregated_atts
    }

    assert proof_participant_sets == expected_participant_sets
    assert att_participant_sets == expected_participant_sets


def test_build_block_greedy_tie_chain_skips_redundant_proof(
    container_key_manager: XmssKeyManager,
) -> None:
    """Overlapping tie chains should cover all validators without selecting zero-gain proofs."""
    state = make_keyed_genesis_state(5, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=source,
    )

    proof_12 = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1), ValidatorIndex(2)], att_data
    )
    proof_23 = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(2), ValidatorIndex(3)], att_data
    )
    proof_34 = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(3), ValidatorIndex(4)], att_data
    )
    proof_2 = make_aggregated_proof(container_key_manager, [ValidatorIndex(2)], att_data)

    _, _, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={att_data: {proof_12, proof_23, proof_34, proof_2}},
    )

    proof_participant_sets = {
        tuple(sorted(int(v) for v in proof.participants.to_validator_indices()))
        for proof in aggregated_proofs
    }
    covered_validators = {
        validator for participants in proof_participant_sets for validator in participants
    }
    att_participant_sets = {
        tuple(sorted(int(v) for v in att.aggregation_bits.to_validator_indices()))
        for att in aggregated_atts
    }

    assert covered_validators == {1, 2, 3, 4}
    assert (2,) not in proof_participant_sets
    assert 2 <= len(aggregated_proofs) <= 3
    assert att_participant_sets == proof_participant_sets


def test_build_block_greedy_skips_subset_when_superset_selected(
    container_key_manager: XmssKeyManager,
) -> None:
    """Subset proof should be skipped after a superset has already covered it."""
    state = make_keyed_genesis_state(3, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=source,
    )

    proof_0 = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data)
    proof_01 = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(0), ValidatorIndex(1)], att_data
    )
    proof_2 = make_aggregated_proof(container_key_manager, [ValidatorIndex(2)], att_data)

    _, _, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={att_data: {proof_0, proof_01, proof_2}},
    )

    expected_participant_sets = {(0, 1), (2,)}
    proof_participant_sets = {
        tuple(sorted(int(v) for v in proof.participants.to_validator_indices()))
        for proof in aggregated_proofs
    }
    att_participant_sets = {
        tuple(sorted(int(v) for v in att.aggregation_bits.to_validator_indices()))
        for att in aggregated_atts
    }

    assert proof_participant_sets == expected_participant_sets
    assert att_participant_sets == expected_participant_sets


def test_build_block_skips_non_matching_source(
    container_key_manager: XmssKeyManager,
) -> None:
    """Only attestation data whose source matches current_justified is included."""
    state = make_keyed_genesis_state(2, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    correct_source = Checkpoint(root=parent_root, slot=Slot(0))
    wrong_source = Checkpoint(root=make_bytes32(99), slot=Slot(0))

    att_data_good = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=correct_source,
    )
    att_data_bad = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=wrong_source,
    )

    proof_good = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data_good)
    proof_bad = make_aggregated_proof(container_key_manager, [ValidatorIndex(1)], att_data_bad)

    _, _, aggregated_atts, _ = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={att_data_good: {proof_good}, att_data_bad: {proof_bad}},
    )

    assert len(aggregated_atts) == 1
    assert aggregated_atts[0].data == att_data_good


def test_build_block_skips_unknown_head_root(
    container_key_manager: XmssKeyManager,
) -> None:
    """Attestation data with head root not in known_block_roots is excluded."""
    state = make_keyed_genesis_state(2, container_key_manager)
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    unknown_root = make_bytes32(200)

    att_data_known = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=source,
    )
    att_data_unknown = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=unknown_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=source,
    )

    proof_known = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data_known)
    proof_unknown = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1)], att_data_unknown
    )

    _, _, aggregated_atts, _ = state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={att_data_known: {proof_known}, att_data_unknown: {proof_unknown}},
    )

    assert len(aggregated_atts) == 1
    assert aggregated_atts[0].data == att_data_known


def test_gossip_none_and_aggregated_payloads_none(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test edge case where both attestation_signatures and aggregated_payloads are None.

    Expected Behavior
    -----------------
    Returns empty results (no attestations can be aggregated without signatures).
    """
    state = make_keyed_genesis_state(2, container_key_manager)

    results = state.aggregate(attestation_signatures=None)

    assert results == []
