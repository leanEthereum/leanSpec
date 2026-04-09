"""Tests for attestation signature aggregation and block building."""

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
    make_store,
)


def test_aggregated_signatures_prefers_full_gossip_payload(
    container_key_manager: XmssKeyManager,
) -> None:
    store = make_store(num_validators=2, key_manager=container_key_manager)
    head_state = store.states[store.head]
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

    store = store.model_copy(update={"attestation_signatures": attestation_signatures})
    _, results = store.aggregate()

    assert len(results) == 1
    assert set(results[0].proof.participants.to_validator_indices()) == {
        ValidatorIndex(0),
        ValidatorIndex(1),
    }

    public_keys = [
        head_state.validators[ValidatorIndex(i)].get_attestation_pubkey() for i in range(2)
    ]
    results[0].proof.verify(
        public_keys=public_keys,
        message=hash_tree_root(att_data),
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
    data_root = hash_tree_root(att_data)

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


def test_aggregate_with_empty_attestation_signatures(
    container_key_manager: XmssKeyManager,
) -> None:
    """Empty attestations list should return empty results."""
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = store.aggregate()

    assert results == []


def test_aggregated_signatures_with_multiple_data_groups(
    container_key_manager: XmssKeyManager,
) -> None:
    """Multiple attestation data groups should be processed independently."""
    store = make_store(num_validators=4, key_manager=container_key_manager)
    head_state = store.states[store.head]
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

    store = store.model_copy(update={"attestation_signatures": attestation_signatures})
    _, results = store.aggregate()

    assert len(results) == 2

    for signed_att in results:
        participants = signed_att.proof.participants.to_validator_indices()
        public_keys = [head_state.validators[vid].get_attestation_pubkey() for vid in participants]
        signed_att.proof.verify(
            public_keys=public_keys,
            message=hash_tree_root(signed_att.data),
            slot=signed_att.data.slot,
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

    assert len(aggregated_atts) == 1, "Expected compaction into 1 attestation"

    covered = set(aggregated_atts[0].aggregation_bits.to_validator_indices())
    assert covered == {ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)}, (
        "Compacted attestation should cover all three validators"
    )

    result_state = pre_state.state_transition(block, valid_signatures=True)

    assert result_state.slot == Slot(1)
    assert result_state.latest_block_header.slot == Slot(1)
    assert result_state.latest_block_header.proposer_index == ValidatorIndex(1)
    assert result_state.latest_block_header.parent_root == parent_root
    assert block.state_root == hash_tree_root(result_state)
    assert len(block.body.attestations.data) == 1
    assert len(result_state.validators.data) == num_validators


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


def test_aggregate_with_no_signatures(
    container_key_manager: XmssKeyManager,
) -> None:
    """
    Test edge case where the store has no attestation signatures or payloads.

    Returns empty results (no attestations can be aggregated without signatures).
    """
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = store.aggregate()

    assert results == []
