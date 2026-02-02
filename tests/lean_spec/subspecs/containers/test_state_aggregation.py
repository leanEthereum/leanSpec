"""Tests for the State aggregation helpers introduced on the aggregation branch."""

from __future__ import annotations

import pytest
from consensus_testing.keys import get_shared_key_manager

from lean_spec.subspecs.containers.attestation import (
    AggregationBits,
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.containers.state.types import Validators
from lean_spec.subspecs.containers.validator import Validator, ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, SignatureKey
from lean_spec.types import Bytes32, Bytes52, Uint64


@pytest.fixture(scope="module", autouse=True)
def _set_test_env(monkeypatch_module):
    """Ensure LEAN_ENV is set to test for all tests in this module."""
    monkeypatch_module.setenv("LEAN_ENV", "test")


@pytest.fixture(scope="module")
def monkeypatch_module():
    """Module-scoped monkeypatch fixture."""
    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    yield mp
    mp.undo()


def make_bytes32(seed: int) -> Bytes32:
    """Create a deterministic Bytes32 value for tests."""
    return Bytes32(bytes([seed % 256]) * 32)


def make_validators(count: int) -> Validators:
    """Build a validator registry using public keys from the key manager."""
    key_manager = get_shared_key_manager()
    validators = [
        Validator(
            pubkey=Bytes52(key_manager.get_public_key(ValidatorIndex(i)).encode_bytes()),
            index=ValidatorIndex(i),
        )
        for i in range(count)
    ]
    return Validators(data=validators)


def make_state(num_validators: int) -> State:
    """Create a genesis state with the requested number of validators."""
    validators = make_validators(num_validators)
    return State.generate_genesis(Uint64(0), validators=validators)


def make_attestation_data(
    slot: int,
    head_root: Bytes32,
    target_root: Bytes32,
    source: Checkpoint,
) -> AttestationData:
    """
    Construct AttestationData with deterministic head/target roots.

    Parameters
    ----------
    slot : int
        Slot number for the attestation.
    head_root : Bytes32
        Root of the head block.
    target_root : Bytes32
        Root of the target checkpoint.
    source : Checkpoint
        Source checkpoint for the attestation.
    """
    return AttestationData(
        slot=Slot(slot),
        head=Checkpoint(root=head_root, slot=Slot(slot)),
        target=Checkpoint(root=target_root, slot=Slot(slot)),
        source=source,
    )


def test_aggregated_signatures_prefers_full_gossip_payload() -> None:
    key_manager = get_shared_key_manager()
    state = make_state(2)
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    att_data = make_attestation_data(2, make_bytes32(3), make_bytes32(4), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()
    gossip_signatures = {
        SignatureKey(ValidatorIndex(i), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(i), att_data
        )
        for i in range(2)
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

    # Verify the aggregated proof
    public_keys = [key_manager.get_public_key(ValidatorIndex(i)) for i in range(2)]
    aggregated_proofs[0].verify(
        public_keys=public_keys,
        message=data_root,
        epoch=att_data.slot,
    )


def test_aggregate_signatures_splits_when_needed() -> None:
    """Test that gossip and aggregated proofs are kept separate."""
    key_manager = get_shared_key_manager()
    state = make_state(3)
    source = Checkpoint(root=make_bytes32(2), slot=Slot(0))
    att_data = make_attestation_data(3, make_bytes32(5), make_bytes32(6), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]
    data_root = att_data.data_root_bytes()
    gossip_signatures = {
        SignatureKey(ValidatorIndex(0), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(0), att_data
        )
    }

    block_proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(1), ValidatorIndex(2)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(1)),
            key_manager.get_public_key(ValidatorIndex(2)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(2), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    aggregated_payloads = {
        SignatureKey(ValidatorIndex(1), data_root): [block_proof],
        SignatureKey(ValidatorIndex(2), data_root): [block_proof],
    }

    # Combine gossip and aggregated proofs manually
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
    # Check we have both proofs
    proof_participants = [
        tuple(int(v) for v in p.participants.to_validator_indices()) for p in aggregated_proofs
    ]
    assert (0,) in proof_participants
    assert (1, 2) in proof_participants

    # Verify the proof for validator 0 (the one with a real signature)
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        if participants == [ValidatorIndex(0)]:
            proof.verify(
                public_keys=[key_manager.get_public_key(ValidatorIndex(0))],
                message=data_root,
                epoch=att_data.slot,
            )


def test_build_block_collects_valid_available_attestations() -> None:
    key_manager = get_shared_key_manager()
    state = make_state(2)
    # Compute parent_root as it will be after process_slots fills in the state_root
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    head_root = make_bytes32(10)
    # Target checkpoint should reference the justified checkpoint (slot 0), not the attestation slot
    target = Checkpoint(root=make_bytes32(11), slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=head_root, slot=Slot(1)),
        target=target,
        source=source,
    )
    attestation = Attestation(validator_id=ValidatorIndex(0), data=att_data)
    data_root = att_data.data_root_bytes()

    # Calculate aggregated proof directly
    signature = key_manager.sign_attestation_data(ValidatorIndex(0), att_data)
    proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(0)]),
        public_keys=[key_manager.get_public_key(ValidatorIndex(0))],
        signatures=[signature],
        message=data_root,
        epoch=att_data.slot,
    )
    aggregated_payloads = {SignatureKey(ValidatorIndex(0), data_root): [proof]}

    # Proposer for slot 1 with 2 validators: slot % num_validators = 1 % 2 = 1
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

    # Verify the aggregated proof
    aggregated_proofs[0].verify(
        public_keys=[key_manager.get_public_key(ValidatorIndex(0))],
        message=data_root,
        epoch=att_data.slot,
    )


def test_build_block_skips_attestations_without_signatures() -> None:
    state = make_state(1)
    # Compute parent_root as it will be after process_slots fills in the state_root
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    head_root = make_bytes32(15)
    # Target checkpoint should reference the justified checkpoint (slot 0), not the attestation slot
    target = Checkpoint(root=make_bytes32(16), slot=Slot(0))
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=head_root, slot=Slot(1)),
        target=target,
        source=source,
    )
    attestation = Attestation(validator_id=ValidatorIndex(0), data=att_data)

    # Proposer for slot 1 with 1 validator: slot % num_validators = 1 % 1 = 0
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


def test_aggregate_gossip_signatures_with_empty_attestations() -> None:
    """Empty attestations list should return empty results."""
    state = make_state(2)

    results = state.aggregate_gossip_signatures(
        [],  # empty attestations
        gossip_signatures={},
    )

    assert results == []


def test_aggregated_signatures_with_multiple_data_groups() -> None:
    """Multiple attestation data groups should be processed independently."""
    key_manager = get_shared_key_manager()
    state = make_state(4)
    source = Checkpoint(root=make_bytes32(22), slot=Slot(0))
    att_data1 = make_attestation_data(9, make_bytes32(23), make_bytes32(24), source=source)
    att_data2 = make_attestation_data(10, make_bytes32(25), make_bytes32(26), source=source)

    attestations = [
        Attestation(validator_id=ValidatorIndex(0), data=att_data1),
        Attestation(validator_id=ValidatorIndex(1), data=att_data1),
        Attestation(validator_id=ValidatorIndex(2), data=att_data2),
        Attestation(validator_id=ValidatorIndex(3), data=att_data2),
    ]

    data_root1 = att_data1.data_root_bytes()
    data_root2 = att_data2.data_root_bytes()

    gossip_signatures = {
        SignatureKey(ValidatorIndex(0), data_root1): key_manager.sign_attestation_data(
            ValidatorIndex(0), att_data1
        ),
        SignatureKey(ValidatorIndex(1), data_root1): key_manager.sign_attestation_data(
            ValidatorIndex(1), att_data1
        ),
        SignatureKey(ValidatorIndex(2), data_root2): key_manager.sign_attestation_data(
            ValidatorIndex(2), att_data2
        ),
        SignatureKey(ValidatorIndex(3), data_root2): key_manager.sign_attestation_data(
            ValidatorIndex(3), att_data2
        ),
    }

    results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )
    aggregated_atts, aggregated_proofs = (
        [att for att, _ in results],
        [proof for _, proof in results],
    )

    # Should have 2 aggregated attestations (one per data group)
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    # Verify each aggregated proof
    for agg_att, proof in zip(aggregated_atts, aggregated_proofs, strict=True):
        participants = proof.participants.to_validator_indices()
        public_keys = [key_manager.get_public_key(vid) for vid in participants]
        proof.verify(
            public_keys=public_keys,
            message=agg_att.data.data_root_bytes(),
            epoch=agg_att.data.slot,
        )


def test_aggregated_signatures_falls_back_to_block_payload() -> None:
    """Should fall back to block payload when gossip is incomplete."""
    key_manager = get_shared_key_manager()
    state = make_state(2)
    source = Checkpoint(root=make_bytes32(27), slot=Slot(0))
    att_data = make_attestation_data(11, make_bytes32(28), make_bytes32(29), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()

    # Only gossip signature for validator 0 (incomplete)
    gossip_signatures = {
        SignatureKey(ValidatorIndex(0), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(0), att_data
        )
    }

    # Block payload covers both validators
    block_proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(0), ValidatorIndex(1)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(0)),
            key_manager.get_public_key(ValidatorIndex(1)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    aggregated_payloads = {
        SignatureKey(ValidatorIndex(0), data_root): [block_proof],
        SignatureKey(ValidatorIndex(1), data_root): [block_proof],
    }

    # Combine gossip and aggregated proofs manually
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

    # Should include both gossip-covered and fallback payload attestations/proofs
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2
    # Check we have one proof with validator 0 and one proof with both validators
    proof_participants = [set(p.participants.to_validator_indices()) for p in aggregated_proofs]
    assert {ValidatorIndex(0)} in proof_participants
    assert {ValidatorIndex(0), ValidatorIndex(1)} in proof_participants

    # Verify the proof for validator 0 (the one with a real signature from gossip)
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        if participants == [ValidatorIndex(0)]:
            proof.verify(
                public_keys=[key_manager.get_public_key(ValidatorIndex(0))],
                message=data_root,
                epoch=att_data.slot,
            )


def test_build_block_state_root_valid_when_signatures_split() -> None:
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
    key_manager = get_shared_key_manager()
    num_validators = 4
    pre_state = make_state(num_validators)

    # Compute the parent block root.
    #
    # The header needs its state root filled in before hashing.
    # This mirrors what happens during slot processing.
    parent_header_with_state_root = pre_state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(pre_state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)

    # Set up checkpoint references for the attestation.
    #
    # Source points to the justified checkpoint (genesis here).
    # Target references the current epoch's checkpoint.
    source = Checkpoint(root=parent_root, slot=Slot(0))
    head_root = make_bytes32(50)
    target = Checkpoint(root=make_bytes32(51), slot=Slot(0))

    # Create the attestation data that all validators will sign.
    #
    # All three validators vote on the same head, target, and source.
    # This is the common case when validators agree on chain head.
    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=head_root, slot=Slot(1)),
        target=target,
        source=source,
    )
    data_root = att_data.data_root_bytes()

    # Three validators attest to identical data.
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]

    # Use a second aggregated proof for Validator 0 instead of gossip.
    # This simulates receiving an aggregated signature for this validator from another source.
    proof_0 = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(0)]),
        public_keys=[key_manager.get_public_key(ValidatorIndex(0))],
        signatures=[key_manager.sign_attestation_data(ValidatorIndex(0), att_data)],
        message=data_root,
        epoch=att_data.slot,
    )

    # Simulate the remaining signatures arriving via aggregated proof.
    #
    # These validators' signatures were batched in a previous block.
    # The proof covers both validators together.
    fallback_proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(1), ValidatorIndex(2)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(1)),
            key_manager.get_public_key(ValidatorIndex(2)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(2), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )
    aggregated_payloads = {
        SignatureKey(ValidatorIndex(0), data_root): [proof_0],
        SignatureKey(ValidatorIndex(1), data_root): [fallback_proof],
        SignatureKey(ValidatorIndex(2), data_root): [fallback_proof],
    }

    # Build the block with mixed signature sources.
    #
    # Proposer index follows round-robin: slot 1 with 4 validators selects validator 1.
    block, post_state, aggregated_atts, _ = pre_state.build_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        attestations=attestations,
        aggregated_payloads=aggregated_payloads,
    )

    # Verify attestations split by signature source.
    #
    # Cannot merge gossip and aggregated proof signatures.
    # Each source becomes a separate attestation in the block.
    assert len(aggregated_atts) == 2, "Expected split into 2 attestations"

    # Confirm each attestation covers the expected validators.
    actual_bits = [set(att.aggregation_bits.to_validator_indices()) for att in aggregated_atts]
    assert {ValidatorIndex(0)} in actual_bits, "First attestation should cover only validator 0"
    assert {ValidatorIndex(1), ValidatorIndex(2)} in actual_bits, (
        "Fallback should cover validators 1,2"
    )

    # Execute the state transition.
    #
    # The block's state root must match the post-state computed from
    # the final block body. This validates that attestation splitting
    # does not break state root consistency.
    result_state = pre_state.state_transition(block, valid_signatures=True)

    # Verify slot advanced correctly.
    assert result_state.slot == Slot(1)

    # Verify block header reflects the processed block.
    assert result_state.latest_block_header.slot == Slot(1)
    assert result_state.latest_block_header.proposer_index == ValidatorIndex(1)
    assert result_state.latest_block_header.parent_root == parent_root

    # Verify state root consistency.
    #
    # The block's embedded state root must equal the hash of the resulting state.
    assert block.state_root == hash_tree_root(result_state)

    # Verify the block contains both split attestations.
    assert len(block.body.attestations.data) == 2

    # Verify validators remain unchanged (attestation processing does not modify registry).
    assert len(result_state.validators.data) == num_validators


# =============================================================================
# Greedy Algorithm Tests
# =============================================================================


def test_greedy_selects_proof_with_maximum_overlap() -> None:
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
    key_manager = get_shared_key_manager()
    state = make_state(4)
    source = Checkpoint(root=make_bytes32(60), slot=Slot(0))
    att_data = make_attestation_data(12, make_bytes32(61), make_bytes32(62), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(4)]
    data_root = att_data.data_root_bytes()

    # No gossip signatures - all validators need fallback

    # Create three proofs with different coverage
    # Proof A: validators {0, 1}
    proof_a = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(0), ValidatorIndex(1)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(0)),
            key_manager.get_public_key(ValidatorIndex(1)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    # Proof B: validators {1, 2, 3} - largest coverage
    proof_b = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices(
            [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)]
        ),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(1)),
            key_manager.get_public_key(ValidatorIndex(2)),
            key_manager.get_public_key(ValidatorIndex(3)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(2), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(3), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    # Proof C: validator {3} only
    proof_c = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(3)]),
        public_keys=[key_manager.get_public_key(ValidatorIndex(3))],
        signatures=[key_manager.sign_attestation_data(ValidatorIndex(3), att_data)],
        message=data_root,
        epoch=att_data.slot,
    )

    # Make all proofs available for lookup by any validator they cover
    aggregated_payloads: dict[SignatureKey, list[AggregatedSignatureProof]] = {
        SignatureKey(ValidatorIndex(0), data_root): [proof_a],
        SignatureKey(ValidatorIndex(1), data_root): [proof_a, proof_b],
        SignatureKey(ValidatorIndex(2), data_root): [proof_b],
        SignatureKey(ValidatorIndex(3), data_root): [proof_b, proof_c],
    }

    aggregated_atts, aggregated_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )

    # Should have 2 attestations (optimal greedy selection: B + A)
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    # Verify the proofs cover all 4 validators
    all_participants: set[int] = set()
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        all_participants.update(int(v) for v in participants)
    assert all_participants == {0, 1, 2, 3}, f"All validators should be covered: {all_participants}"


def test_greedy_stops_when_no_useful_proofs_remain() -> None:
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
    key_manager = get_shared_key_manager()
    state = make_state(5)
    source = Checkpoint(root=make_bytes32(70), slot=Slot(0))
    att_data = make_attestation_data(13, make_bytes32(71), make_bytes32(72), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(5)]
    data_root = att_data.data_root_bytes()

    # Gossip covers validators 0 and 1
    gossip_signatures = {
        SignatureKey(ValidatorIndex(0), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(0), att_data
        ),
        SignatureKey(ValidatorIndex(1), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(1), att_data
        ),
    }

    # Proof only covers validators 2 and 3 (no proof for validator 4)
    proof_23 = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(2), ValidatorIndex(3)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(2)),
            key_manager.get_public_key(ValidatorIndex(3)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(2), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(3), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    aggregated_payloads = {
        SignatureKey(ValidatorIndex(2), data_root): [proof_23],
        SignatureKey(ValidatorIndex(3), data_root): [proof_23],
        # Note: No proof available for validator 4
    }

    # Combine gossip and aggregated proofs manually
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

    # Should have 2 attestations: gossip {0,1} and fallback {2,3}
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    # Verify covered validators
    all_participants: set[int] = set()
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        all_participants.update(int(v) for v in participants)

    # Validator 4 is NOT covered (expected - no proof available)
    assert 4 not in all_participants, "Validator 4 should not be covered"
    assert all_participants == {0, 1, 2, 3}, f"Expected {{0,1,2,3}} covered: {all_participants}"


def test_greedy_handles_overlapping_proof_chains() -> None:
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
    key_manager = get_shared_key_manager()
    state = make_state(5)
    source = Checkpoint(root=make_bytes32(80), slot=Slot(0))
    att_data = make_attestation_data(14, make_bytes32(81), make_bytes32(82), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(5)]
    data_root = att_data.data_root_bytes()

    # Gossip covers only validator 0
    gossip_signatures = {
        SignatureKey(ValidatorIndex(0), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(0), att_data
        ),
    }

    # Proof A: {1, 2}
    proof_a = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(1), ValidatorIndex(2)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(1)),
            key_manager.get_public_key(ValidatorIndex(2)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(2), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    # Proof B: {2, 3}
    proof_b = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(2), ValidatorIndex(3)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(2)),
            key_manager.get_public_key(ValidatorIndex(3)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(2), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(3), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    # Proof C: {3, 4}
    proof_c = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(3), ValidatorIndex(4)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(3)),
            key_manager.get_public_key(ValidatorIndex(4)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(3), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(4), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    aggregated_payloads = {
        SignatureKey(ValidatorIndex(1), data_root): [proof_a],
        SignatureKey(ValidatorIndex(2), data_root): [proof_a, proof_b],
        SignatureKey(ValidatorIndex(3), data_root): [proof_b, proof_c],
        SignatureKey(ValidatorIndex(4), data_root): [proof_c],
    }

    # Combine gossip and aggregated proofs manually
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

    # Should have at least 3 attestations (1 gossip + 2 fallback minimum)
    assert len(aggregated_atts) >= 3
    assert len(aggregated_proofs) >= 3

    # Key check: all 5 validators should be covered
    all_participants: set[int] = set()
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        all_participants.update(int(v) for v in participants)

    assert all_participants == {0, 1, 2, 3, 4}, (
        f"All 5 validators should be covered: {all_participants}"
    )


def test_greedy_single_validator_proofs() -> None:
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
    key_manager = get_shared_key_manager()
    state = make_state(3)
    source = Checkpoint(root=make_bytes32(90), slot=Slot(0))
    att_data = make_attestation_data(15, make_bytes32(91), make_bytes32(92), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]
    data_root = att_data.data_root_bytes()

    # No gossip - all need fallback

    # Single-validator proofs only
    proofs = []
    for i in range(3):
        proof = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices([ValidatorIndex(i)]),
            public_keys=[key_manager.get_public_key(ValidatorIndex(i))],
            signatures=[key_manager.sign_attestation_data(ValidatorIndex(i), att_data)],
            message=data_root,
            epoch=att_data.slot,
        )
        proofs.append(proof)

    aggregated_payloads = {
        SignatureKey(ValidatorIndex(i), data_root): [proofs[i]] for i in range(3)
    }

    aggregated_atts, aggregated_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )

    # Should have 3 attestations (one per validator)
    assert len(aggregated_atts) == 3
    assert len(aggregated_proofs) == 3

    # Verify each validator is covered exactly once
    seen_validators: set[int] = set()
    for proof in aggregated_proofs:
        participants = [int(v) for v in proof.participants.to_validator_indices()]
        assert len(participants) == 1, "Each proof should cover exactly 1 validator"
        seen_validators.update(participants)

    assert seen_validators == {0, 1, 2}


# =============================================================================
# Edge Case and Safety Tests
# =============================================================================


def test_validator_in_both_gossip_and_fallback_proof() -> None:
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
    key_manager = get_shared_key_manager()
    state = make_state(2)
    source = Checkpoint(root=make_bytes32(100), slot=Slot(0))
    att_data = make_attestation_data(16, make_bytes32(101), make_bytes32(102), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()

    # Gossip signature only for validator 0
    gossip_signatures = {
        SignatureKey(ValidatorIndex(0), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(0), att_data
        ),
    }

    # Fallback proof covers BOTH validators {0, 1}
    fallback_proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(0), ValidatorIndex(1)]),
        public_keys=[
            key_manager.get_public_key(ValidatorIndex(0)),
            key_manager.get_public_key(ValidatorIndex(1)),
        ],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
            key_manager.sign_attestation_data(ValidatorIndex(1), att_data),
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    # Make proof available for both validators
    aggregated_payloads = {
        SignatureKey(ValidatorIndex(0), data_root): [fallback_proof],
        SignatureKey(ValidatorIndex(1), data_root): [fallback_proof],
    }

    # Combine gossip and aggregated proofs manually
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

    # Should have 2 attestations
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    # Document the expected overlap behavior
    proof_participants = [
        {int(v) for v in p.participants.to_validator_indices()} for p in aggregated_proofs
    ]

    # Gossip proof covers {0}
    assert {0} in proof_participants, "Gossip attestation should cover validator 0"
    # Fallback proof covers {0, 1} (includes validator 0 again)
    assert {0, 1} in proof_participants, "Fallback proof should cover {0, 1}"

    # Verify the proofs are valid
    for proof in aggregated_proofs:
        participants = proof.participants.to_validator_indices()
        public_keys = [key_manager.get_public_key(vid) for vid in participants]
        proof.verify(public_keys=public_keys, message=data_root, epoch=att_data.slot)


def test_gossip_none_and_aggregated_payloads_none() -> None:
    """
    Test edge case where both gossip_signatures and aggregated_payloads are None.

    Expected Behavior
    -----------------
    Returns empty results (no attestations can be aggregated without signatures).
    """
    state = make_state(2)
    source = Checkpoint(root=make_bytes32(110), slot=Slot(0))
    att_data = make_attestation_data(17, make_bytes32(111), make_bytes32(112), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]

    # Both sources are None - test that empty results are returned
    results = state.aggregate_gossip_signatures(
        attestations,
        gossip_signatures=None,
    )

    # Should return empty results
    assert results == []


def test_aggregated_payloads_only_no_gossip() -> None:
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
    key_manager = get_shared_key_manager()
    state = make_state(3)
    source = Checkpoint(root=make_bytes32(120), slot=Slot(0))
    att_data = make_attestation_data(18, make_bytes32(121), make_bytes32(122), source=source)
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(3)]
    data_root = att_data.data_root_bytes()

    # No gossip signatures

    # Proof covering all 3 validators
    proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices(
            [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)]
        ),
        public_keys=[key_manager.get_public_key(ValidatorIndex(i)) for i in range(3)],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(i), att_data) for i in range(3)
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    aggregated_payloads = {SignatureKey(ValidatorIndex(i), data_root): [proof] for i in range(3)}

    aggregated_atts, aggregated_proofs = state.select_aggregated_proofs(
        attestations,
        aggregated_payloads=aggregated_payloads,
    )

    # Should have single attestation from fallback
    assert len(aggregated_atts) == 1
    assert len(aggregated_proofs) == 1

    participants = {int(v) for v in aggregated_proofs[0].participants.to_validator_indices()}
    assert participants == {0, 1, 2}

    # Verify the proof
    public_keys = [key_manager.get_public_key(ValidatorIndex(i)) for i in range(3)]
    aggregated_proofs[0].verify(public_keys=public_keys, message=data_root, epoch=att_data.slot)


def test_proof_with_extra_validators_beyond_needed() -> None:
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
    key_manager = get_shared_key_manager()
    state = make_state(4)
    source = Checkpoint(root=make_bytes32(130), slot=Slot(0))
    att_data = make_attestation_data(19, make_bytes32(131), make_bytes32(132), source=source)
    # Only validators 0 and 1 attest
    attestations = [Attestation(validator_id=ValidatorIndex(i), data=att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()

    # Gossip covers validator 0
    gossip_signatures = {
        SignatureKey(ValidatorIndex(0), data_root): key_manager.sign_attestation_data(
            ValidatorIndex(0), att_data
        ),
    }

    # Proof covers {0, 1, 2, 3} - more than needed
    proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices([ValidatorIndex(i) for i in range(4)]),
        public_keys=[key_manager.get_public_key(ValidatorIndex(i)) for i in range(4)],
        signatures=[
            key_manager.sign_attestation_data(ValidatorIndex(i), att_data) for i in range(4)
        ],
        message=data_root,
        epoch=att_data.slot,
    )

    aggregated_payloads = {
        SignatureKey(ValidatorIndex(1), data_root): [proof],
    }

    # Combine gossip and aggregated proofs manually
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

    # Should have 2 attestations
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2

    proof_participants = [
        {int(v) for v in p.participants.to_validator_indices()} for p in aggregated_proofs
    ]
    assert {0} in proof_participants  # Gossip
    assert {0, 1, 2, 3} in proof_participants  # Fallback (includes extra validators)
