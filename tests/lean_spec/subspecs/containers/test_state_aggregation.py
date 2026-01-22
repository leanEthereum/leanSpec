"""Tests for the State aggregation helpers introduced on the aggregation branch."""

from __future__ import annotations

from lean_spec.subspecs.containers.attestation import (
    AggregationBits,
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.containers.state.types import Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, SignatureKey
from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    Randomness,
)
from lean_spec.types import Bytes32, Bytes52, Uint64
from lean_spec.types.byte_arrays import ByteListMiB


def make_test_proof(validator_ids: list[Uint64], data: bytes = b"\x00") -> AggregatedSignatureProof:
    """Create a test AggregatedSignatureProof with given participants."""
    return AggregatedSignatureProof(
        participants=AggregationBits.from_validator_indices(validator_ids),
        proof_data=ByteListMiB(data=data),
    )


# Default test proof with empty participants (will be replaced in most tests)
TEST_AGGREGATED_PROOF = make_test_proof([Uint64(0), Uint64(1)])


def make_bytes32(seed: int) -> Bytes32:
    """Create a deterministic Bytes32 value for tests."""
    return Bytes32(bytes([seed % 256]) * 32)


def make_public_key_bytes(seed: int) -> bytes:
    """Encode a deterministic XMSS public key."""
    root = HashDigestVector(data=[Fp(seed + i) for i in range(HashDigestVector.LENGTH)])
    parameter = Parameter(data=[Fp(seed + 100 + i) for i in range(Parameter.LENGTH)])
    public_key = PublicKey(root=root, parameter=parameter)
    return public_key.encode_bytes()


def make_signature(seed: int) -> Signature:
    """Create a minimal but valid XMSS signature container."""
    randomness = Randomness(data=[Fp(seed + 200 + i) for i in range(Randomness.LENGTH)])
    return Signature(
        path=HashTreeOpening(siblings=HashDigestList(data=[])),
        rho=randomness,
        hashes=HashDigestList(data=[]),
    )


def make_validators(count: int) -> Validators:
    """Build a validator registry with deterministic keys."""
    validators = [
        Validator(pubkey=Bytes52(make_public_key_bytes(i)), index=Uint64(i)) for i in range(count)
    ]
    return Validators(data=validators)


def make_state(num_validators: int) -> State:
    """Create a genesis state with the requested number of validators."""
    return State.generate_genesis(Uint64(0), validators=make_validators(num_validators))


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


def test_compute_aggregated_signatures_prefers_full_gossip_payload() -> None:
    state = make_state(2)
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    att_data = make_attestation_data(2, make_bytes32(3), make_bytes32(4), source=source)
    attestations = [Attestation(validator_id=Uint64(i), data=att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()
    gossip_signatures = {SignatureKey(Uint64(i), data_root): make_signature(i) for i in range(2)}

    aggregated_atts, aggregated_proofs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )

    assert len(aggregated_atts) == 1
    assert len(aggregated_proofs) == 1
    assert set(aggregated_proofs[0].participants.to_validator_indices()) == {Uint64(0), Uint64(1)}


def test_compute_aggregated_signatures_splits_when_needed() -> None:
    state = make_state(3)
    source = Checkpoint(root=make_bytes32(2), slot=Slot(0))
    att_data = make_attestation_data(3, make_bytes32(5), make_bytes32(6), source=source)
    attestations = [Attestation(validator_id=Uint64(i), data=att_data) for i in range(3)]
    data_root = att_data.data_root_bytes()
    gossip_signatures = {SignatureKey(Uint64(0), data_root): make_signature(0)}

    block_proof = make_test_proof([Uint64(1), Uint64(2)], b"block-12")
    aggregated_payloads = {
        SignatureKey(Uint64(1), data_root): [block_proof],
        SignatureKey(Uint64(2), data_root): [block_proof],
    }

    aggregated_atts, aggregated_proofs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
        aggregated_payloads=aggregated_payloads,
    )

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


def test_build_block_collects_valid_available_attestations() -> None:
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
    attestation = Attestation(validator_id=Uint64(0), data=att_data)
    data_root = att_data.data_root_bytes()

    gossip_signatures = {SignatureKey(Uint64(0), data_root): make_signature(0)}

    # Proposer for slot 1 with 2 validators: slot % num_validators = 1 % 2 = 1
    block, post_state, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=Uint64(1),
        parent_root=parent_root,
        attestations=[],
        available_attestations=[attestation],
        known_block_roots={head_root},
        gossip_signatures=gossip_signatures,
        aggregated_payloads={},
    )

    assert post_state.latest_block_header.slot == Slot(1)
    assert list(block.body.attestations.data) == aggregated_atts
    assert len(aggregated_proofs) == 1
    assert aggregated_proofs[0].participants.to_validator_indices() == [Uint64(0)]
    assert block.body.attestations.data[0].aggregation_bits.to_validator_indices() == [Uint64(0)]


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
    attestation = Attestation(validator_id=Uint64(0), data=att_data)

    # Proposer for slot 1 with 1 validator: slot % num_validators = 1 % 1 = 0
    block, post_state, aggregated_atts, aggregated_proofs = state.build_block(
        slot=Slot(1),
        proposer_index=Uint64(0),
        parent_root=parent_root,
        attestations=[],
        available_attestations=[attestation],
        known_block_roots={head_root},
        gossip_signatures={},
        aggregated_payloads={},
    )

    assert post_state.latest_block_header.slot == Slot(1)
    assert aggregated_atts == []
    assert aggregated_proofs == []
    assert list(block.body.attestations.data) == []


def test_compute_aggregated_signatures_with_empty_attestations() -> None:
    """Empty attestations list should return empty results."""
    state = make_state(2)

    aggregated_atts, aggregated_sigs = state.compute_aggregated_signatures(
        [],  # empty attestations
        gossip_signatures={},
        aggregated_payloads={},
    )

    assert aggregated_atts == []
    assert aggregated_sigs == []


def test_compute_aggregated_signatures_with_multiple_data_groups() -> None:
    """Multiple attestation data groups should be processed independently."""
    state = make_state(4)
    source = Checkpoint(root=make_bytes32(22), slot=Slot(0))
    att_data1 = make_attestation_data(9, make_bytes32(23), make_bytes32(24), source=source)
    att_data2 = make_attestation_data(10, make_bytes32(25), make_bytes32(26), source=source)

    attestations = [
        Attestation(validator_id=Uint64(0), data=att_data1),
        Attestation(validator_id=Uint64(1), data=att_data1),
        Attestation(validator_id=Uint64(2), data=att_data2),
        Attestation(validator_id=Uint64(3), data=att_data2),
    ]

    data_root1 = att_data1.data_root_bytes()
    data_root2 = att_data2.data_root_bytes()

    gossip_signatures = {
        SignatureKey(Uint64(0), data_root1): make_signature(0),
        SignatureKey(Uint64(1), data_root1): make_signature(1),
        SignatureKey(Uint64(2), data_root2): make_signature(2),
        SignatureKey(Uint64(3), data_root2): make_signature(3),
    }

    aggregated_atts, aggregated_proofs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )

    # Should have 2 aggregated attestations (one per data group)
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2


def test_compute_aggregated_signatures_falls_back_to_block_payload() -> None:
    """Should fall back to block payload when gossip is incomplete."""
    state = make_state(2)
    source = Checkpoint(root=make_bytes32(27), slot=Slot(0))
    att_data = make_attestation_data(11, make_bytes32(28), make_bytes32(29), source=source)
    attestations = [Attestation(validator_id=Uint64(i), data=att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()

    # Only gossip signature for validator 0 (incomplete)
    gossip_signatures = {SignatureKey(Uint64(0), data_root): make_signature(0)}

    # Block payload covers both validators
    block_proof = make_test_proof([Uint64(0), Uint64(1)], b"block-fallback")
    aggregated_payloads = {
        SignatureKey(Uint64(0), data_root): [block_proof],
        SignatureKey(Uint64(1), data_root): [block_proof],
    }

    aggregated_atts, aggregated_proofs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
        aggregated_payloads=aggregated_payloads,
    )

    # Should include both gossip-covered and fallback payload attestations/proofs
    assert len(aggregated_atts) == 2
    assert len(aggregated_proofs) == 2
    # Check we have one proof with validator 0 and one proof with both validators
    proof_participants = [set(p.participants.to_validator_indices()) for p in aggregated_proofs]
    assert {Uint64(0)} in proof_participants
    assert {Uint64(0), Uint64(1)} in proof_participants


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
    attestations = [Attestation(validator_id=Uint64(i), data=att_data) for i in range(3)]

    # Simulate partial gossip coverage.
    #
    # Only one signature arrived via the gossip network.
    # This happens when network partitions delay some messages.
    gossip_signatures = {SignatureKey(Uint64(0), data_root): make_signature(0)}

    # Simulate the remaining signatures arriving via aggregated proof.
    #
    # These validators' signatures were batched in a previous block.
    # The proof covers both validators together.
    fallback_proof = make_test_proof([Uint64(1), Uint64(2)], b"fallback-12")
    aggregated_payloads = {
        SignatureKey(Uint64(1), data_root): [fallback_proof],
        SignatureKey(Uint64(2), data_root): [fallback_proof],
    }

    # Build the block with mixed signature sources.
    #
    # Proposer index follows round-robin: slot 1 with 4 validators selects validator 1.
    block, post_state, aggregated_atts, _ = pre_state.build_block(
        slot=Slot(1),
        proposer_index=Uint64(1),
        parent_root=parent_root,
        attestations=attestations,
        gossip_signatures=gossip_signatures,
        aggregated_payloads=aggregated_payloads,
    )

    # Verify attestations split by signature source.
    #
    # Cannot merge gossip and aggregated proof signatures.
    # Each source becomes a separate attestation in the block.
    assert len(aggregated_atts) == 2, "Expected split into 2 attestations"

    # Confirm each attestation covers the expected validators.
    actual_bits = [set(att.aggregation_bits.to_validator_indices()) for att in aggregated_atts]
    assert {Uint64(0)} in actual_bits, "Gossip attestation should cover only validator 0"
    assert {Uint64(1), Uint64(2)} in actual_bits, "Fallback should cover validators 1,2"

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
    assert result_state.latest_block_header.proposer_index == Uint64(1)
    assert result_state.latest_block_header.parent_root == parent_root

    # Verify state root consistency.
    #
    # The block's embedded state root must equal the hash of the resulting state.
    assert block.state_root == hash_tree_root(result_state)
    
    # Verify the block contains both split attestations.
    assert len(block.body.attestations.data) == 2

    # Verify validators remain unchanged (attestation processing does not modify registry).
    assert len(result_state.validators.data) == num_validators