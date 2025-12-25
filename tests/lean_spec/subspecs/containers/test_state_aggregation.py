"""Tests for the State aggregation helpers introduced on the aggregation branch."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers.attestation import (
    AggregatedAttestation,
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
from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    Randomness,
)
from lean_spec.types import Bytes32, Bytes52, Uint64
from lean_spec.types.byte_arrays import LeanAggregatedSignature

TEST_AGGREGATED_SIGNATURE = LeanAggregatedSignature(data=b"\x00")


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


def make_checkpoint(root: Bytes32, slot: int) -> Checkpoint:
    """Helper to build checkpoints with integer slots."""
    return Checkpoint(root=root, slot=Slot(slot))


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
        head=make_checkpoint(head_root, slot),
        target=make_checkpoint(target_root, slot),
        source=source,
    )


def make_attestation(validator_index: int, data: AttestationData) -> Attestation:
    """Create an attestation for the provided validator."""
    return Attestation(validator_id=Uint64(validator_index), data=data)


def test_gossip_aggregation_succeeds_with_all_signatures() -> None:
    state = make_state(2)
    data_root = b"\x11" * 32
    validator_ids = [Uint64(0), Uint64(1)]
    gossip_signatures = {
        (Uint64(0), data_root): make_signature(0),
        (Uint64(1), data_root): make_signature(1),
    }

    result = state._aggregate_signatures_from_gossip(
        validator_ids,
        data_root,
        Slot(3),
        gossip_signatures,
    )

    assert result == TEST_AGGREGATED_SIGNATURE


def test_gossip_aggregation_returns_none_if_any_signature_missing() -> None:
    state = make_state(2)
    data_root = b"\x22" * 32
    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    result = state._aggregate_signatures_from_gossip(
        [Uint64(0), Uint64(1)],
        data_root,
        Slot(2),
        gossip_signatures,
    )

    assert result is None


def test_block_payload_lookup_requires_matching_entries() -> None:
    state = make_state(3)
    data_root = b"\x33" * 32
    validator_ids = [Uint64(0), Uint64(1), Uint64(2)]
    participant_bits = AggregationBits.from_validator_indices(validator_ids)
    payload = LeanAggregatedSignature(data=b"block-payload")
    aggregated_payloads = {
        (Uint64(0), data_root): [(participant_bits, payload)],
        (Uint64(1), data_root): [(participant_bits, payload)],
        (Uint64(2), data_root): [(participant_bits, payload)],
    }

    result = state._aggregate_signatures_from_block_payload(
        validator_ids,
        data_root,
        aggregated_payloads,
    )

    assert result == payload


def test_block_payload_lookup_returns_none_without_complete_matches() -> None:
    state = make_state(2)
    data_root = b"\x44" * 32
    validator_ids = [Uint64(0), Uint64(1)]
    participant_bits = AggregationBits.from_validator_indices([Uint64(0)])
    payload = LeanAggregatedSignature(data=b"partial")
    aggregated_payloads = {
        (Uint64(0), data_root): [(participant_bits, payload)],
        # Missing entries for validator 1
    }

    result = state._aggregate_signatures_from_block_payload(
        validator_ids,
        data_root,
        aggregated_payloads,
    )

    assert result is None


def test_split_aggregated_attestations_prefers_existing_payloads() -> None:
    state = make_state(4)
    source = make_checkpoint(make_bytes32(9), slot=0)
    att_data = make_attestation_data(5, make_bytes32(6), make_bytes32(7), source)
    aggregated_attestation = AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices([Uint64(i) for i in range(4)]),
        data=att_data,
    )
    data_root = att_data.data_root_bytes()

    gossip_signatures = {
        (Uint64(0), data_root): make_signature(0),
        (Uint64(1), data_root): make_signature(1),
    }

    block_bits = AggregationBits.from_validator_indices([Uint64(2), Uint64(3)])
    block_signature = LeanAggregatedSignature(data=b"block-23")
    aggregated_payloads = {
        (Uint64(2), data_root): [(block_bits, block_signature)],
        (Uint64(3), data_root): [(block_bits, block_signature)],
    }

    split_atts, split_sigs = state.split_aggregated_attestations(
        aggregated_attestation,
        gossip_signatures,
        aggregated_payloads,
    )

    seen_participants = {
        tuple(int(v) for v in att.aggregation_bits.to_validator_indices()) for att in split_atts
    }
    assert seen_participants == {(0, 1), (2, 3)}
    assert block_signature in split_sigs
    assert TEST_AGGREGATED_SIGNATURE in split_sigs


def test_split_aggregated_attestations_errors_when_signatures_missing() -> None:
    state = make_state(2)
    source = make_checkpoint(make_bytes32(1), slot=0)
    att_data = make_attestation_data(2, make_bytes32(3), make_bytes32(4), source)
    aggregated_attestation = AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices([Uint64(0), Uint64(1)]),
        data=att_data,
    )

    with pytest.raises(AssertionError, match="Cannot aggregate attestations"):
        state.split_aggregated_attestations(aggregated_attestation, {}, {})


def test_compute_aggregated_signatures_prefers_full_gossip_payload() -> None:
    state = make_state(2)
    source = make_checkpoint(make_bytes32(1), slot=0)
    att_data = make_attestation_data(3, make_bytes32(5), make_bytes32(6), source)
    attestations = [make_attestation(i, att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()
    gossip_signatures = {(Uint64(i), data_root): make_signature(i) for i in range(2)}

    aggregated_atts, aggregated_sigs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )

    assert len(aggregated_atts) == 1
    assert aggregated_sigs == [TEST_AGGREGATED_SIGNATURE]


def test_compute_aggregated_signatures_splits_when_needed() -> None:
    state = make_state(3)
    source = make_checkpoint(make_bytes32(2), slot=0)
    att_data = make_attestation_data(4, make_bytes32(7), make_bytes32(8), source)
    attestations = [make_attestation(i, att_data) for i in range(3)]
    data_root = att_data.data_root_bytes()
    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    block_bits = AggregationBits.from_validator_indices([Uint64(1), Uint64(2)])
    block_signature = LeanAggregatedSignature(data=b"block-12")
    aggregated_payloads = {
        (Uint64(1), data_root): [(block_bits, block_signature)],
        (Uint64(2), data_root): [(block_bits, block_signature)],
    }

    aggregated_atts, aggregated_sigs = state.compute_aggregated_signatures(
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
    assert block_signature in aggregated_sigs
    assert TEST_AGGREGATED_SIGNATURE in aggregated_sigs


def test_build_block_collects_valid_available_attestations() -> None:
    state = make_state(2)
    # Compute parent_root as it will be after process_slots fills in the state_root
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = make_checkpoint(parent_root, slot=0)
    head_root = make_bytes32(10)
    # Target checkpoint should reference the justified checkpoint (slot 0), not the attestation slot
    target = make_checkpoint(make_bytes32(11), slot=0)
    att_data = AttestationData(
        slot=Slot(1),
        head=make_checkpoint(head_root, slot=1),
        target=target,
        source=source,
    )
    attestation = make_attestation(0, att_data)
    data_root = att_data.data_root_bytes()

    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    # Proposer for slot 1 with 2 validators: slot % num_validators = 1 % 2 = 1
    block, post_state, aggregated_atts, aggregated_sigs = state.build_block(
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
    assert aggregated_sigs == [TEST_AGGREGATED_SIGNATURE]
    assert block.body.attestations.data[0].aggregation_bits.to_validator_indices() == [Uint64(0)]


def test_build_block_skips_attestations_without_signatures() -> None:
    state = make_state(1)
    # Compute parent_root as it will be after process_slots fills in the state_root
    parent_header_with_state_root = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    parent_root = hash_tree_root(parent_header_with_state_root)
    source = make_checkpoint(parent_root, slot=0)
    head_root = make_bytes32(15)
    # Target checkpoint should reference the justified checkpoint (slot 0), not the attestation slot
    target = make_checkpoint(make_bytes32(16), slot=0)
    att_data = AttestationData(
        slot=Slot(1),
        head=make_checkpoint(head_root, slot=1),
        target=target,
        source=source,
    )
    attestation = make_attestation(0, att_data)

    # Proposer for slot 1 with 1 validator: slot % num_validators = 1 % 1 = 0
    block, post_state, aggregated_atts, aggregated_sigs = state.build_block(
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
    assert aggregated_sigs == []
    assert list(block.body.attestations.data) == []


# ============================================================================
# Additional edge case tests for _aggregate_signatures_from_gossip
# ============================================================================


def test_gossip_aggregation_with_empty_validator_list() -> None:
    """Empty validator list should return None."""
    state = make_state(2)
    data_root = b"\x99" * 32
    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    result = state._aggregate_signatures_from_gossip(
        [],  # empty validator list
        data_root,
        Slot(1),
        gossip_signatures,
    )

    assert result is None


def test_gossip_aggregation_with_none_gossip_signatures() -> None:
    """None gossip_signatures should return None."""
    state = make_state(2)
    data_root = b"\x88" * 32

    result = state._aggregate_signatures_from_gossip(
        [Uint64(0), Uint64(1)],
        data_root,
        Slot(1),
        None,  # None gossip_signatures
    )

    assert result is None


def test_gossip_aggregation_with_empty_gossip_signatures() -> None:
    """Empty gossip_signatures dict should return None."""
    state = make_state(2)
    data_root = b"\x77" * 32

    result = state._aggregate_signatures_from_gossip(
        [Uint64(0), Uint64(1)],
        data_root,
        Slot(1),
        {},  # empty dict
    )

    assert result is None


# ============================================================================
# Additional edge case tests for _aggregate_signatures_from_block_payload
# ============================================================================


def test_block_payload_with_empty_validator_list() -> None:
    """Empty validator list should return None."""
    state = make_state(2)
    data_root = b"\x66" * 32
    participant_bits = AggregationBits.from_validator_indices([Uint64(0)])
    payload = LeanAggregatedSignature(data=b"payload")
    aggregated_payloads = {
        (Uint64(0), data_root): [(participant_bits, payload)],
    }

    result = state._aggregate_signatures_from_block_payload(
        [],  # empty validator list
        data_root,
        aggregated_payloads,
    )

    assert result is None


def test_block_payload_with_none_aggregated_payloads() -> None:
    """None aggregated_payloads should return None."""
    state = make_state(2)
    data_root = b"\x55" * 32

    result = state._aggregate_signatures_from_block_payload(
        [Uint64(0), Uint64(1)],
        data_root,
        None,  # None aggregated_payloads
    )

    assert result is None


def test_block_payload_with_empty_aggregated_payloads() -> None:
    """Empty aggregated_payloads dict should return None."""
    state = make_state(2)
    data_root = b"\x44" * 32

    result = state._aggregate_signatures_from_block_payload(
        [Uint64(0), Uint64(1)],
        data_root,
        {},  # empty dict
    )

    assert result is None


def test_block_payload_with_empty_first_records() -> None:
    """First validator having empty records should return None."""
    state = make_state(2)
    data_root = b"\x33" * 32
    aggregated_payloads = {
        (Uint64(0), data_root): [],  # empty records for first validator
        (Uint64(1), data_root): [
            (
                AggregationBits.from_validator_indices([Uint64(1)]),
                LeanAggregatedSignature(data=b"sig"),
            )
        ],
    }

    result = state._aggregate_signatures_from_block_payload(
        [Uint64(0), Uint64(1)],
        data_root,
        aggregated_payloads,
    )

    assert result is None


def test_block_payload_with_mismatched_signatures() -> None:
    """All validators have entries but with different signatures should return None."""
    state = make_state(2)
    data_root = b"\x22" * 32
    participant_bits = AggregationBits.from_validator_indices([Uint64(0), Uint64(1)])
    payload1 = LeanAggregatedSignature(data=b"payload1")
    payload2 = LeanAggregatedSignature(data=b"payload2")
    aggregated_payloads = {
        (Uint64(0), data_root): [(participant_bits, payload1)],
        (Uint64(1), data_root): [(participant_bits, payload2)],  # different signature
    }

    result = state._aggregate_signatures_from_block_payload(
        [Uint64(0), Uint64(1)],
        data_root,
        aggregated_payloads,
    )

    assert result is None


def test_block_payload_selects_correct_payload_among_multiple() -> None:
    """When multiple payloads exist, should select the one matching all validators."""
    state = make_state(3)
    data_root = b"\x11" * 32

    # Partial payload for validators 0 and 1
    partial_bits = AggregationBits.from_validator_indices([Uint64(0), Uint64(1)])
    partial_payload = LeanAggregatedSignature(data=b"partial")

    # Full payload for all three validators
    full_bits = AggregationBits.from_validator_indices([Uint64(0), Uint64(1), Uint64(2)])
    full_payload = LeanAggregatedSignature(data=b"full")

    aggregated_payloads = {
        (Uint64(0), data_root): [(partial_bits, partial_payload), (full_bits, full_payload)],
        (Uint64(1), data_root): [(partial_bits, partial_payload), (full_bits, full_payload)],
        (Uint64(2), data_root): [(full_bits, full_payload)],
    }

    result = state._aggregate_signatures_from_block_payload(
        [Uint64(0), Uint64(1), Uint64(2)],
        data_root,
        aggregated_payloads,
    )

    assert result == full_payload


# ============================================================================
# Additional edge case tests for split_aggregated_attestations
# ============================================================================


def test_split_with_only_gossip_signatures() -> None:
    """Split should work with only gossip signatures (no block payloads)."""
    state = make_state(3)
    source = make_checkpoint(make_bytes32(10), slot=0)
    att_data = make_attestation_data(5, make_bytes32(11), make_bytes32(12), source)
    aggregated_attestation = AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices([Uint64(i) for i in range(3)]),
        data=att_data,
    )
    data_root = att_data.data_root_bytes()

    gossip_signatures = {
        (Uint64(0), data_root): make_signature(0),
        (Uint64(1), data_root): make_signature(1),
        (Uint64(2), data_root): make_signature(2),
    }

    split_atts, split_sigs = state.split_aggregated_attestations(
        aggregated_attestation,
        gossip_signatures,
        None,  # no block payloads
    )

    # Should create a single aggregated attestation from gossip
    assert len(split_atts) == 1
    assert len(split_sigs) == 1
    assert split_atts[0].aggregation_bits.to_validator_indices() == [
        Uint64(0),
        Uint64(1),
        Uint64(2),
    ]


def test_split_with_only_block_payloads() -> None:
    """Split should work with only block payloads (no gossip signatures)."""
    state = make_state(2)
    source = make_checkpoint(make_bytes32(13), slot=0)
    att_data = make_attestation_data(6, make_bytes32(14), make_bytes32(15), source)
    aggregated_attestation = AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices([Uint64(0), Uint64(1)]),
        data=att_data,
    )
    data_root = att_data.data_root_bytes()

    block_bits = AggregationBits.from_validator_indices([Uint64(0), Uint64(1)])
    block_signature = LeanAggregatedSignature(data=b"block-01")
    aggregated_payloads = {
        (Uint64(0), data_root): [(block_bits, block_signature)],
        (Uint64(1), data_root): [(block_bits, block_signature)],
    }

    split_atts, split_sigs = state.split_aggregated_attestations(
        aggregated_attestation,
        None,  # no gossip signatures
        aggregated_payloads,
    )

    assert len(split_atts) == 1
    assert len(split_sigs) == 1
    assert split_sigs[0] == block_signature


def test_split_with_single_validator() -> None:
    """Split with a single validator should work correctly."""
    state = make_state(1)
    source = make_checkpoint(make_bytes32(16), slot=0)
    att_data = make_attestation_data(7, make_bytes32(17), make_bytes32(18), source)
    aggregated_attestation = AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices([Uint64(0)]),
        data=att_data,
    )
    data_root = att_data.data_root_bytes()

    gossip_signatures = {
        (Uint64(0), data_root): make_signature(0),
    }

    split_atts, split_sigs = state.split_aggregated_attestations(
        aggregated_attestation,
        gossip_signatures,
        None,
    )

    assert len(split_atts) == 1
    assert len(split_sigs) == 1
    assert split_atts[0].aggregation_bits.to_validator_indices() == [Uint64(0)]


def test_split_greedy_selection_prefers_larger_sets() -> None:
    """Greedy algorithm should prefer larger validator sets to minimize splits."""
    state = make_state(5)
    source = make_checkpoint(make_bytes32(19), slot=0)
    att_data = make_attestation_data(8, make_bytes32(20), make_bytes32(21), source)
    aggregated_attestation = AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices([Uint64(i) for i in range(5)]),
        data=att_data,
    )
    data_root = att_data.data_root_bytes()

    # Provide overlapping payloads: small pairs and one large group
    bits_01 = AggregationBits.from_validator_indices([Uint64(0), Uint64(1)])
    bits_23 = AggregationBits.from_validator_indices([Uint64(2), Uint64(3)])
    bits_0234 = AggregationBits.from_validator_indices([Uint64(0), Uint64(2), Uint64(3), Uint64(4)])

    sig_01 = LeanAggregatedSignature(data=b"sig-01")
    sig_23 = LeanAggregatedSignature(data=b"sig-23")
    sig_0234 = LeanAggregatedSignature(data=b"sig-0234")

    aggregated_payloads = {
        (Uint64(0), data_root): [(bits_01, sig_01), (bits_0234, sig_0234)],
        (Uint64(1), data_root): [(bits_01, sig_01)],
        (Uint64(2), data_root): [(bits_23, sig_23), (bits_0234, sig_0234)],
        (Uint64(3), data_root): [(bits_23, sig_23), (bits_0234, sig_0234)],
        (Uint64(4), data_root): [(bits_0234, sig_0234)],
    }

    split_atts, split_sigs = state.split_aggregated_attestations(
        aggregated_attestation,
        {},
        aggregated_payloads,
    )

    # Greedy should pick the large group first (0,2,3,4), then fill in validator 1
    # This results in 2 splits instead of 3 if it picked small pairs first
    assert len(split_atts) == 2
    participant_sets = [
        {int(v) for v in att.aggregation_bits.to_validator_indices()} for att in split_atts
    ]
    # The large set should be selected
    assert {0, 2, 3, 4} in participant_sets or {0, 1, 2, 3, 4} in participant_sets


# ============================================================================
# Additional edge case tests for compute_aggregated_signatures
# ============================================================================


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
    source = make_checkpoint(make_bytes32(22), slot=0)
    att_data1 = make_attestation_data(9, make_bytes32(23), make_bytes32(24), source)
    att_data2 = make_attestation_data(10, make_bytes32(25), make_bytes32(26), source)

    attestations = [
        make_attestation(0, att_data1),
        make_attestation(1, att_data1),
        make_attestation(2, att_data2),
        make_attestation(3, att_data2),
    ]

    data_root1 = att_data1.data_root_bytes()
    data_root2 = att_data2.data_root_bytes()

    gossip_signatures = {
        (Uint64(0), data_root1): make_signature(0),
        (Uint64(1), data_root1): make_signature(1),
        (Uint64(2), data_root2): make_signature(2),
        (Uint64(3), data_root2): make_signature(3),
    }

    aggregated_atts, aggregated_sigs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
    )

    # Should have 2 aggregated attestations (one per data group)
    assert len(aggregated_atts) == 2
    assert len(aggregated_sigs) == 2


def test_compute_aggregated_signatures_falls_back_to_block_payload() -> None:
    """Should fall back to block payload when gossip is incomplete."""
    state = make_state(2)
    source = make_checkpoint(make_bytes32(27), slot=0)
    att_data = make_attestation_data(11, make_bytes32(28), make_bytes32(29), source)
    attestations = [make_attestation(i, att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()

    # Only gossip signature for validator 0 (incomplete)
    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    # Block payload covers both validators
    block_bits = AggregationBits.from_validator_indices([Uint64(0), Uint64(1)])
    block_signature = LeanAggregatedSignature(data=b"block-fallback")
    aggregated_payloads = {
        (Uint64(0), data_root): [(block_bits, block_signature)],
        (Uint64(1), data_root): [(block_bits, block_signature)],
    }

    aggregated_atts, aggregated_sigs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
        aggregated_payloads=aggregated_payloads,
    )

    # Should use block payload since gossip is incomplete
    assert len(aggregated_atts) == 1
    assert len(aggregated_sigs) == 1
    assert aggregated_sigs[0] == block_signature
