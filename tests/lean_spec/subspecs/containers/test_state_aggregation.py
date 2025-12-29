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
from lean_spec.subspecs.xmss.aggregation import MultisigAggregatedSignature
from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    Randomness,
)
from lean_spec.types import Bytes32, Bytes52, Uint64

TEST_AGGREGATED_SIGNATURE = MultisigAggregatedSignature(data=b"\x00")


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

    assert result is not None
    aggregated_signature, aggregated_bitlist, remaining = result
    assert aggregated_signature == TEST_AGGREGATED_SIGNATURE
    assert set(aggregated_bitlist.to_validator_indices()) == set(validator_ids)
    assert remaining == set()


def test_gossip_aggregation_returns_partial_result_when_some_missing() -> None:
    state = make_state(2)
    data_root = b"\x22" * 32
    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    result = state._aggregate_signatures_from_gossip(
        [Uint64(0), Uint64(1)],
        data_root,
        Slot(2),
        gossip_signatures,
    )

    assert result is not None
    aggregated_signature, aggregated_bitlist, remaining = result
    assert aggregated_signature == TEST_AGGREGATED_SIGNATURE
    assert aggregated_bitlist.to_validator_indices() == [Uint64(0)]
    assert remaining == {Uint64(1)}


def test_gossip_aggregation_returns_none_if_no_signature_matches() -> None:
    state = make_state(2)
    data_root = b"\x33" * 32
    # Gossip data exists but for a different validator key, so no signatures match
    gossip_signatures = {(Uint64(9), data_root): make_signature(0)}

    result = state._aggregate_signatures_from_gossip(
        [Uint64(0), Uint64(1)],
        data_root,
        Slot(2),
        gossip_signatures,
    )

    assert result is None


def test_pick_from_aggregated_signatures_prefers_widest_overlap() -> None:
    state = make_state(3)
    data_root = b"\x44" * 32
    remaining_validator_ids = {Uint64(0), Uint64(1)}

    narrow_bits = AggregationBits.from_validator_indices([Uint64(0)])
    best_bits = AggregationBits.from_validator_indices([Uint64(0), Uint64(1)])
    narrow_signature = MultisigAggregatedSignature(data=b"narrow")
    best_signature = MultisigAggregatedSignature(data=b"best")

    aggregated_payloads = {
        (Uint64(0), data_root): [
            (narrow_bits, narrow_signature),
            (best_bits, best_signature),
        ],
        (Uint64(1), data_root): [
            (best_bits, best_signature),
            (narrow_bits, narrow_signature),
        ],
    }

    signature, bitlist, remaining = state._pick_from_aggregated_signatures(
        remaining_validator_ids=remaining_validator_ids,
        data_root=data_root,
        aggregated_payloads=aggregated_payloads,
    )

    assert signature == best_signature
    assert set(bitlist.to_validator_indices()) == {Uint64(0), Uint64(1)}
    assert remaining == set()


def test_pick_from_aggregated_signatures_returns_remaining_for_partial_payload() -> None:
    state = make_state(2)
    data_root = b"\x45" * 32
    remaining_validator_ids = {Uint64(0), Uint64(1)}

    partial_bits_0 = AggregationBits.from_validator_indices([Uint64(0)])
    partial_bits_1 = AggregationBits.from_validator_indices([Uint64(1)])
    partial_signature_0 = MultisigAggregatedSignature(data=b"partial-0")
    partial_signature_1 = MultisigAggregatedSignature(data=b"partial-1")

    aggregated_payloads = {
        (Uint64(0), data_root): [(partial_bits_0, partial_signature_0)],
        (Uint64(1), data_root): [(partial_bits_1, partial_signature_1)],
    }

    signature, bitlist, remaining = state._pick_from_aggregated_signatures(
        remaining_validator_ids=remaining_validator_ids,
        data_root=data_root,
        aggregated_payloads=aggregated_payloads,
    )

    covered_validators = set(bitlist.to_validator_indices())
    assert covered_validators <= {Uint64(0), Uint64(1)}
    assert signature in {partial_signature_0, partial_signature_1}
    assert remaining == remaining_validator_ids - covered_validators


def test_pick_from_aggregated_signatures_requires_payloads() -> None:
    state = make_state(1)

    with pytest.raises(ValueError, match="aggregated payloads is required"):
        state._pick_from_aggregated_signatures(
            remaining_validator_ids={Uint64(0)},
            data_root=b"\x55" * 32,
            aggregated_payloads=None,
        )


def test_pick_from_aggregated_signatures_errors_on_empty_remaining() -> None:
    state = make_state(1)

    with pytest.raises(ValueError, match="remaining validator ids cannot be empty"):
        state._pick_from_aggregated_signatures(
            remaining_validator_ids=set(),
            data_root=b"\x66" * 32,
            aggregated_payloads={},
        )


def test_pick_from_aggregated_signatures_errors_when_no_candidates() -> None:
    state = make_state(1)
    data_root = b"\x77" * 32

    with pytest.raises(ValueError, match="Failed to locate an aggregated signature payload"):
        state._pick_from_aggregated_signatures(
            remaining_validator_ids={Uint64(0)},
            data_root=data_root,
            aggregated_payloads={(Uint64(0), data_root): []},
        )


def test_compute_aggregated_signatures_prefers_full_gossip_payload() -> None:
    state = make_state(2)
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    att_data = make_attestation_data(2, make_bytes32(3), make_bytes32(4), source=source)
    attestations = [Attestation(validator_id=Uint64(i), data=att_data) for i in range(2)]
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
    source = Checkpoint(root=make_bytes32(2), slot=Slot(0))
    att_data = make_attestation_data(3, make_bytes32(5), make_bytes32(6), source=source)
    attestations = [Attestation(validator_id=Uint64(i), data=att_data) for i in range(3)]
    data_root = att_data.data_root_bytes()
    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    block_bits = AggregationBits.from_validator_indices([Uint64(1), Uint64(2)])
    block_signature = MultisigAggregatedSignature(data=b"block-12")
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
    source = Checkpoint(root=make_bytes32(27), slot=Slot(0))
    att_data = make_attestation_data(11, make_bytes32(28), make_bytes32(29), source=source)
    attestations = [Attestation(validator_id=Uint64(i), data=att_data) for i in range(2)]
    data_root = att_data.data_root_bytes()

    # Only gossip signature for validator 0 (incomplete)
    gossip_signatures = {(Uint64(0), data_root): make_signature(0)}

    # Block payload covers both validators
    block_bits = AggregationBits.from_validator_indices([Uint64(0), Uint64(1)])
    block_signature = MultisigAggregatedSignature(data=b"block-fallback")
    aggregated_payloads = {
        (Uint64(0), data_root): [(block_bits, block_signature)],
        (Uint64(1), data_root): [(block_bits, block_signature)],
    }

    aggregated_atts, aggregated_sigs = state.compute_aggregated_signatures(
        attestations,
        gossip_signatures=gossip_signatures,
        aggregated_payloads=aggregated_payloads,
    )

    # Should include both gossip-covered and fallback payload attestations/signatures
    assert len(aggregated_atts) == 2
    assert len(aggregated_sigs) == 2
    assert block_signature in aggregated_sigs
    assert TEST_AGGREGATED_SIGNATURE in aggregated_sigs
