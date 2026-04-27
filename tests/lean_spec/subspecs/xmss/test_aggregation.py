"""Tests for XMSS signature aggregation with children and individual signatures."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.forks.lstar.containers.checkpoint import Checkpoint
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, AggregationError
from lean_spec.types import ByteListMiB
from tests.lean_spec.helpers import make_attestation_data_simple, make_bytes32


def _sign_and_aggregate(
    key_manager: XmssKeyManager,
    validator_ids: list[ValidatorIndex],
    att_data_args: tuple[Slot, int, int, Checkpoint],
) -> AggregatedSignatureProof:
    """Sign attestation data with the given validators and aggregate."""
    slot, head, target, source = att_data_args
    att_data = make_attestation_data_simple(slot, make_bytes32(head), make_bytes32(target), source)
    data_root = hash_tree_root(att_data)

    xmss_participants = ValidatorIndices(data=validator_ids).to_aggregation_bits()
    raw_xmss = list(
        zip(
            [key_manager[vid].attestation_public for vid in validator_ids],
            [key_manager.sign_attestation_data(vid, att_data) for vid in validator_ids],
            strict=True,
        )
    )
    proof = AggregatedSignatureProof.aggregate(
        xmss_participants=xmss_participants,
        children=[],
        raw_xmss=raw_xmss,
        message=data_root,
        slot=att_data.slot,
    )
    return proof


def test_aggregate_rejects_empty_inputs() -> None:
    """Aggregation with no signatures and no children raises an error."""
    with pytest.raises(AggregationError, match="At least one raw signature or child proof"):
        AggregatedSignatureProof.aggregate(
            xmss_participants=None,
            children=[],
            raw_xmss=[],
            message=make_bytes32(0),
            slot=Slot(0),
        )


def test_aggregate_multiple_signatures(key_manager: XmssKeyManager) -> None:
    """Multiple validators' signatures can be aggregated into a single proof."""
    source = Checkpoint(root=make_bytes32(10), slot=Slot(0))
    att_data = make_attestation_data_simple(Slot(2), make_bytes32(11), make_bytes32(12), source)
    vids = [ValidatorIndex(i) for i in range(4)]

    xmss_participants = ValidatorIndices(data=vids).to_aggregation_bits()
    raw_xmss = list(
        zip(
            [key_manager[vid].attestation_public for vid in vids],
            [key_manager.sign_attestation_data(vid, att_data) for vid in vids],
            strict=True,
        )
    )

    proof = AggregatedSignatureProof.aggregate(
        xmss_participants=xmss_participants,
        children=[],
        raw_xmss=raw_xmss,
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )

    assert set(proof.participants.to_validator_indices()) == set(vids)

    public_keys = [key_manager[vid].attestation_public for vid in vids]
    proof.verify(
        public_keys=public_keys,
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )


def test_aggregate_children_with_raw_signatures(key_manager: XmssKeyManager) -> None:
    """A child proof can be combined with additional raw signatures."""
    source = Checkpoint(root=make_bytes32(30), slot=Slot(0))
    att_args = (Slot(4), 31, 32, source)
    att_data = make_attestation_data_simple(
        att_args[0], make_bytes32(att_args[1]), make_bytes32(att_args[2]), att_args[3]
    )

    # Child: validators 0, 1
    child = _sign_and_aggregate(key_manager, [ValidatorIndex(0), ValidatorIndex(1)], att_args)

    # Additional raw signatures: validators 2, 3
    extra_vids = [ValidatorIndex(2), ValidatorIndex(3)]
    xmss_participants = ValidatorIndices(data=extra_vids).to_aggregation_bits()
    raw_xmss = list(
        zip(
            [key_manager[vid].attestation_public for vid in extra_vids],
            [key_manager.sign_attestation_data(vid, att_data) for vid in extra_vids],
            strict=True,
        )
    )

    parent = AggregatedSignatureProof.aggregate(
        xmss_participants=xmss_participants,
        children=[(child, [key_manager[ValidatorIndex(i)].attestation_public for i in range(2)])],
        raw_xmss=raw_xmss,
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )

    expected_vids = {ValidatorIndex(i) for i in range(4)}
    assert set(parent.participants.to_validator_indices()) == expected_vids

    public_keys = [key_manager[ValidatorIndex(i)].attestation_public for i in range(4)]
    parent.verify(
        public_keys=public_keys,
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )


def test_aggregate_three_children(key_manager: XmssKeyManager) -> None:
    """Three child proofs can be aggregated together."""
    source = Checkpoint(root=make_bytes32(40), slot=Slot(0))
    att_args = (Slot(5), 41, 42, source)
    att_data = make_attestation_data_simple(
        att_args[0], make_bytes32(att_args[1]), make_bytes32(att_args[2]), att_args[3]
    )

    child_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], att_args)
    child_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], att_args)
    child_c = _sign_and_aggregate(key_manager, [ValidatorIndex(2)], att_args)

    child_a_pks = [key_manager[ValidatorIndex(0)].attestation_public]
    child_b_pks = [key_manager[ValidatorIndex(1)].attestation_public]
    child_c_pks = [key_manager[ValidatorIndex(2)].attestation_public]

    parent = AggregatedSignatureProof.aggregate(
        xmss_participants=None,
        children=[(child_a, child_a_pks), (child_b, child_b_pks), (child_c, child_c_pks)],
        raw_xmss=[],
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )

    expected_vids = {ValidatorIndex(i) for i in range(3)}
    assert set(parent.participants.to_validator_indices()) == expected_vids

    public_keys = [key_manager[ValidatorIndex(i)].attestation_public for i in range(3)]
    parent.verify(
        public_keys=public_keys,
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )


def test_aggregate_children_of_children(key_manager: XmssKeyManager) -> None:
    """Two-level recursive aggregation: aggregate proofs that are themselves aggregated."""
    source = Checkpoint(root=make_bytes32(90), slot=Slot(0))
    att_args = (Slot(6), 91, 92, source)
    att_data = make_attestation_data_simple(
        att_args[0], make_bytes32(att_args[1]), make_bytes32(att_args[2]), att_args[3]
    )
    msg = hash_tree_root(att_data)

    # Level 0: four individual leaf proofs
    leaf_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], att_args)
    leaf_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], att_args)
    leaf_c = _sign_and_aggregate(key_manager, [ValidatorIndex(2)], att_args)
    leaf_d = _sign_and_aggregate(key_manager, [ValidatorIndex(3)], att_args)

    leaf_a_pks = [key_manager[ValidatorIndex(0)].attestation_public]
    leaf_b_pks = [key_manager[ValidatorIndex(1)].attestation_public]
    leaf_c_pks = [key_manager[ValidatorIndex(2)].attestation_public]
    leaf_d_pks = [key_manager[ValidatorIndex(3)].attestation_public]

    # Level 1: two intermediate proofs
    mid_ab = AggregatedSignatureProof.aggregate(
        xmss_participants=None,
        children=[(leaf_a, leaf_a_pks), (leaf_b, leaf_b_pks)],
        raw_xmss=[],
        message=msg,
        slot=att_data.slot,
    )
    mid_cd = AggregatedSignatureProof.aggregate(
        xmss_participants=None,
        children=[(leaf_c, leaf_c_pks), (leaf_d, leaf_d_pks)],
        raw_xmss=[],
        message=msg,
        slot=att_data.slot,
    )

    # Level 2: final root proof
    root = AggregatedSignatureProof.aggregate(
        xmss_participants=None,
        children=[(mid_ab, leaf_a_pks + leaf_b_pks), (mid_cd, leaf_c_pks + leaf_d_pks)],
        raw_xmss=[],
        message=msg,
        slot=att_data.slot,
    )

    assert set(root.participants.to_validator_indices()) == {ValidatorIndex(i) for i in range(4)}
    root.verify(
        public_keys=[key_manager[ValidatorIndex(i)].attestation_public for i in range(4)],
        message=msg,
        slot=att_data.slot,
    )


def test_aggregate_mixed_children_and_raw_multiple(key_manager: XmssKeyManager) -> None:
    """Two child proofs combined with additional raw signatures."""
    source = Checkpoint(root=make_bytes32(100), slot=Slot(0))
    att_args = (Slot(7), 101, 102, source)
    att_data = make_attestation_data_simple(
        att_args[0], make_bytes32(att_args[1]), make_bytes32(att_args[2]), att_args[3]
    )
    msg = hash_tree_root(att_data)

    # Two child proofs
    child_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], att_args)
    child_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], att_args)

    child_a_pks = [key_manager[ValidatorIndex(0)].attestation_public]
    child_b_pks = [key_manager[ValidatorIndex(1)].attestation_public]

    # Additional raw signatures from validators 2 and 3
    extra_vids = [ValidatorIndex(2), ValidatorIndex(3)]
    xmss_participants = ValidatorIndices(data=extra_vids).to_aggregation_bits()
    raw_xmss = list(
        zip(
            [key_manager[vid].attestation_public for vid in extra_vids],
            [key_manager.sign_attestation_data(vid, att_data) for vid in extra_vids],
            strict=True,
        )
    )

    proof = AggregatedSignatureProof.aggregate(
        xmss_participants=xmss_participants,
        children=[(child_a, child_a_pks), (child_b, child_b_pks)],
        raw_xmss=raw_xmss,
        message=msg,
        slot=att_data.slot,
    )

    assert set(proof.participants.to_validator_indices()) == {ValidatorIndex(i) for i in range(4)}
    proof.verify(
        public_keys=[key_manager[ValidatorIndex(i)].attestation_public for i in range(4)],
        message=msg,
        slot=att_data.slot,
    )


def test_aggregate_wrong_message_fails_verification(key_manager: XmssKeyManager) -> None:
    """Verification fails when the message doesn't match what was signed."""
    source = Checkpoint(root=make_bytes32(120), slot=Slot(0))
    att_data = make_attestation_data_simple(Slot(1), make_bytes32(121), make_bytes32(122), source)
    vid = ValidatorIndex(0)

    xmss_participants = ValidatorIndices(data=[vid]).to_aggregation_bits()
    raw_xmss = [
        (
            key_manager[vid].attestation_public,
            key_manager.sign_attestation_data(vid, att_data),
        )
    ]

    proof = AggregatedSignatureProof.aggregate(
        xmss_participants=xmss_participants,
        children=[],
        raw_xmss=raw_xmss,
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )

    wrong_message = make_bytes32(999)
    with pytest.raises(AggregationError, match="verification failed"):
        proof.verify(
            public_keys=[key_manager[vid].attestation_public],
            message=wrong_message,
            slot=att_data.slot,
        )


def test_aggregate_wrong_slot_fails_verification(key_manager: XmssKeyManager) -> None:
    """Verification fails when the slot doesn't match what was signed."""
    source = Checkpoint(root=make_bytes32(130), slot=Slot(0))
    att_data = make_attestation_data_simple(Slot(2), make_bytes32(131), make_bytes32(132), source)
    vid = ValidatorIndex(1)

    xmss_participants = ValidatorIndices(data=[vid]).to_aggregation_bits()
    raw_xmss = [
        (
            key_manager[vid].attestation_public,
            key_manager.sign_attestation_data(vid, att_data),
        )
    ]

    proof = AggregatedSignatureProof.aggregate(
        xmss_participants=xmss_participants,
        children=[],
        raw_xmss=raw_xmss,
        message=hash_tree_root(att_data),
        slot=att_data.slot,
    )

    with pytest.raises(AggregationError, match="verification failed"):
        proof.verify(
            public_keys=[key_manager[vid].attestation_public],
            message=hash_tree_root(att_data),
            slot=Slot(99),
        )


def test_aggregate_corrupted_proof_fails_verification(key_manager: XmssKeyManager) -> None:
    """Verification fails when proof bytes are corrupted."""
    source = Checkpoint(root=make_bytes32(140), slot=Slot(0))
    att_data = make_attestation_data_simple(Slot(3), make_bytes32(141), make_bytes32(142), source)
    vid = ValidatorIndex(2)

    proof = _sign_and_aggregate(
        key_manager,
        [vid],
        (att_data.slot, 141, 142, source),
    )

    # Corrupt the proof data by flipping bytes
    corrupted_data = bytearray(proof.proof_data.encode_bytes())
    corrupted_data[10] ^= 0xFF
    corrupted_data[20] ^= 0xFF
    corrupted_proof = AggregatedSignatureProof(
        participants=proof.participants,
        proof_data=ByteListMiB(data=bytes(corrupted_data)),
    )

    with pytest.raises(AggregationError, match="verification failed"):
        corrupted_proof.verify(
            public_keys=[key_manager[vid].attestation_public],
            message=hash_tree_root(att_data),
            slot=att_data.slot,
        )


def test_aggregate_child_signed_different_message_fails(key_manager: XmssKeyManager) -> None:
    """Aggregating children that signed different messages fails."""
    source = Checkpoint(root=make_bytes32(150), slot=Slot(0))
    att_args_a = (Slot(4), 151, 152, source)
    att_args_b = (Slot(4), 161, 162, source)
    att_data_b = make_attestation_data_simple(
        att_args_b[0], make_bytes32(att_args_b[1]), make_bytes32(att_args_b[2]), att_args_b[3]
    )

    # Child A signs message A
    child_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], att_args_a)
    # Child B signs message B (different)
    child_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], att_args_b)

    child_a_pks = [key_manager[ValidatorIndex(0)].attestation_public]
    child_b_pks = [key_manager[ValidatorIndex(1)].attestation_public]

    # Aggregation rejects children that signed different messages
    with pytest.raises(AggregationError):
        AggregatedSignatureProof.aggregate(
            xmss_participants=None,
            children=[(child_a, child_a_pks), (child_b, child_b_pks)],
            raw_xmss=[],
            message=hash_tree_root(att_data_b),
            slot=att_data_b.slot,
        )


def test_aggregate_rejects_single_child_without_raw(key_manager: XmssKeyManager) -> None:
    """A single child without raw signatures is rejected (need at least two children)."""
    # Create a stub child proof without calling the Rust bindings
    stub_child = AggregatedSignatureProof(
        participants=ValidatorIndices(data=[ValidatorIndex(0)]).to_aggregation_bits(),
        proof_data=ByteListMiB(data=b"\x00"),
    )

    with pytest.raises(AggregationError, match="At least two child proofs"):
        AggregatedSignatureProof.aggregate(
            xmss_participants=None,
            children=[
                (stub_child, [key_manager[ValidatorIndex(i)].attestation_public for i in range(1)])
            ],
            raw_xmss=[],
            message=make_bytes32(0),
            slot=Slot(0),
        )


def test_aggregate_rejects_mismatched_participant_count(
    key_manager: XmssKeyManager,
) -> None:
    """Participant bitfield count must match raw signature count."""
    source = Checkpoint(root=make_bytes32(60), slot=Slot(0))
    att_data = make_attestation_data_simple(Slot(7), make_bytes32(61), make_bytes32(62), source)

    # Claim 2 participants but only provide 1 signature
    xmss_participants = ValidatorIndices(
        data=[ValidatorIndex(0), ValidatorIndex(1)]
    ).to_aggregation_bits()
    raw_xmss = [
        (
            key_manager[ValidatorIndex(0)].attestation_public,
            key_manager.sign_attestation_data(ValidatorIndex(0), att_data),
        )
    ]

    with pytest.raises(AggregationError, match="does not match"):
        AggregatedSignatureProof.aggregate(
            xmss_participants=xmss_participants,
            children=[],
            raw_xmss=raw_xmss,
            message=hash_tree_root(att_data),
            slot=att_data.slot,
        )
