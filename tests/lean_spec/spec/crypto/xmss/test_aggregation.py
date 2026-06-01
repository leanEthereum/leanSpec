"""Tests for XMSS signature aggregation with children and individual signatures."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregationError,
    MultiMessageAggregate,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz import ByteList512KiB
from tests.lean_spec.helpers import make_attestation_data_simple, make_bytes32


def _sign_and_aggregate(
    key_manager: XmssKeyManager,
    validator_indices: list[ValidatorIndex],
    attestation_data_args: tuple[Slot, int, int, Checkpoint],
) -> SingleMessageAggregate:
    """Sign attestation data with the given validators and aggregate."""
    slot, head, target, source = attestation_data_args
    attestation_data = make_attestation_data_simple(
        slot, make_bytes32(head), make_bytes32(target), source
    )
    data_root = hash_tree_root(attestation_data)

    raw_xmss = [
        (
            validator_index,
            key_manager[validator_index].attestation_keypair.public_key,
            key_manager.sign_attestation_data(validator_index, attestation_data),
        )
        for validator_index in validator_indices
    ]
    return SingleMessageAggregate.aggregate(
        children=[],
        raw_xmss=raw_xmss,
        message=data_root,
        slot=attestation_data.slot,
    )


def test_aggregate_multiple_signatures(key_manager: XmssKeyManager) -> None:
    """Multiple validators' signatures aggregate into one single-message aggregate proof."""
    source = Checkpoint(root=make_bytes32(10), slot=Slot(0))
    attestation_data = make_attestation_data_simple(
        Slot(2), make_bytes32(11), make_bytes32(12), source
    )
    validator_indices = [ValidatorIndex(i) for i in range(4)]

    raw_xmss = [
        (
            validator_index,
            key_manager[validator_index].attestation_keypair.public_key,
            key_manager.sign_attestation_data(validator_index, attestation_data),
        )
        for validator_index in validator_indices
    ]

    proof = SingleMessageAggregate.aggregate(
        children=[],
        raw_xmss=raw_xmss,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )

    assert set(proof.participants.to_validator_indices()) == set(validator_indices)

    public_keys = [
        key_manager[validator_index].attestation_keypair.public_key
        for validator_index in validator_indices
    ]
    proof.verify(
        public_keys=public_keys,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )


def test_aggregate_children_with_raw_signatures(key_manager: XmssKeyManager) -> None:
    """A child proof can be combined with additional raw signatures."""
    source = Checkpoint(root=make_bytes32(30), slot=Slot(0))
    attestation_args = (Slot(4), 31, 32, source)
    attestation_data = make_attestation_data_simple(
        attestation_args[0],
        make_bytes32(attestation_args[1]),
        make_bytes32(attestation_args[2]),
        attestation_args[3],
    )

    # Child: validators 0, 1
    child = _sign_and_aggregate(
        key_manager, [ValidatorIndex(0), ValidatorIndex(1)], attestation_args
    )

    # Additional raw signatures: validators 2, 3
    extra_vids = [ValidatorIndex(2), ValidatorIndex(3)]
    raw_xmss = [
        (
            validator_index,
            key_manager[validator_index].attestation_keypair.public_key,
            key_manager.sign_attestation_data(validator_index, attestation_data),
        )
        for validator_index in extra_vids
    ]

    parent = SingleMessageAggregate.aggregate(
        children=[
            (
                child,
                [key_manager[ValidatorIndex(i)].attestation_keypair.public_key for i in range(2)],
            )
            for child in [child, child]
        ],
        raw_xmss=raw_xmss,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )

    expected_vids = {ValidatorIndex(i) for i in range(4)}
    assert set(parent.participants.to_validator_indices()) == expected_vids

    public_keys = [key_manager[ValidatorIndex(i)].attestation_keypair.public_key for i in range(4)]
    parent.verify(
        public_keys=public_keys,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )


def test_aggregate_three_children(key_manager: XmssKeyManager) -> None:
    """Three child proofs can be aggregated together."""
    source = Checkpoint(root=make_bytes32(40), slot=Slot(0))
    attestation_args = (Slot(5), 41, 42, source)
    attestation_data = make_attestation_data_simple(
        attestation_args[0],
        make_bytes32(attestation_args[1]),
        make_bytes32(attestation_args[2]),
        attestation_args[3],
    )

    child_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], attestation_args)
    child_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], attestation_args)
    child_c = _sign_and_aggregate(key_manager, [ValidatorIndex(2)], attestation_args)

    child_a_public_keys = [key_manager[ValidatorIndex(0)].attestation_keypair.public_key]
    child_b_public_keys = [key_manager[ValidatorIndex(1)].attestation_keypair.public_key]
    child_c_public_keys = [key_manager[ValidatorIndex(2)].attestation_keypair.public_key]

    parent = SingleMessageAggregate.aggregate(
        children=[
            (child_a, child_a_public_keys),
            (child_b, child_b_public_keys),
            (child_c, child_c_public_keys),
        ],
        raw_xmss=[],
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )

    expected_vids = {ValidatorIndex(i) for i in range(3)}
    assert set(parent.participants.to_validator_indices()) == expected_vids

    public_keys = [key_manager[ValidatorIndex(i)].attestation_keypair.public_key for i in range(3)]
    parent.verify(
        public_keys=public_keys,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )


def test_aggregate_children_of_children(key_manager: XmssKeyManager) -> None:
    """Two-level recursive aggregation: aggregate proofs that are themselves aggregated."""
    source = Checkpoint(root=make_bytes32(90), slot=Slot(0))
    attestation_args = (Slot(6), 91, 92, source)
    attestation_data = make_attestation_data_simple(
        attestation_args[0],
        make_bytes32(attestation_args[1]),
        make_bytes32(attestation_args[2]),
        attestation_args[3],
    )
    message = hash_tree_root(attestation_data)

    # Level 0: four individual leaf proofs.
    leaf_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], attestation_args)
    leaf_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], attestation_args)
    leaf_c = _sign_and_aggregate(key_manager, [ValidatorIndex(2)], attestation_args)
    leaf_d = _sign_and_aggregate(key_manager, [ValidatorIndex(3)], attestation_args)

    leaf_a_public_keys = [key_manager[ValidatorIndex(0)].attestation_keypair.public_key]
    leaf_b_public_keys = [key_manager[ValidatorIndex(1)].attestation_keypair.public_key]
    leaf_c_public_keys = [key_manager[ValidatorIndex(2)].attestation_keypair.public_key]
    leaf_d_public_keys = [key_manager[ValidatorIndex(3)].attestation_keypair.public_key]

    # Level 1: two intermediate proofs.
    mid_ab = SingleMessageAggregate.aggregate(
        children=[(leaf_a, leaf_a_public_keys), (leaf_b, leaf_b_public_keys)],
        raw_xmss=[],
        message=message,
        slot=attestation_data.slot,
    )
    mid_cd = SingleMessageAggregate.aggregate(
        children=[(leaf_c, leaf_c_public_keys), (leaf_d, leaf_d_public_keys)],
        raw_xmss=[],
        message=message,
        slot=attestation_data.slot,
    )

    # Level 2: final root proof.
    root = SingleMessageAggregate.aggregate(
        children=[
            (mid_ab, leaf_a_public_keys + leaf_b_public_keys),
            (mid_cd, leaf_c_public_keys + leaf_d_public_keys),
        ],
        raw_xmss=[],
        message=message,
        slot=attestation_data.slot,
    )

    assert set(root.participants.to_validator_indices()) == {ValidatorIndex(i) for i in range(4)}
    root.verify(
        public_keys=[
            key_manager[ValidatorIndex(i)].attestation_keypair.public_key for i in range(4)
        ],
        message=message,
        slot=attestation_data.slot,
    )


def test_aggregate_mixed_children_and_raw_multiple(key_manager: XmssKeyManager) -> None:
    """Two child proofs combined with additional raw signatures."""
    source = Checkpoint(root=make_bytes32(100), slot=Slot(0))
    attestation_args = (Slot(7), 101, 102, source)
    attestation_data = make_attestation_data_simple(
        attestation_args[0],
        make_bytes32(attestation_args[1]),
        make_bytes32(attestation_args[2]),
        attestation_args[3],
    )
    message = hash_tree_root(attestation_data)

    # Two child proofs.
    child_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], attestation_args)
    child_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], attestation_args)

    child_a_public_keys = [key_manager[ValidatorIndex(0)].attestation_keypair.public_key]
    child_b_public_keys = [key_manager[ValidatorIndex(1)].attestation_keypair.public_key]

    # Additional raw signatures from validators 2 and 3.
    extra_vids = [ValidatorIndex(2), ValidatorIndex(3)]
    raw_xmss = [
        (
            validator_index,
            key_manager[validator_index].attestation_keypair.public_key,
            key_manager.sign_attestation_data(validator_index, attestation_data),
        )
        for validator_index in extra_vids
    ]

    proof = SingleMessageAggregate.aggregate(
        children=[(child_a, child_a_public_keys), (child_b, child_b_public_keys)],
        raw_xmss=raw_xmss,
        message=message,
        slot=attestation_data.slot,
    )

    assert set(proof.participants.to_validator_indices()) == {ValidatorIndex(i) for i in range(4)}
    proof.verify(
        public_keys=[
            key_manager[ValidatorIndex(i)].attestation_keypair.public_key for i in range(4)
        ],
        message=message,
        slot=attestation_data.slot,
    )


def test_single_message_aggregate_verify_rejects_public_key_count_mismatch(
    key_manager: XmssKeyManager,
) -> None:
    """Verification refuses a public_key set whose size does not match the bitfield."""
    source = Checkpoint(root=make_bytes32(160), slot=Slot(0))
    attestation_args = (Slot(2), 161, 162, source)
    validator_indices = [ValidatorIndex(0), ValidatorIndex(1)]

    proof = _sign_and_aggregate(key_manager, validator_indices, attestation_args)
    # The bitfield names two validators but only one key is supplied.
    only_one = [key_manager[ValidatorIndex(0)].attestation_keypair.public_key]

    with pytest.raises(
        AggregationError,
        match="single-message aggregate verify expected 2 pubkeys for participants, got 1",
    ):
        proof.verify(public_keys=only_one, message=make_bytes32(161), slot=attestation_args[0])


def test_multi_message_aggregate_split_by_message_rejected_under_test_prover(
    key_manager: XmssKeyManager,
) -> None:
    """Splitting a merged proof aborts under the reduced test-config prover.

    The split branch is functional only under the production prover.
    The test-config build aborts it with an in-circuit assertion.
    Exercising it here drives the serialization and error-translation path.
    """
    source = Checkpoint(root=make_bytes32(600), slot=Slot(0))
    attestation_args_a = (Slot(11), 601, 602, source)
    attestation_args_b = (Slot(11), 603, 604, source)
    attestation_data_a = make_attestation_data_simple(
        attestation_args_a[0],
        make_bytes32(attestation_args_a[1]),
        make_bytes32(attestation_args_a[2]),
        attestation_args_a[3],
    )

    vids_a = [ValidatorIndex(0), ValidatorIndex(1)]
    vids_b = [ValidatorIndex(2), ValidatorIndex(3)]
    part_a = _sign_and_aggregate(key_manager, vids_a, attestation_args_a)
    part_b = _sign_and_aggregate(key_manager, vids_b, attestation_args_b)

    public_keys_a = [
        key_manager[validator_index].attestation_keypair.public_key for validator_index in vids_a
    ]
    public_keys_b = [
        key_manager[validator_index].attestation_keypair.public_key for validator_index in vids_b
    ]

    merged = MultiMessageAggregate.aggregate(
        parts=[part_a, part_b],
        public_keys_per_part=[public_keys_a, public_keys_b],
    )

    with pytest.raises(AggregationError, match="multi-message aggregate split failed"):
        merged.split_by_message(
            message=hash_tree_root(attestation_data_a),
            public_keys_per_message=[public_keys_a, public_keys_b],
            participants=part_a.participants,
        )


def test_aggregate_wrong_message_fails_verification(key_manager: XmssKeyManager) -> None:
    """Verification fails when the caller passes a message that does not match the proof."""
    source = Checkpoint(root=make_bytes32(120), slot=Slot(0))
    attestation_data = make_attestation_data_simple(
        Slot(1), make_bytes32(121), make_bytes32(122), source
    )
    validator_index = ValidatorIndex(0)

    proof = _sign_and_aggregate(
        key_manager, [validator_index], (attestation_data.slot, 121, 122, source)
    )

    with pytest.raises(AggregationError, match="verification failed"):
        proof.verify(
            public_keys=[key_manager[validator_index].attestation_keypair.public_key],
            message=make_bytes32(123),
            slot=attestation_data.slot,
        )


def test_aggregate_wrong_slot_fails_verification(key_manager: XmssKeyManager) -> None:
    """Verification fails when the caller passes a slot that does not match the proof."""
    source = Checkpoint(root=make_bytes32(130), slot=Slot(0))
    attestation_data = make_attestation_data_simple(
        Slot(2), make_bytes32(131), make_bytes32(132), source
    )
    validator_index = ValidatorIndex(1)

    proof = _sign_and_aggregate(
        key_manager, [validator_index], (attestation_data.slot, 131, 132, source)
    )

    with pytest.raises(AggregationError, match="verification failed"):
        proof.verify(
            public_keys=[key_manager[validator_index].attestation_keypair.public_key],
            message=hash_tree_root(attestation_data),
            slot=Slot(99),
        )


def test_aggregate_corrupted_proof_fails_verification(key_manager: XmssKeyManager) -> None:
    """Verification fails when proof bytes are corrupted."""
    source = Checkpoint(root=make_bytes32(140), slot=Slot(0))
    attestation_data = make_attestation_data_simple(
        Slot(3), make_bytes32(141), make_bytes32(142), source
    )
    validator_index = ValidatorIndex(2)

    proof = _sign_and_aggregate(
        key_manager, [validator_index], (attestation_data.slot, 141, 142, source)
    )

    corrupted_bytes = bytearray(proof.proof.data)
    corrupted_bytes[10] ^= 0xFF
    corrupted_bytes[20] ^= 0xFF
    proof = SingleMessageAggregate(
        participants=proof.participants,
        proof=ByteList512KiB(data=bytes(corrupted_bytes)),
    )

    with pytest.raises(AggregationError, match="verification failed"):
        proof.verify(
            public_keys=[key_manager[validator_index].attestation_keypair.public_key],
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )


def test_aggregate_child_signed_different_message_fails(key_manager: XmssKeyManager) -> None:
    """Aggregating children that signed different messages fails inside the binding."""
    source = Checkpoint(root=make_bytes32(150), slot=Slot(0))
    attestation_args_a = (Slot(4), 151, 152, source)
    attestation_args_b = (Slot(4), 161, 162, source)
    attestation_data_b = make_attestation_data_simple(
        attestation_args_b[0],
        make_bytes32(attestation_args_b[1]),
        make_bytes32(attestation_args_b[2]),
        attestation_args_b[3],
    )

    child_a = _sign_and_aggregate(key_manager, [ValidatorIndex(0)], attestation_args_a)
    child_b = _sign_and_aggregate(key_manager, [ValidatorIndex(1)], attestation_args_b)

    child_a_public_keys = [key_manager[ValidatorIndex(0)].attestation_keypair.public_key]
    child_b_public_keys = [key_manager[ValidatorIndex(1)].attestation_keypair.public_key]

    # The binding rejects mismatching messages during recursive aggregation.
    with pytest.raises(AggregationError):
        SingleMessageAggregate.aggregate(
            children=[(child_a, child_a_public_keys), (child_b, child_b_public_keys)],
            raw_xmss=[],
            message=hash_tree_root(attestation_data_b),
            slot=attestation_data_b.slot,
        )


def test_multi_message_aggregate_rejects_empty_parts() -> None:
    """multi-message aggregate aggregation requires at least one single-message aggregate input."""
    with pytest.raises(AggregationError, match="at least one single-message aggregate input"):
        MultiMessageAggregate.aggregate(parts=[], public_keys_per_part=[])


def test_multi_message_aggregate_rejects_mismatched_public_key_layout(
    key_manager: XmssKeyManager,
) -> None:
    """The per-part public_key layout must match the participant count of each part."""
    source = Checkpoint(root=make_bytes32(200), slot=Slot(0))
    attestation_args = (Slot(7), 201, 202, source)

    part = _sign_and_aggregate(
        key_manager,
        [ValidatorIndex(0), ValidatorIndex(1)],
        attestation_args,
    )
    # Layout claims one public_key for a part that binds two participants.
    wrong_layout = [[key_manager[ValidatorIndex(0)].attestation_keypair.public_key]]

    with pytest.raises(AggregationError, match="expected 2 pubkeys, got 1"):
        MultiMessageAggregate.aggregate(
            parts=[part],
            public_keys_per_part=wrong_layout,
        )


def test_multi_message_aggregate_propagates_prover_error(key_manager: XmssKeyManager) -> None:
    """A corrupted component proof makes the merge prover reject the inputs."""
    source = Checkpoint(root=make_bytes32(210), slot=Slot(0))
    attestation_args = (Slot(8), 211, 212, source)
    validator_indices = [ValidatorIndex(0), ValidatorIndex(1)]

    part = _sign_and_aggregate(key_manager, validator_indices, attestation_args)
    public_keys = [
        key_manager[validator_index].attestation_keypair.public_key
        for validator_index in validator_indices
    ]

    corrupted_bytes = bytearray(part.proof.data)
    corrupted_bytes[10] ^= 0xFF
    corrupted_bytes[20] ^= 0xFF
    part = SingleMessageAggregate(
        participants=part.participants,
        proof=ByteList512KiB(data=bytes(corrupted_bytes)),
    )

    with pytest.raises(AggregationError, match="merge_many_type_1 failed"):
        MultiMessageAggregate.aggregate(parts=[part], public_keys_per_part=[public_keys])


def test_multi_message_aggregate_verify_round_trip(key_manager: XmssKeyManager) -> None:
    """Merging two distinct-message single-message aggregates round-trips through verify."""
    source = Checkpoint(root=make_bytes32(300), slot=Slot(0))

    # Two distinct messages signed by disjoint validator sets.
    attestation_args_a = (Slot(8), 301, 302, source)
    attestation_args_b = (Slot(8), 303, 304, source)
    attestation_data_a = make_attestation_data_simple(
        attestation_args_a[0],
        make_bytes32(attestation_args_a[1]),
        make_bytes32(attestation_args_a[2]),
        attestation_args_a[3],
    )
    attestation_data_b = make_attestation_data_simple(
        attestation_args_b[0],
        make_bytes32(attestation_args_b[1]),
        make_bytes32(attestation_args_b[2]),
        attestation_args_b[3],
    )

    vids_a = [ValidatorIndex(0), ValidatorIndex(1)]
    vids_b = [ValidatorIndex(2), ValidatorIndex(3)]
    part_a = _sign_and_aggregate(key_manager, vids_a, attestation_args_a)
    part_b = _sign_and_aggregate(key_manager, vids_b, attestation_args_b)

    public_keys_a = [
        key_manager[validator_index].attestation_keypair.public_key for validator_index in vids_a
    ]
    public_keys_b = [
        key_manager[validator_index].attestation_keypair.public_key for validator_index in vids_b
    ]

    merged = MultiMessageAggregate.aggregate(
        parts=[part_a, part_b],
        public_keys_per_part=[public_keys_a, public_keys_b],
    )

    merged.verify(
        public_keys_per_message=[public_keys_a, public_keys_b],
        messages=[
            (hash_tree_root(attestation_data_a), attestation_data_a.slot),
            (hash_tree_root(attestation_data_b), attestation_data_b.slot),
        ],
    )


def test_multi_message_aggregate_verify_rejects_message_swap(key_manager: XmssKeyManager) -> None:
    """Swapping the parallel message bindings causes verification to fail.

    Without per-component message binding a proposer could pair honest
    signatures with attacker-chosen attestation data.
    """
    source = Checkpoint(root=make_bytes32(400), slot=Slot(0))

    attestation_args_a = (Slot(9), 401, 402, source)
    attestation_args_b = (Slot(9), 403, 404, source)
    attestation_data_a = make_attestation_data_simple(
        attestation_args_a[0],
        make_bytes32(attestation_args_a[1]),
        make_bytes32(attestation_args_a[2]),
        attestation_args_a[3],
    )
    attestation_data_b = make_attestation_data_simple(
        attestation_args_b[0],
        make_bytes32(attestation_args_b[1]),
        make_bytes32(attestation_args_b[2]),
        attestation_args_b[3],
    )

    vids_a = [ValidatorIndex(0), ValidatorIndex(1)]
    vids_b = [ValidatorIndex(2), ValidatorIndex(3)]
    part_a = _sign_and_aggregate(key_manager, vids_a, attestation_args_a)
    part_b = _sign_and_aggregate(key_manager, vids_b, attestation_args_b)

    public_keys_a = [
        key_manager[validator_index].attestation_keypair.public_key for validator_index in vids_a
    ]
    public_keys_b = [
        key_manager[validator_index].attestation_keypair.public_key for validator_index in vids_b
    ]

    merged = MultiMessageAggregate.aggregate(
        parts=[part_a, part_b],
        public_keys_per_part=[public_keys_a, public_keys_b],
    )

    # Swap the parallel messages: part_a's public_keys are now paired with part_b's
    # message and vice versa.
    with pytest.raises(AggregationError, match="verification failed"):
        merged.verify(
            public_keys_per_message=[public_keys_a, public_keys_b],
            messages=[
                (hash_tree_root(attestation_data_b), attestation_data_b.slot),
                (hash_tree_root(attestation_data_a), attestation_data_a.slot),
            ],
        )


def test_multi_message_aggregate_verify_rejects_mismatched_messages_length(
    key_manager: XmssKeyManager,
) -> None:
    """messages must have the same length as public_keys_per_message."""
    source = Checkpoint(root=make_bytes32(500), slot=Slot(0))
    attestation_args = (Slot(10), 501, 502, source)

    validator_indices = [ValidatorIndex(0), ValidatorIndex(1)]
    part = _sign_and_aggregate(key_manager, validator_indices, attestation_args)
    public_keys = [
        key_manager[validator_index].attestation_keypair.public_key
        for validator_index in validator_indices
    ]

    merged = MultiMessageAggregate.aggregate(
        parts=[part],
        public_keys_per_part=[public_keys],
    )

    with pytest.raises(AggregationError, match="expected 1 message bindings, got 0"):
        merged.verify(
            public_keys_per_message=[public_keys],
            messages=[],
        )
