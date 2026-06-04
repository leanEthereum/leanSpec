"""Tests for Store attestation data pruning."""

from lean_spec.spec.forks import AggregationBits, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import AttestationSignatureEntry, Store
from lean_spec.spec.forks.lstar.containers import AttestationData, SingleMessageAggregate
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ByteList512KiB, Bytes32
from tests.lean_spec.helpers import (
    make_attestation_data,
    make_bytes32,
    make_checkpoint,
    make_mock_signature,
)


def test_prunes_entries_with_head_at_finalized(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify entries with head.slot == finalized slot are pruned."""
    store = pruning_store

    # Create attestation data with head.slot == 5
    attestation_data = make_attestation_data(
        slot=Slot(5),
        target_slot=Slot(5),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Set up store with attestation data and finalized slot at 5
    store.attestation_signatures = {
        attestation_data: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert attestation_data in store.attestation_signatures

    # Prune should remove entries where head.slot <= finalized.slot
    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data not in pruned_store.attestation_signatures


def test_prunes_entries_with_head_before_finalized(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify entries with head.slot < finalized slot are pruned."""
    store = pruning_store

    # Create attestation data with head.slot == 3
    attestation_data = make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Set up store with finalized slot at 5 (greater than head.slot)
    store.attestation_signatures = {
        attestation_data: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert attestation_data in store.attestation_signatures

    # Prune should remove entries where head.slot <= finalized.slot
    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data not in pruned_store.attestation_signatures


def test_keeps_entries_with_head_after_finalized(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify entries with head.slot > finalized slot are kept."""
    store = pruning_store

    # Create attestation data with head.slot == 10
    attestation_data = make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=make_bytes32(1),
        source_slot=Slot(5),
        source_root=make_bytes32(2),
    )

    # Set up store with finalized slot at 5 (less than head.slot)
    store.attestation_signatures = {
        attestation_data: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert attestation_data in store.attestation_signatures

    # Prune should keep entries where head.slot > finalized.slot
    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data in pruned_store.attestation_signatures


def test_keeps_finalized_target_when_head_after_finalized(
    spec: LstarSpec, pruning_store: Store
) -> None:
    """A finalized target is still useful while the attested head is unfinalized."""
    store = pruning_store
    finalized = make_checkpoint(root_seed=1, slot=5)
    head = make_checkpoint(root_seed=2, slot=6)
    attestation_data = AttestationData(
        slot=Slot(6),
        head=head,
        target=finalized,
        source=make_checkpoint(root_seed=0, slot=0),
    )

    placeholder = ByteList512KiB(data=b"")
    mock_proof = SingleMessageAggregate(
        participants=AggregationBits.from_indices([ValidatorIndex(1)]),
        proof=placeholder,
    )
    signature = AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())

    store.attestation_signatures = {attestation_data: {signature}}
    store.latest_new_aggregated_payloads = {attestation_data: {mock_proof}}
    store.latest_known_aggregated_payloads = {attestation_data: {mock_proof}}
    store.latest_finalized = finalized

    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data in pruned_store.attestation_signatures
    assert attestation_data in pruned_store.latest_new_aggregated_payloads
    assert attestation_data in pruned_store.latest_known_aggregated_payloads


def test_prunes_related_structures_together(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify all three data structures are pruned atomically."""
    store = pruning_store

    # Create stale attestation data
    stale_attestation = make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Create fresh attestation data
    fresh_attestation = make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=make_bytes32(2),
        source_slot=Slot(5),
        source_root=make_bytes32(255),
    )

    # Create mock aggregated proof (empty proof data for testing)
    placeholder = ByteList512KiB(data=b"")
    mock_proof = SingleMessageAggregate(
        participants=AggregationBits.from_indices([ValidatorIndex(1)]),
        proof=placeholder,
    )

    # Set up store with both stale and fresh entries in all structures
    store.attestation_signatures = {
        stale_attestation: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
        fresh_attestation: {AttestationSignatureEntry(ValidatorIndex(2), make_mock_signature())},
    }
    store.latest_new_aggregated_payloads = {
        stale_attestation: {mock_proof},
        fresh_attestation: {mock_proof},
    }
    store.latest_known_aggregated_payloads = {
        stale_attestation: {mock_proof},
        fresh_attestation: {mock_proof},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify all data exists before pruning
    assert stale_attestation in store.attestation_signatures
    assert stale_attestation in store.latest_new_aggregated_payloads
    assert stale_attestation in store.latest_known_aggregated_payloads
    assert fresh_attestation in store.attestation_signatures
    assert fresh_attestation in store.latest_new_aggregated_payloads
    assert fresh_attestation in store.latest_known_aggregated_payloads

    pruned_store = spec.prune_stale_attestation_data(store)

    # Stale entries should be removed from all structures
    assert stale_attestation not in pruned_store.attestation_signatures
    assert stale_attestation not in pruned_store.latest_new_aggregated_payloads
    assert stale_attestation not in pruned_store.latest_known_aggregated_payloads

    # Fresh entries should be preserved in all structures
    assert fresh_attestation in pruned_store.attestation_signatures
    assert fresh_attestation in pruned_store.latest_new_aggregated_payloads
    assert fresh_attestation in pruned_store.latest_known_aggregated_payloads


def test_handles_empty_attestation_signatures(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify pruning works correctly when attestation_signatures is empty."""
    store = pruning_store

    # Ensure store has empty gossip signatures
    assert len(store.attestation_signatures) == 0

    # Pruning should not fail
    pruned_store = spec.prune_stale_attestation_data(store)

    assert len(pruned_store.attestation_signatures) == 0


def test_prunes_multiple_validators_same_attestation_data(
    spec: LstarSpec, pruning_store: Store
) -> None:
    """Verify pruning removes entries for multiple validators with same attestation data."""
    store = pruning_store

    # Create stale attestation data
    stale_attestation = make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Multiple validators signed the same attestation data
    store.attestation_signatures = {
        stale_attestation: {
            AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature()),
            AttestationSignatureEntry(ValidatorIndex(2), make_mock_signature()),
        },
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert stale_attestation in store.attestation_signatures
    assert len(store.attestation_signatures[stale_attestation]) == 2

    pruned_store = spec.prune_stale_attestation_data(store)

    # All validators' signatures should be removed (whole entry pruned)
    assert stale_attestation not in pruned_store.attestation_signatures


def test_mixed_stale_and_fresh_entries(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify correct pruning behavior with a mix of stale and fresh entries."""
    store = pruning_store

    # Create multiple attestations at different slots
    attestations = [
        make_attestation_data(
            slot=Slot(i),
            target_slot=Slot(i),
            target_root=Bytes32(bytes([i]) * 32),
            source_slot=Slot(0),
            source_root=Bytes32.zero(),
        )
        for i in range(1, 11)  # Slots 1-10
    ]

    gossip_signatures = {
        attestation: {AttestationSignatureEntry(ValidatorIndex(i), make_mock_signature())}
        for i, attestation in enumerate(attestations, start=1)
    }

    # Finalized at slot 5 means slots 1-5 are stale, 6-10 are fresh
    store.attestation_signatures = gossip_signatures
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify all data exists before pruning
    for attestation in attestations:
        assert attestation in store.attestation_signatures

    pruned_store = spec.prune_stale_attestation_data(store)

    # Entries with head.slot <= 5 should be pruned (slots 1-5)
    for attestation in attestations[:5]:
        assert attestation not in pruned_store.attestation_signatures

    # Entries with head.slot > 5 should be kept (slots 6-10)
    for attestation in attestations[5:]:
        assert attestation in pruned_store.attestation_signatures
