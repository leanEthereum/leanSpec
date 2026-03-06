"""Tests for Store attestation data pruning."""

from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.forkchoice import GossipSignatureEntry, Store
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import ByteListMiB, Bytes32
from tests.lean_spec.helpers import (
    make_attestation_data,
    make_bytes32,
    make_checkpoint,
    make_mock_signature,
)


def test_prunes_entries_with_target_at_finalized(pruning_store: Store) -> None:
    """Verify entries with target.slot == finalized slot are pruned."""
    store = pruning_store

    # Create attestation data with target.slot == 5
    attestation_data = make_attestation_data(
        slot=Slot(5),
        target_slot=Slot(5),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Set up store with attestation data and finalized slot at 5
    store = store.model_copy(
        update={
            "gossip_signatures": {
                attestation_data: {GossipSignatureEntry(ValidatorIndex(1), make_mock_signature())},
            },
            "latest_finalized": make_checkpoint(root_seed=255, slot=5),
        }
    )

    # Verify data exists before pruning
    assert attestation_data in store.gossip_signatures

    # Prune should remove entries where target.slot <= finalized.slot
    pruned_store = store.prune_stale_attestation_data()

    assert attestation_data not in pruned_store.gossip_signatures


def test_prunes_entries_with_target_before_finalized(pruning_store: Store) -> None:
    """Verify entries with target.slot < finalized slot are pruned."""
    store = pruning_store

    # Create attestation data with target.slot == 3
    attestation_data = make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Set up store with finalized slot at 5 (greater than target.slot)
    store = store.model_copy(
        update={
            "gossip_signatures": {
                attestation_data: {GossipSignatureEntry(ValidatorIndex(1), make_mock_signature())},
            },
            "latest_finalized": make_checkpoint(root_seed=255, slot=5),
        }
    )

    # Verify data exists before pruning
    assert attestation_data in store.gossip_signatures

    # Prune should remove entries where target.slot <= finalized.slot
    pruned_store = store.prune_stale_attestation_data()

    assert attestation_data not in pruned_store.gossip_signatures


def test_keeps_entries_with_target_after_finalized(pruning_store: Store) -> None:
    """Verify entries with target.slot > finalized slot are kept."""
    store = pruning_store

    # Create attestation data with target.slot == 10
    attestation_data = make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=make_bytes32(1),
        source_slot=Slot(5),
        source_root=make_bytes32(2),
    )

    # Set up store with finalized slot at 5 (less than target.slot)
    store = store.model_copy(
        update={
            "gossip_signatures": {
                attestation_data: {GossipSignatureEntry(ValidatorIndex(1), make_mock_signature())},
            },
            "latest_finalized": make_checkpoint(root_seed=255, slot=5),
        }
    )

    # Verify data exists before pruning
    assert attestation_data in store.gossip_signatures

    # Prune should keep entries where target.slot > finalized.slot
    pruned_store = store.prune_stale_attestation_data()

    assert attestation_data in pruned_store.gossip_signatures


def test_prunes_related_structures_together(pruning_store: Store) -> None:
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
    mock_proof = AggregatedSignatureProof(
        participants=AggregationBits.from_validator_indices(
            ValidatorIndices(data=[ValidatorIndex(1)])
        ),
        proof_data=ByteListMiB(data=b""),
    )

    # Set up store with both stale and fresh entries in all structures
    store = store.model_copy(
        update={
            "gossip_signatures": {
                stale_attestation: {GossipSignatureEntry(ValidatorIndex(1), make_mock_signature())},
                fresh_attestation: {GossipSignatureEntry(ValidatorIndex(2), make_mock_signature())},
            },
            "latest_new_aggregated_payloads": {
                stale_attestation: {mock_proof},
                fresh_attestation: {mock_proof},
            },
            "latest_known_aggregated_payloads": {
                stale_attestation: {mock_proof},
                fresh_attestation: {mock_proof},
            },
            "latest_finalized": make_checkpoint(root_seed=255, slot=5),
        }
    )

    # Verify all data exists before pruning
    assert stale_attestation in store.gossip_signatures
    assert stale_attestation in store.latest_new_aggregated_payloads
    assert stale_attestation in store.latest_known_aggregated_payloads
    assert fresh_attestation in store.gossip_signatures
    assert fresh_attestation in store.latest_new_aggregated_payloads
    assert fresh_attestation in store.latest_known_aggregated_payloads

    pruned_store = store.prune_stale_attestation_data()

    # Stale entries should be removed from all structures
    assert stale_attestation not in pruned_store.gossip_signatures
    assert stale_attestation not in pruned_store.latest_new_aggregated_payloads
    assert stale_attestation not in pruned_store.latest_known_aggregated_payloads

    # Fresh entries should be preserved in all structures
    assert fresh_attestation in pruned_store.gossip_signatures
    assert fresh_attestation in pruned_store.latest_new_aggregated_payloads
    assert fresh_attestation in pruned_store.latest_known_aggregated_payloads


def test_handles_empty_gossip_signatures(pruning_store: Store) -> None:
    """Verify pruning works correctly when gossip_signatures is empty."""
    store = pruning_store

    # Ensure store has empty gossip signatures
    assert len(store.gossip_signatures) == 0

    # Pruning should not fail
    pruned_store = store.prune_stale_attestation_data()

    assert len(pruned_store.gossip_signatures) == 0


def test_prunes_multiple_validators_same_attestation_data(pruning_store: Store) -> None:
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
    store = store.model_copy(
        update={
            "gossip_signatures": {
                stale_attestation: {
                    GossipSignatureEntry(ValidatorIndex(1), make_mock_signature()),
                    GossipSignatureEntry(ValidatorIndex(2), make_mock_signature()),
                },
            },
            "latest_finalized": make_checkpoint(root_seed=255, slot=5),
        }
    )

    # Verify data exists before pruning
    assert stale_attestation in store.gossip_signatures
    assert len(store.gossip_signatures[stale_attestation]) == 2

    pruned_store = store.prune_stale_attestation_data()

    # All validators' signatures should be removed (whole entry pruned)
    assert stale_attestation not in pruned_store.gossip_signatures


def test_mixed_stale_and_fresh_entries(pruning_store: Store) -> None:
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

    gossip_sigs = {
        att: {GossipSignatureEntry(ValidatorIndex(i), make_mock_signature())}
        for i, att in enumerate(attestations, start=1)
    }

    # Finalized at slot 5 means slots 1-5 are stale, 6-10 are fresh
    store = store.model_copy(
        update={
            "gossip_signatures": gossip_sigs,
            "latest_finalized": make_checkpoint(root_seed=255, slot=5),
        }
    )

    # Verify all data exists before pruning
    for att in attestations:
        assert att in store.gossip_signatures

    pruned_store = store.prune_stale_attestation_data()

    # Entries with target.slot <= 5 should be pruned (slots 1-5)
    for att in attestations[:5]:
        assert att not in pruned_store.gossip_signatures

    # Entries with target.slot > 5 should be kept (slots 6-10)
    for att in attestations[5:]:
        assert att in pruned_store.gossip_signatures
