"""Tests for post-block Type-1 deconstruction in SyncService.

Exercises `SyncService._deconstruct_block_into_store`: for every processed
block (gossip, head-sync, or backfilled), the merged Type-2 proof is split
into per-attestation Type-1 proofs, merged with locally held partials, and
written into the pending pool, replacing the partials it subsumes.

Deconstruction only runs for an attestation when:

- its target is ahead of the store's justified checkpoint, so the proof
  can still help move justification, and
- it adds at least one participant the node does not already hold.

Only the decision/gate paths are exercised here. The split itself
(`split_type_2_by_msg`) is implemented and works in the production prover,
but the upstream `lean_multisig` `test-config` build aborts it with an
in-circuit assertion (the reduced XMSS dimensions are inconsistent with
the aggregation program's split branch). It is not a leanSpec defect and
cannot be fixed here, so the split-extract-merge body is verified under a
production prover, not in this test-mode suite.
"""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.node.networking import PeerId
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData
from lean_spec.spec.forks.lstar.spec import LstarSpec
from tests.lean_spec.helpers import (
    create_mock_sync_service,
    make_aggregated_proof,
    make_signed_block_from_store,
    make_store,
)

# Round-robin proposer is slot % num_validators with four validators.
NUM_VALIDATORS = 4
CHAIN_SLOT = Slot(1)
CHAIN_PROPOSER = ValidatorIndex(1)
BLOCK_SLOT = Slot(2)
BLOCK_PROPOSER = ValidatorIndex(2)


def _setup(
    key_manager: XmssKeyManager,
    *,
    block_participants: list[ValidatorIndex],
):
    """Build a two-block chain and a signed block carrying an attestation.

    The chain block sits at slot 1. The returned signed block sits at slot
    2 and carries one attestation whose target is the slot-1 block, ahead
    of the still-genesis justified checkpoint. The returned store holds the
    slot-1 block and its state (the parent state the Type-2 pubkey layout
    is resolved against) with the justified checkpoint still at genesis.
    """
    spec = LstarSpec()
    base_store = make_store(
        num_validators=NUM_VALIDATORS, validator_id=ValidatorIndex(0), key_manager=key_manager
    )

    consumer_store, chain_block = make_signed_block_from_store(
        base_store, key_manager, CHAIN_SLOT, CHAIN_PROPOSER
    )
    chain_store = spec.on_block(consumer_store, chain_block)
    chain_root = hash_tree_root(chain_block.block)

    # Target the slot-1 block; source stays at the genesis justified
    # checkpoint so the builder accepts the attestation.
    attestation_data = AttestationData(
        slot=BLOCK_SLOT,
        head=Checkpoint(root=chain_root, slot=CHAIN_SLOT),
        target=Checkpoint(root=chain_root, slot=CHAIN_SLOT),
        source=chain_store.latest_justified,
    )

    block_proof = make_aggregated_proof(key_manager, block_participants, attestation_data)
    producer_store = chain_store.model_copy(
        update={"latest_known_aggregated_payloads": {attestation_data: {block_proof}}}
    )
    _, signed_block = make_signed_block_from_store(
        producer_store, key_manager, BLOCK_SLOT, BLOCK_PROPOSER
    )
    return chain_store, signed_block, attestation_data


def _service(peer_id: PeerId):
    """A SyncService usable to invoke the deconstruction core directly."""
    return create_mock_sync_service(peer_id)


def test_skips_when_target_not_ahead_of_justified(
    peer_id: PeerId, key_manager: XmssKeyManager
) -> None:
    """Target at or behind the justified checkpoint -> no aggregates.

    The block's attestation cannot move justification, so the expensive
    split is never attempted and the store is returned unchanged.
    """
    chain_store, signed_block, attestation_data = _setup(
        key_manager, block_participants=[ValidatorIndex(1), ValidatorIndex(2)]
    )
    # Justified now sits at the attestation's target slot.
    store = chain_store.model_copy(update={"latest_justified": attestation_data.target})
    service = _service(peer_id)

    new_store, aggregates = service._deconstruct_block_into_store(store, signed_block)

    assert aggregates == []
    assert new_store is store


def test_skips_when_block_adds_no_new_validators(
    peer_id: PeerId, key_manager: XmssKeyManager
) -> None:
    """Block participants are a subset of the local union -> no aggregates.

    The target is ahead of justified, so the only thing stopping the split
    is that the block adds no new participant. The store is unchanged.
    """
    block_participants = [ValidatorIndex(1), ValidatorIndex(2)]
    chain_store, signed_block, attestation_data = _setup(
        key_manager, block_participants=block_participants
    )

    local_partial = make_aggregated_proof(
        key_manager,
        [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        attestation_data,
    )
    store = chain_store.model_copy(
        update={"latest_new_aggregated_payloads": {attestation_data: {local_partial}}}
    )
    service = _service(peer_id)

    new_store, aggregates = service._deconstruct_block_into_store(store, signed_block)

    assert aggregates == []
    assert new_store is store


def test_noop_when_parent_state_missing(peer_id: PeerId, key_manager: XmssKeyManager) -> None:
    """Without the parent state the pubkey layout cannot be resolved -> no-op."""
    chain_store, signed_block, _ = _setup(
        key_manager, block_participants=[ValidatorIndex(1), ValidatorIndex(2)]
    )
    store = chain_store.model_copy(update={"states": {}})
    service = _service(peer_id)

    new_store, aggregates = service._deconstruct_block_into_store(store, signed_block)

    assert aggregates == []
    assert new_store is store
