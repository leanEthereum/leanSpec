"""Tests for post-block Type-1 extraction and re-aggregation in SyncService.

Exercises the decision/guard logic of
`SyncService._maybe_publish_reaggregated_attestations_from_block`: an
aggregator that imports a block extracts each attestation's Type-1 proof out
of the merged Type-2 proof, merges it with locally held partial aggregates
for the same data, and gossips the combined Type-1.

These tests cover only the paths reachable without a Type-2 split. The split
primitive (`split_type_2_by_msg`) is unsupported by the test-mode prover in
the current `lean_multisig_py` build, so the proof-extraction path is not
exercised here.
"""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.forks.lstar.containers import SignedAggregatedAttestation
from lean_spec.forks.lstar.spec import LstarSpec
from lean_spec.subspecs.networking import PeerId
from lean_spec.types import Slot, ValidatorIndex
from tests.lean_spec.helpers import (
    create_mock_sync_service,
    make_aggregated_proof,
    make_signed_block_from_store,
    make_store,
)

ATTESTATION_SLOT = Slot(1)
PROPOSER_INDEX = ValidatorIndex(1)


def _setup(
    key_manager: XmssKeyManager,
    *,
    block_participants: list[ValidatorIndex],
):
    """Build a genesis store and a signed block carrying an aggregated attestation.

    The block body holds one attestation for ``attestation_data`` whose
    participant bits are ``block_participants``. The returned store is genesis
    (it holds the parent state needed to resolve the Type-2 pubkey layout).
    """
    spec = LstarSpec()
    base_store = make_store(
        num_validators=4, validator_id=ValidatorIndex(0), key_manager=key_manager
    )
    attestation_data = spec.produce_attestation_data(base_store, ATTESTATION_SLOT)

    block_proof = make_aggregated_proof(key_manager, block_participants, attestation_data)
    producer_store = base_store.model_copy(
        update={"latest_known_aggregated_payloads": {attestation_data: {block_proof}}}
    )
    _, signed_block = make_signed_block_from_store(
        producer_store, key_manager, ATTESTATION_SLOT, PROPOSER_INDEX
    )
    return base_store, signed_block, attestation_data


def _aggregator_service(peer_id: PeerId, store):
    """A capturing aggregator SyncService wrapping the given real store."""
    service = create_mock_sync_service(peer_id)
    service.store = store
    service.is_aggregator = True
    published: list[SignedAggregatedAttestation] = []

    async def capture(agg: SignedAggregatedAttestation) -> None:
        published.append(agg)

    service.set_publish_agg_fn(capture)
    return service, published


async def test_skips_when_block_adds_no_new_validators(
    peer_id: PeerId, key_manager: XmssKeyManager
) -> None:
    """Block participants are a subset of the local union -> nothing published.

    The trigger gate rejects the block before any Type-2 split is attempted.
    """
    block_participants = [ValidatorIndex(1), ValidatorIndex(2)]
    base_store, signed_block, attestation_data = _setup(
        key_manager, block_participants=block_participants
    )

    local_partial = make_aggregated_proof(
        key_manager,
        [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        attestation_data,
    )
    store = base_store.model_copy(
        update={"latest_new_aggregated_payloads": {attestation_data: {local_partial}}}
    )
    service, published = _aggregator_service(peer_id, store)

    await service._maybe_publish_reaggregated_attestations_from_block(signed_block)

    assert published == []


async def test_noop_when_not_a_validator(peer_id: PeerId, key_manager: XmssKeyManager) -> None:
    """A node with no validator identity never re-aggregates or publishes.

    The gate is the absence of a validator id, not the aggregator role.
    """
    base_store, signed_block, _ = _setup(
        key_manager, block_participants=[ValidatorIndex(1), ValidatorIndex(2)]
    )
    store = base_store.model_copy(update={"validator_id": None})
    service, published = _aggregator_service(peer_id, store)

    await service._maybe_publish_reaggregated_attestations_from_block(signed_block)

    assert published == []


async def test_noop_when_parent_state_missing(peer_id: PeerId, key_manager: XmssKeyManager) -> None:
    """Without the parent state the pubkey layout cannot be resolved -> no-op."""
    base_store, signed_block, _ = _setup(
        key_manager, block_participants=[ValidatorIndex(1), ValidatorIndex(2)]
    )
    store = base_store.model_copy(update={"states": {}})
    service, published = _aggregator_service(peer_id, store)

    await service._maybe_publish_reaggregated_attestations_from_block(signed_block)

    assert published == []
