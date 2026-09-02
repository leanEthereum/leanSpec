"""Canonical store snapshot emitted after every fork choice step."""

from ssz import hash_tree_root

from lean_spec.base import StrictBaseModel
from lean_spec.spec.forks import Interval
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    Checkpoint,
    SingleMessageAggregate,
    Store,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz_types import Bytes32


class BlockWeightEntry(StrictBaseModel):
    """Fork-choice weight of one block above the finalized slot."""

    root: Bytes32
    """Block root the weight accrues to."""

    weight: int
    """Accumulated attestation weight."""


class AttestationPoolEntry(StrictBaseModel):
    """
    Validator coverage of one attestation data in the raw signature pool.

    Signature bytes are excluded since coverage is the consensus-relevant observable.
    """

    data_root: Bytes32
    """Hash tree root of the attestation data."""

    validator_indices: list[int]
    """Validators whose signatures the pool holds, ascending."""


class AggregatedPoolEntry(StrictBaseModel):
    """
    Participant coverage of one attestation data in an aggregated payload pool.

    Proof bytes are excluded since the randomized prover differs between identical fills.
    """

    data_root: Bytes32
    """Hash tree root of the attestation data."""

    participant_sets: list[list[int]]
    """One ascending validator list per payload, sorted lexicographically."""


class StoreSnapshot(StrictBaseModel):
    """
    Canonical store observables captured after a fork choice step.

    Recorded after every step, including rejected ones, so clients reproduce every field.
    """

    time: Interval
    """Store time in intervals since genesis."""

    head_root: Bytes32
    """Root of the canonical chain head block."""

    safe_target_root: Bytes32
    """Root of the current safe attestation target."""

    latest_justified: Checkpoint
    """Highest slot justified checkpoint known to the store."""

    latest_finalized: Checkpoint
    """Highest slot finalized checkpoint known to the store."""

    block_roots: list[Bytes32]
    """Every block root the store retains, ascending.

    Full membership makes pruning observable, so an over- or under-pruning client fails here.
    """

    block_weights: list[BlockWeightEntry]
    """Fork-choice weight per block above the finalized slot, ascending by root.

    Weights drive head selection and must match exactly, even where two clients agree on the head.
    """

    attestation_signatures: list[AttestationPoolEntry]
    """Raw signature pool coverage, ascending by data root."""

    new_aggregated_payloads: list[AggregatedPoolEntry]
    """Pending aggregated payload pool, ascending by data root.

    These payloads do not contribute to fork choice yet, but their migration timing is observable.
    """

    known_aggregated_payloads: list[AggregatedPoolEntry]
    """Processed aggregated payload pool, ascending by data root."""

    @classmethod
    def from_store(cls, store: Store) -> "StoreSnapshot":
        """Capture the canonical observables of a store."""
        finalized_slot = store.latest_finalized.slot
        weights = LstarSpec().compute_block_weights(store)

        return cls(
            time=store.time,
            head_root=store.head,
            safe_target_root=store.safe_target,
            latest_justified=store.latest_justified,
            latest_finalized=store.latest_finalized,
            block_roots=sorted(store.blocks),
            block_weights=[
                BlockWeightEntry(root=root, weight=weights.get(root, 0))
                for root in sorted(store.blocks)
                if store.blocks[root].slot > finalized_slot
            ],
            attestation_signatures=[
                AttestationPoolEntry(
                    data_root=data_root,
                    validator_indices=sorted(
                        int(entry.validator_index) for entry in signature_entries
                    ),
                )
                for data_root, signature_entries in sorted(
                    (
                        (hash_tree_root(attestation_data), signature_entries)
                        for attestation_data, signature_entries in (
                            store.attestation_signatures.items()
                        )
                    ),
                    key=lambda entry: entry[0],
                )
            ],
            new_aggregated_payloads=_aggregated_pool_entries(store.latest_new_aggregated_payloads),
            known_aggregated_payloads=_aggregated_pool_entries(
                store.latest_known_aggregated_payloads
            ),
        )


def _aggregated_pool_entries(
    pool: dict[AttestationData, set[SingleMessageAggregate]],
) -> list[AggregatedPoolEntry]:
    """Convert an aggregated payload pool into sorted coverage entries."""
    return [
        AggregatedPoolEntry(
            data_root=data_root,
            participant_sets=sorted(
                sorted(int(index) for index in payload.participants.to_validator_indices())
                for payload in payloads
            ),
        )
        for data_root, payloads in sorted(
            (
                (hash_tree_root(attestation_data), payloads)
                for attestation_data, payloads in pool.items()
            ),
            key=lambda entry: entry[0],
        )
    ]
