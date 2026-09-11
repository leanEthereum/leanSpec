"""Tests for the attestation duty in `validator_duties.py`."""

from ssz import hash_tree_root

from lean_spec.spec.forks import Slot
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import Block, Checkpoint
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz_types import Bytes32


def _extend(store: Store, slots: list[int]) -> tuple[Store, dict[int, Bytes32]]:
    """
    Append one block per slot on top of the store's head, in order, without state transitions.

    The blocks carry the genesis body and state root: the target walk only reads slots and
    parent links, so that is all the test needs. Returns the store and the root of each slot.
    """
    blocks = dict(store.blocks)
    parent_root = store.head
    parent = blocks[parent_root]
    roots: dict[int, Bytes32] = {}
    for slot in slots:
        block = Block(
            slot=Slot(slot),
            proposer_index=parent.proposer_index,
            parent_root=parent_root,
            state_root=parent.state_root,
            body=parent.body,
        )
        parent_root = hash_tree_root(block)
        blocks[parent_root] = block
        parent = block
        roots[slot] = parent_root
    return store.model_copy(update={"blocks": blocks, "head": parent_root}), roots


def test_target_is_raised_to_the_source_when_the_walk_lands_behind_it(
    base_store: Store, spec: LstarSpec
) -> None:
    """
    The attestation target never falls behind the head chain's justified checkpoint.

    The head chain is 62 -> 59 -> 51 -> 50 -> 49 -> 45 -> 42 (a shape seen on a three-node
    devnet), finalized at 42 with the head's justified at 49. The lookback walk from 62
    takes three steps to 50. Neither 50 nor 49 is justifiable after 42 (deltas 8 and 7),
    so the justifiability walk continues to 45: behind the source at 49. The duty then votes
    for the justified checkpoint itself instead of producing a vote no peer would admit.
    """
    store, roots = _extend(base_store, [42, 45, 49, 50, 51, 59, 62])
    finalized = Checkpoint(root=roots[42], slot=Slot(42))
    justified = Checkpoint(root=roots[49], slot=Slot(49))
    head_state = store.states[base_store.head].model_copy(
        update={"latest_justified": justified, "latest_finalized": finalized}
    )
    store = store.model_copy(
        update={
            "states": {**store.states, store.head: head_state},
            "safe_target": roots[42],
            "latest_justified": justified,
            "latest_finalized": finalized,
        }
    )

    # The walk itself still selects 45: that part of the spec is unchanged.
    assert spec.get_attestation_target(store) == Checkpoint(root=roots[45], slot=Slot(45))

    data = spec.produce_attestation_data(store, Slot(63))

    assert data.source == justified
    assert data.target == justified
    assert data.head == Checkpoint(root=roots[62], slot=Slot(62))


def test_target_is_kept_when_the_walk_stays_at_or_after_the_source(
    base_store: Store, spec: LstarSpec
) -> None:
    """
    A target at or after the source is left exactly as the walk selected it.

    Same chain, but the head's justified checkpoint sits at 45: the walk's own answer.
    """
    store, roots = _extend(base_store, [42, 45, 49, 50, 51, 59, 62])
    finalized = Checkpoint(root=roots[42], slot=Slot(42))
    justified = Checkpoint(root=roots[45], slot=Slot(45))
    head_state = store.states[base_store.head].model_copy(
        update={"latest_justified": justified, "latest_finalized": finalized}
    )
    store = store.model_copy(
        update={
            "states": {**store.states, store.head: head_state},
            "safe_target": roots[42],
            "latest_justified": justified,
            "latest_finalized": finalized,
        }
    )

    data = spec.produce_attestation_data(store, Slot(63))

    assert data.source == justified
    assert data.target == Checkpoint(root=roots[45], slot=Slot(45))
