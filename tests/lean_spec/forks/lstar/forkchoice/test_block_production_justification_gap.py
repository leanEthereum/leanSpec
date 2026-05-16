"""Block production closes the justification gap when the canonical head lags."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_types.aggregated_attestation_spec import AggregatedAttestationSpec
from consensus_testing.test_types.block_spec import BlockSpec

from lean_spec.forks.lstar import Store
from lean_spec.forks.lstar.containers import Block
from lean_spec.forks.lstar.spec import LstarSpec
from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Checkpoint, Slot, ValidatorIndex


def test_produce_block_on_head_with_lagging_justification(
    spec: LstarSpec,
    keyed_store: Store,
    keyed_genesis_block: Block,
    key_manager: XmssKeyManager,
) -> None:
    r"""Producer on a lagging head pulls a sibling's attestation to catch up.

    Fork tree::

                              block_4(4) -- block_5(5)  <-- head
                             /
        genesis -- 1 -- 2 -- 3
                             \
                              block_6(6)

    The head branch only justifies block_1.
    The sibling branch justifies block_2 and pushes the store ahead of the head.
    Producing on top of the head must reuse the sibling's attestation to close the gap.
    """
    store = keyed_store
    block_registry: dict[str, Block] = {"genesis": keyed_genesis_block}

    def add_block(block_spec: BlockSpec) -> None:
        """Build the spec'd block on the current store and apply it."""
        nonlocal store
        signed_block, store = block_spec.build_signed_block_with_store(
            store, block_registry, key_manager, "test"
        )
        if block_spec.label is not None:
            block_registry[block_spec.label] = signed_block.block
        # The block builder helper ticks a local store copy and discards it.
        # The outer store therefore still sits at genesis time.
        # Without this tick, the block is rejected as too far in the future.
        target_interval = Interval.from_slot(signed_block.block.slot)
        store, _ = spec.on_tick(store, target_interval, has_proposal=True, is_aggregator=True)
        store = spec.on_block(store, signed_block)

    # Phase 1: linear chain genesis -> block_1 -> block_2 -> block_3.
    add_block(BlockSpec(slot=Slot(1), label="block_1"))
    add_block(BlockSpec(slot=Slot(2), label="block_2"))
    add_block(BlockSpec(slot=Slot(3), label="block_3"))

    # Phase 2a: block_4 carries 6/8 votes for target=block_1.
    # Crosses the 2/3 threshold, so block_1 becomes justified.
    add_block(
        BlockSpec(
            slot=Slot(4),
            parent_label="block_3",
            label="block_4",
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(i) for i in range(6)],
                    slot=Slot(4),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                ),
            ],
        )
    )
    block_1_root = hash_tree_root(block_registry["block_1"])
    assert store.latest_justified == Checkpoint(root=block_1_root, slot=Slot(1))

    # Phase 2b: block_5 carries 2/8 head votes for block_4.
    # Below the 2/3 threshold, so justification does not advance.
    # The votes pull fork-choice weight into block_5's subtree.
    add_block(
        BlockSpec(
            slot=Slot(5),
            parent_label="block_4",
            label="block_5",
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(6), ValidatorIndex(7)],
                    slot=Slot(5),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                ),
            ],
        )
    )
    assert store.latest_justified == Checkpoint(root=block_1_root, slot=Slot(1))

    # Phase 3: block_6 (sibling of block_4) carries 6/8 votes for target=block_2.
    # The store learns block_2 is justified.
    # block_5's chain still has latest_justified = block_1: the divergence.
    add_block(
        BlockSpec(
            slot=Slot(6),
            parent_label="block_3",
            label="block_6",
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(i) for i in range(6)],
                    slot=Slot(6),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ],
        )
    )

    # Pre-condition: head is block_5, but the store's justified is ahead at block_2.
    # Validators 0-5 vote head=block_2 (a common ancestor); validators 6-7 vote head=block_4.
    # block_5's subtree wins fork choice with weight 2 vs 0.
    genesis_root = hash_tree_root(keyed_genesis_block)
    block_2_root = hash_tree_root(block_registry["block_2"])
    block_2_checkpoint = Checkpoint(root=block_2_root, slot=Slot(2))
    assert store.head == hash_tree_root(block_registry["block_5"])
    assert store.latest_justified == block_2_checkpoint

    # The gap-closing attestation is in the pool: source=genesis, target=block_2.
    # Its source is NOT block_5's latest_justified (which is block_1).
    # The filter must accept it on source-slot-justified, not full-Checkpoint equality.
    block_6_target_atts = [
        att for att in store.latest_known_aggregated_payloads if att.target == block_2_checkpoint
    ]
    assert len(block_6_target_atts) == 1
    assert block_6_target_atts[0].source == Checkpoint(root=genesis_root, slot=Slot(0))
    assert block_6_target_atts[0].slot == Slot(6)

    # Propose at slot 7 on top of block_5.
    # The block builder picks up the gap-closing attestation and advances justification.
    new_store, new_block, _ = spec.produce_block_with_signatures(store, Slot(7), ValidatorIndex(7))

    # The produced block's post-state caught up to the store's justified checkpoint.
    # Its body carries the attestation that closed the gap.
    new_block_root = hash_tree_root(new_block)
    body_targets = [att.data.target for att in new_block.body.attestations]
    assert new_store.latest_justified == block_2_checkpoint
    assert new_block.parent_root == hash_tree_root(block_registry["block_5"])
    assert new_store.states[new_block_root].latest_justified == block_2_checkpoint
    assert block_2_checkpoint in body_targets
