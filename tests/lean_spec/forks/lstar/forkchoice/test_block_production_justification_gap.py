"""
Block production closes the justification gap on a canonical head that lags.

The scenario builds a fork tree where one branch advances the store's justified
checkpoint past the level that the canonical head's chain has proven. The
fixed-point attestation loop inside build_block picks up the gap-closing
attestation from the gossip pool and produces a block whose post-state
catches up to the store.
"""

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
    """
    Closing the justification gap via the fixed-point attestation loop.

    Fork tree (labels are block names; slot numbers shown in parentheses)::

                               block_4(4) -- block_5(5)  <-- head
                              /
        genesis -- 1 -- 2 -- 3
                              \
                               block_6(6)

    Setup:

    - block_4 carries 6 of 8 attestations targeting block_1, justifying block_1.
    - block_5 carries 2 attestations (validators 6, 7) with head=block_4. These
      give block_5's subtree fork-choice weight against block_6.
    - block_6 (sibling of block_4) carries 6 of 8 attestations targeting block_2.
      Block_6 alone moves the store's latest_justified to block_2.

    After all six blocks are processed:

    - store.latest_justified points at block_2 (slot 2)
    - fork choice still picks block_5 as the head:
        validators 0-5 vote head=block_2 (a common ancestor)
        validators 6-7 vote head=block_4 (in block_5's subtree)
        weight on block_3's child block_4 is 2; weight on block_6 is 0

    Proposing at slot 7 builds on block_5, whose post-state has
    latest_justified=block_1. The gossip pool holds block_6's attestation
    (source=genesis, target=block_2). The fixed-point loop accepts that
    attestation because genesis is justified on block_5's chain and
    block_2 is on the common ancestor segment, so the produced block's
    post-state catches up to the store's justified checkpoint.
    """
    store = keyed_store
    block_registry: dict[str, Block] = {"genesis": keyed_genesis_block}

    def add_block(block_spec: BlockSpec) -> None:
        nonlocal store
        signed_block = block_spec.build_signed_block_with_store(
            store, block_registry, key_manager, "test"
        )
        if block_spec.label is not None:
            block_registry[block_spec.label] = signed_block.block
        # Re-align store time with the block's slot before processing.
        # build_signed_block_with_store already ticks forward; this second tick
        # is idempotent and mirrors the fork-choice spec-test fixture.
        target_interval = Interval.from_slot(signed_block.block.slot)
        store, _ = spec.on_tick(store, target_interval, has_proposal=True, is_aggregator=True)
        store = spec.on_block(store, signed_block)

    # Linear chain through block_3.
    add_block(BlockSpec(slot=Slot(1), label="block_1"))
    add_block(BlockSpec(slot=Slot(2), label="block_2"))
    add_block(BlockSpec(slot=Slot(3), label="block_3"))

    # block_4: 6 of 8 validators attest target=block_1, justifying block_1.
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
    assert store.latest_justified.slot == Slot(1)
    assert store.latest_justified.root == hash_tree_root(block_registry["block_1"])

    # block_5: validators 6, 7 attest target=block_4 with head=block_4.
    # The head vote pulls fork-choice weight into block_5's subtree without
    # advancing justification.
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
    assert store.latest_justified.slot == Slot(1)

    # block_6: sibling of block_4 (parent=block_3). 6 of 8 validators attest
    # target=block_2 with source=genesis. After processing, the store's
    # latest_justified advances to block_2.
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

    # Sanity: block_5 is the head and the store's justified is block_2.
    # Validators 0-5's latest vote is for head=block_2 (common ancestor).
    # Validators 6, 7's latest vote is for head=block_4 (in block_5's subtree).
    # block_4's subtree carries weight 2; block_6's subtree carries weight 0.
    assert store.head == hash_tree_root(block_registry["block_5"])
    assert store.latest_justified.slot == Slot(2)
    assert store.latest_justified.root == hash_tree_root(block_registry["block_2"])

    # block_6's body attestation justifying block_2 is merged into the
    # store's known aggregated payload pool. Its source is genesis (the
    # latest_justified at block_6's parent, block_3), so the filter must
    # match on source-slot-justified, not full Checkpoint equality, to be
    # able to reuse it from block_5's chain.
    genesis_root = hash_tree_root(keyed_genesis_block)
    block_2_root = hash_tree_root(block_registry["block_2"])
    block_6_target_atts = [
        att
        for att in store.latest_known_aggregated_payloads
        if att.target.root == block_2_root and att.target.slot == Slot(2)
    ]
    assert len(block_6_target_atts) == 1
    assert block_6_target_atts[0].source == Checkpoint(root=genesis_root, slot=Slot(0))
    assert block_6_target_atts[0].slot == Slot(6)

    # Propose at slot 7 on top of block_5 (the head). The fixed-point loop
    # picks up block_6's attestation (source=genesis matches the chain at
    # slot 0) and advances the produced block's justified checkpoint to
    # block_2 to match the store.
    new_store, new_block, _ = spec.produce_block_with_signatures(store, Slot(7), ValidatorIndex(7))

    # The store's justified checkpoint stays at block_2; the new block
    # closes the gap rather than leaving the producer behind.
    block_2_checkpoint = Checkpoint(root=block_2_root, slot=Slot(2))
    assert new_store.latest_justified == block_2_checkpoint

    # The new block's post-state caught up to the store's justified checkpoint.
    new_block_root = hash_tree_root(new_block)
    assert new_block.parent_root == hash_tree_root(block_registry["block_5"])
    assert new_store.states[new_block_root].latest_justified == block_2_checkpoint

    # The produced block must include the attestation that justifies block_2.
    body_targets = [att.data.target for att in new_block.body.attestations]
    assert block_2_checkpoint in body_targets
