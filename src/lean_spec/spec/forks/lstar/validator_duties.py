"""Lstar fork — validator duties: proposal head and production."""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.lstar.config import (
    JUSTIFICATION_LOOKBACK_SLOTS,
)
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    Block,
    Checkpoint,
    SingleMessageAggregate,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.ssz import Bytes32, Uint64

from ._contract import LstarSpecContract, LstarStore
from .interval import Interval


class ValidatorDutiesMixin(LstarSpecContract):
    """Validator duties for the lstar fork."""

    def get_proposal_head(self, store: LstarStore, slot: Slot) -> tuple[LstarStore, Bytes32]:
        """Get the head for block proposal at given slot.

        Ensures store is up-to-date and processes any pending attestations
        before returning the canonical head. This guarantees the proposer
        builds on the most recent view of the chain.
        """
        # Advance time to this slot's first interval
        target_interval = Interval.from_slot(slot)
        store, _ = self.on_tick(store, target_interval, True)

        # Process any pending attestations before proposal
        store = self.accept_new_attestations(store)

        return store, store.head

    def get_attestation_target(self, store: LstarStore) -> Checkpoint:
        """Calculate target checkpoint for validator attestations.

        Determines appropriate attestation target based on head, safe target,
        and finalization constraints. The algorithm balances between advancing
        the chain head and maintaining safety guarantees.

        The walk starts at the head and goes backward (up to
        ``JUSTIFICATION_LOOKBACK_SLOTS`` steps) until both the safe-target
        bound and the justifiability rules of the slot are satisfied.
        """
        # Start from current head
        target_block_root = store.head

        # Walk back toward safe target (up to `JUSTIFICATION_LOOKBACK_SLOTS` steps)
        #
        # This ensures the target doesn't advance too far ahead of safe target,
        # providing a balance between liveness and safety.
        for _ in range(int(JUSTIFICATION_LOOKBACK_SLOTS)):
            if store.blocks[target_block_root].slot > store.blocks[store.safe_target].slot:
                target_block_root = store.blocks[target_block_root].parent_root
            else:
                break

        # Ensure target is in justifiable slot range
        #
        # Walk back until we find a slot that satisfies justifiability rules
        # relative to the latest finalized checkpoint.
        while not store.blocks[target_block_root].slot.is_justifiable_after(
            store.latest_finalized.slot
        ):
            target_block_root = store.blocks[target_block_root].parent_root

        # Create checkpoint from selected target block
        target_block = store.blocks[target_block_root]

        return Checkpoint(root=target_block_root, slot=target_block.slot)

    def produce_attestation_data(self, store: LstarStore, slot: Slot) -> AttestationData:
        """Produce attestation data for the given slot.

        This method constructs an AttestationData object according to the lean protocol
        specification. The attestation data represents the chain state view including
        head, target, and source checkpoints.
        """
        # Get the head block the validator sees for this slot
        head_checkpoint = Checkpoint(
            root=store.head,
            slot=store.blocks[store.head].slot,
        )

        # Calculate the target checkpoint for this attestation
        target_checkpoint = self.get_attestation_target(store)

        # Construct attestation data
        return self.attestation_data_class(
            slot=slot,
            head=head_checkpoint,
            target=target_checkpoint,
            source=store.latest_justified,
        )

    def produce_block_with_signatures(
        self,
        store: LstarStore,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> tuple[LstarStore, Block, list[SingleMessageAggregate]]:
        """Produce a block for the target slot.

        Returns the block alongside its per-attestation single-message
        aggregate proofs.

        Block production proceeds in four stages:
        1. Retrieve the current chain head as the parent block
        2. Verify proposer authorization for the target slot
        3. Build the block with maximal valid attestations
        4. Store the block and update checkpoints

        The block builder uses a fixed-point algorithm to collect attestations.
        Each iteration may update the justified checkpoint.

        Returns the per-attestation single-message aggregate proofs unmerged. The validator
        service signs the block root with the proposal key, wraps that into
        a singleton single-message aggregate, and merges all of them into the block-level
        multi-message aggregate proof carried by SignedBlock.proof.

        Raises:
            AssertionError: If validator is not the proposer for this slot,
                or if the produced block fails to close a justified divergence
                between the store and the head chain.
        """
        # Retrieve parent block.
        #
        # The proposal head reflects the latest chain view after processing
        # all pending attestations. Building on stale state would orphan the block.
        store, head_root = self.get_proposal_head(store, slot)
        head_state = store.states[head_root]

        # Verify proposer authorization.
        #
        # Only one validator may propose per slot.
        # Unauthorized proposals would be rejected by other nodes.
        num_validators = Uint64(len(head_state.validators))
        assert validator_index.is_proposer_for(slot, num_validators), (
            f"Validator {validator_index} is not the proposer for slot {slot}"
        )

        # Build the block.
        #
        # The builder iteratively collects valid attestations from aggregated
        # payloads matching the justified checkpoint. Each iteration may advance
        # justification, unlocking more attestation data entries.
        final_block, final_post_state, _, signatures = self.build_block(
            head_state,
            slot=slot,
            proposer_index=validator_index,
            parent_root=head_root,
            known_block_roots=set(store.blocks.keys()),
            aggregated_payloads=store.latest_known_aggregated_payloads,
        )

        # Invariant: the produced block must close any justified divergence.
        #
        # The store may have advanced its justified checkpoint from attestations
        # on a minority fork that the head state never processed. The fixed-point
        # loop above must incorporate those attestations from the pool, advancing
        # the block's justified checkpoint to at least match the store.
        #
        # Without this, other nodes processing the block would never see the
        # justification advance, degrading consensus liveness: only nodes that
        # happened to receive the minority fork would know justification moved.
        block_justified = final_post_state.latest_justified.slot
        store_justified = store.latest_justified.slot
        assert block_justified >= store_justified, (
            f"Produced block justified={block_justified} < store justified="
            f"{store_justified}. Fixed-point attestation loop did not converge."
        )

        # Compute block hash for storage.
        block_hash = hash_tree_root(final_block)

        # Update checkpoints from post-state.
        #
        # Locally produced blocks bypass normal block processing.
        # Checkpoint advances must be propagated manually here.
        #
        # Tie semantics mirror the block-import path.
        # A candidate needs a strictly higher slot to replace the store's view.
        latest_justified = store.latest_justified.advance_to(final_post_state.latest_justified)
        latest_finalized = store.latest_finalized.advance_to(final_post_state.latest_finalized)

        # Persist block and state.
        previous_finalized_slot = store.latest_finalized.slot
        store.blocks = store.blocks | {block_hash: final_block}
        store.states = store.states | {block_hash: final_post_state}
        store.latest_justified = latest_justified
        store.latest_finalized = latest_finalized

        # Prune stale attestation data when finalization advances
        if store.latest_finalized.slot > previous_finalized_slot:
            store = self.prune_stale_attestation_data(store)

        return store, final_block, signatures
