"""Lstar fork — validator duties: proposal head and production."""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.lstar._base import LstarSpecBase, LstarStore
from lean_spec.spec.forks.lstar.config import (
    JUSTIFICATION_LOOKBACK_SLOTS,
)
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    Block,
    Checkpoint,
    Interval,
    SingleMessageAggregate,
    Slot,
    ValidatorIndex,
)
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.ssz import Uint64


class ValidatorDutiesMixin(LstarSpecBase):
    """Validator duties for the lstar fork."""

    def get_attestation_target(self, store: LstarStore) -> Checkpoint:
        """
        Calculate target checkpoint for validator attestations.

        Determines the attestation target from the head, the safe target,
        and the finalization constraints.
        The algorithm balances advancing the chain head against safety.

        The walk starts at the head and goes backward.
        It takes up to the justification lookback bound steps.
        It stops once both the lower-bound slot and the justifiability rules are satisfied.

        The walk never crosses the finalized boundary.
        If the safe target lags behind finalization, the finalized slot is the lower bound.
        """
        # Start from current head
        target_block_root = store.head

        # Walk back toward the safe target, up to the justification lookback bound steps.
        #
        # If the safe target is stale behind the finalized checkpoint, the finalized slot
        # becomes the lower bound.
        # Target selection must never inspect candidate slots before the finalized boundary.
        safe_target_slot = store.blocks[store.safe_target].slot
        finalized_slot = store.latest_finalized.slot
        lower_bound_slot = max(safe_target_slot, finalized_slot)

        # This keeps the target from advancing too far ahead of the safe target.
        # It balances liveness against safety.
        for _ in range(int(JUSTIFICATION_LOOKBACK_SLOTS)):
            target_block = store.blocks[target_block_root]
            if target_block.slot > lower_bound_slot:
                target_block_root = target_block.parent_root
            else:
                break

        # Ensure target is in justifiable slot range
        #
        # Walk back until we find a slot that satisfies justifiability rules
        # relative to the latest finalized checkpoint.
        while True:
            target_block = store.blocks[target_block_root]
            if target_block.slot <= finalized_slot:
                break
            if target_block.slot.is_justifiable_after(finalized_slot):
                break
            target_block_root = target_block.parent_root

        # Create checkpoint from selected target block
        target_block = store.blocks[target_block_root]

        return Checkpoint(root=target_block_root, slot=target_block.slot)

    def produce_attestation_data(self, store: LstarStore, slot: Slot) -> AttestationData:
        """
        Produce attestation data for the given slot.

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
        """
        Produce a block for the target slot.

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
        proof carried by the signed block envelope.

        Raises:
            AssertionError: If validator is not the proposer for this slot,
                or if the produced block fails to close a justified divergence
                between the store and the head chain.
        """
        # Build on the freshest canonical head.
        #
        # Advance time to this slot's first interval, then fold in pending attestations.
        # The proposal head then reflects the latest chain view.
        # Building on stale state would orphan the block.
        target_interval = Interval.from_slot(slot)
        store, _ = self.on_tick(store, target_interval, True)
        store = self.accept_new_attestations(store)
        head_root = store.head
        head_state = store.states[head_root]

        # Verify proposer authorization.
        #
        # Only one validator may propose per slot.
        # Unauthorized proposals would be rejected by other nodes.
        num_validators = Uint64(len(head_state.validators))
        if validator_index != ValidatorIndex.proposer_for_slot(slot, num_validators):
            raise SpecRejectionError(
                RejectionReason.WRONG_PROPOSER,
                f"Validator {validator_index} is not the proposer for slot {slot}",
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

        # A locally produced block skips the import path.
        # Advance the justified checkpoint manually here.
        # Leave the finalized checkpoint to head recomputation.
        # Pinning it from this block's own state would strand it on a later reorg.
        latest_justified = store.latest_justified.advance_to(final_post_state.latest_justified)
        store = store.model_copy(
            update={
                "blocks": store.blocks | {block_hash: final_block},
                "states": store.states | {block_hash: final_post_state},
                "latest_justified": latest_justified,
            }
        )

        return store, final_block, signatures
