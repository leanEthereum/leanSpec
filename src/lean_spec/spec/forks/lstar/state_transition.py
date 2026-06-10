"""Lstar fork — state transition: slots, header, body, finalization."""

from collections.abc import Iterable, Sequence
from typing import Any

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.lstar._base import LstarSpecBase
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AttestationData,
    Block,
    Checkpoint,
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Slot,
    State,
    ValidatorIndex,
    Validators,
)
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.forks.protocol import SpecStateType
from lean_spec.spec.observability import (
    observe_state_transition,
)
from lean_spec.spec.ssz import ZERO_HASH, Boolean, Bytes32, SSZList, Uint64


def attestation_data_matches_chain(
    attestation_data: AttestationData,
    historical_block_hashes: Sequence[Bytes32],
) -> bool:
    """
    Check that attestation checkpoints point to blocks on a chain.

    Args:
        attestation_data: The attestation being validated.
        historical_block_hashes: Chain view indexed by slot.
            Empty slots carry the zero hash.

    Returns:
        True when all checkpoint roots match the chain at their slot.
        False when any root is the zero hash.
        False when any checkpoint slot is past the end of the chain view.
    """
    # Reject zero-hash checkpoints up front.
    #
    # Empty slots carry the zero hash on the chain.
    # A vote whose recorded root equals the zero hash is meaningless.
    if (
        attestation_data.source.root == ZERO_HASH
        or attestation_data.target.root == ZERO_HASH
        or attestation_data.head.root == ZERO_HASH
    ):
        return False

    # Reject checkpoints whose slot is beyond the chain view.
    #
    # Without this guard, indexed access raises IndexError.
    source_slot = int(attestation_data.source.slot)
    target_slot = int(attestation_data.target.slot)
    head_slot = int(attestation_data.head.slot)
    chain_length = len(historical_block_hashes)
    if source_slot >= chain_length or target_slot >= chain_length or head_slot >= chain_length:
        return False

    # All checkpoint roots must match the chain at their slot.
    return (
        attestation_data.source.root == historical_block_hashes[source_slot]
        and attestation_data.target.root == historical_block_hashes[target_slot]
        and attestation_data.head.root == historical_block_hashes[head_slot]
    )


class StateTransitionMixin(LstarSpecBase):
    """State transition function for the lstar fork."""

    def upgrade_state(self, state: SpecStateType) -> State:
        """
        Lstar is the root fork: there is no predecessor, so no migration.

        Returns the input state unchanged.
        """
        assert isinstance(state, State)
        return state

    def generate_genesis(self, genesis_time: Uint64, validators: SSZList[Any]) -> State:
        """Generate a genesis state with empty history and proper initial values."""
        assert isinstance(validators, Validators)

        # Configure the genesis state.
        genesis_config = self.genesis_config_class(
            genesis_time=genesis_time,
        )

        # Build the genesis block header for the state.
        genesis_header = self.block_header_class(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(
                self.block_body_class(attestations=self.aggregated_attestations_class(data=[]))
            ),
        )

        # Assemble and return the full genesis state.
        return self.state_class(
            config=genesis_config,
            slot=Slot(0),
            latest_block_header=genesis_header,
            latest_justified=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            latest_finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=validators,
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        )

    def process_slots(self, state: State, target_slot: Slot) -> State:
        """
        Advance the state through empty slots up to, but not including, target_slot.

        The loop:
          - Performs per-slot maintenance (e.g., state root caching).
          - Increments the slot counter after each call.
        The function returns a new state with slot == target_slot.

        Raises:
            SpecRejectionError: BLOCK_SLOT_NOT_IN_FUTURE if target_slot is not in the future.
        """
        # The target must be strictly greater than the current slot.
        if state.slot >= target_slot:
            raise SpecRejectionError(
                RejectionReason.BLOCK_SLOT_NOT_IN_FUTURE, "Target slot must be in the future"
            )

        # Step through each missing slot.
        while state.slot < target_slot:
            # Cache the pre-block state root into the latest header, then bump the slot.
            #
            # Invariant: the header's state root is empty only for the first empty
            # slot after a block, so this caching happens at most once per block.
            # Later empty slots in a run find a populated root and reuse it.
            needs_state_root = state.latest_block_header.state_root == Bytes32.zero()
            cached_state_root = (
                hash_tree_root(state) if needs_state_root else state.latest_block_header.state_root
            )

            state = state.model_copy(
                update={
                    "latest_block_header": state.latest_block_header.model_copy(
                        update={"state_root": cached_state_root}
                    ),
                    "slot": Slot(state.slot + Slot(1)),
                }
            )

        # Reached the target slot. Return the advanced state.
        return state

    def process_block_header(self, state: State, block: Block) -> State:
        """
        Validate the block header and update header-linked state.

        Checks:
          - The block slot equals the current state slot.
          - The block slot is newer than the latest header slot.
          - The proposer index matches the round-robin selection.
          - The parent root matches the hash of the latest block header.

        Updates:
          - For the first post-genesis block, mark genesis as justified/finalized.
          - Append the parent root to historical hashes.
          - Append the justified bit for the parent (true only for genesis).
          - Insert ZERO_HASH entries for any skipped empty slots.
          - Set latest_block_header for the new block with an empty state_root.

        Raises:
            SpecRejectionError: If any header check fails (slot mismatch, block older
                than the latest header, wrong proposer, or parent root mismatch).
        """
        # Validation
        #
        # - Retrieve the header of the previous block (the parent).
        # - Compute the parent root hash.
        parent_header = state.latest_block_header
        parent_root = hash_tree_root(parent_header)

        # Consensus checks

        # Verify the block corresponds to the current state slot.
        #
        # To move to this slot, we have processed any intermediate slots before.
        if block.slot != state.slot:
            raise SpecRejectionError(RejectionReason.BLOCK_SLOT_MISMATCH, "Block slot mismatch")

        # The block must be newer than the current latest header.
        if block.slot <= parent_header.slot:
            raise SpecRejectionError(
                RejectionReason.BLOCK_OLDER_THAN_LATEST_HEADER, "Block is older than latest header"
            )

        # Verify the block proposer.
        #
        # Ensures the block was proposed by the assigned validator for this round.
        if block.proposer_index != ValidatorIndex.proposer_for_slot(
            slot=state.slot,
            num_validators=Uint64(len(state.validators)),
        ):
            raise SpecRejectionError(RejectionReason.WRONG_PROPOSER, "Incorrect block proposer")

        # Verify the chain link.
        #
        # The block must cryptographically point to the known parent.
        if block.parent_root != parent_root:
            raise SpecRejectionError(
                RejectionReason.PARENT_ROOT_MISMATCH, "Block parent root mismatch"
            )

        # Checkpoint Updates

        # Detect if we are transitioning from the genesis block.
        #
        # This flag is True only when processing the very first block of the chain.
        # This means the parent is the Genesis block (Slot 0).
        is_genesis_parent = parent_header.slot == Slot(0)

        # Update the consensus checkpoints.
        #
        # This logic acts as the trust anchor for the chain:
        #
        # - If the parent is the Genesis block: It cannot receive votes as it
        #   precedes the start of the chain. Therefore, we explicitly force it
        #   to be Justified and Finalized immediately.
        #
        # - For all other blocks: We retain the existing checkpoints. Future
        #   updates rely entirely on validator attestations which are processed
        #   later in the block body.
        if is_genesis_parent:
            new_latest_justified = Checkpoint(slot=Slot(0), root=parent_root)
            new_latest_finalized = Checkpoint(slot=Slot(0), root=parent_root)
        else:
            new_latest_justified = state.latest_justified
            new_latest_finalized = state.latest_finalized

        # Historical Data Management

        # Calculate the gap between the parent and the current block.
        #
        # If slots were skipped (missed proposals), we must record them.
        #
        # Formula: (Current - Parent - 1). Adjacent blocks have a gap of 0.
        num_empty_slots = int(block.slot - parent_header.slot - Slot(1))

        # Update the list of historical block roots.
        #
        # Structure: [Existing history] + [Parent root] + [Zero hash for gaps]
        new_historical_block_hashes = (
            state.historical_block_hashes + [parent_root] + [ZERO_HASH] * num_empty_slots
        )

        # Update the list of justified slot flags.
        #
        # IMPORTANT: This list is stored relative to the finalized boundary.
        #
        # The first entry corresponds to the slot immediately following the
        # latest finalized checkpoint.
        #
        # Here, we extend the storage capacity to ensure the range from the
        # finalized boundary up to the last materialized slot is fully tracked
        # and addressable. The current block's slot is not materialized until
        # its header is fully processed, so we stop at slot (block.slot - 1).
        last_materialized_slot = block.slot - Slot(1)
        new_justified_slots = state.justified_slots.extend_to_slot(
            new_latest_finalized.slot,
            last_materialized_slot,
        )

        # Construct the new latest block header.
        #
        # The new header object represents the tip of the chain.
        #
        # Leave state root empty.
        # It is not computed until the block body is fully processed or the next slot begins.
        new_latest_block_header = self.block_header_class(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            body_root=hash_tree_root(block.body),
            state_root=Bytes32.zero(),
        )

        # Apply all calculated updates atomically in one new state.
        return state.model_copy(
            update={
                "latest_justified": new_latest_justified,
                "latest_finalized": new_latest_finalized,
                "historical_block_hashes": new_historical_block_hashes,
                "justified_slots": new_justified_slots,
                "latest_block_header": new_latest_block_header,
            }
        )

    def process_block(self, state: State, block: Block) -> State:
        """
        Apply full block processing including header and body.

        Raises:
            SpecRejectionError: If header validation fails.
        """
        # First process the block header.
        state = self.process_block_header(state, block)

        return self.process_attestations(state, block.body.attestations)

    def process_attestations(
        self,
        state: State,
        attestations: Iterable[AggregatedAttestation],
    ) -> State:
        """
        Apply attestations and update justification/finalization
        according to the Lean Consensus 3SF-mini rules.

        This simplified consensus mechanism:
        1. Processes each attestation
        2. Updates justified status for target checkpoints
        3. Applies finalization rules based on justified status

        Raises:
            SpecRejectionError: EMPTY_AGGREGATION_BITS if an attestation that passes
                the vote filters has no set bits.
            SpecRejectionError: VALIDATOR_INDEX_OUT_OF_RANGE if a set bit points
                outside the validator registry.
        """
        # Reconstruct the vote-tracking structure
        #
        # The state stores justification data in a compact SSZ layout:
        #
        #   - A list of block roots that are currently being tracked.
        #   - One long flat list containing validator vote flags.
        #
        # For each tracked block, there is a consecutive segment of vote flags.
        # Every segment has the same length: the number of validators.
        #
        # Conceptually, we want to recover a more natural view:
        #
        #   "For each block root, here is the list of votes from all validators."
        #
        # We rebuild this intuitive structure by slicing the flat vote list back
        # into its individual segments. Each slice corresponds to one tracked block.
        #
        # This gives us a mapping:
        #
        #       (block root) → [vote flags for validators 0..N-1]
        #
        # which makes the rest of the logic easier to express and understand.
        assert not any(root == ZERO_HASH for root in state.justifications_roots), (
            "zero hash is not allowed in justifications roots"
        )
        justifications = {
            root: state.justifications_validators[
                i * len(state.validators) : (i + 1) * len(state.validators)
            ]
            for i, root in enumerate(state.justifications_roots)
        }

        # Track state changes to be applied at the end
        latest_justified = state.latest_justified
        latest_finalized = state.latest_finalized
        finalized_slot = latest_finalized.slot
        justified_slots = state.justified_slots

        # Map roots to their latest slot for pruning.
        #
        # Votes for zero hash are ignored, so we only need the most recent slot
        # where a root appears to decide whether it is still unfinalized.
        start_slot = int(finalized_slot) + 1
        root_to_slot: dict[Bytes32, Slot] = {
            root: Slot(i)
            for i, root in enumerate(state.historical_block_hashes[start_slot:], start=start_slot)
        }

        # Process each attestation independently.
        #
        # Every attestation is a claim:
        # "I vote to extend the chain from SOURCE to TARGET."
        #
        # The rules below filter out invalid or irrelevant votes.
        for attestation in attestations:
            source = attestation.data.source
            target = attestation.data.target

            # Check that the source is already trusted.
            #
            # A vote may only originate from a point in history that is already justified.
            # A source that lacks existing justification cannot be used to anchor a new vote.
            if not justified_slots.is_slot_justified(finalized_slot, source.slot):
                continue

            # Ignore votes for targets that have already reached consensus.
            #
            # If a block is already justified, additional votes do not change anything.
            # We simply skip them.
            if justified_slots.is_slot_justified(finalized_slot, target.slot):
                continue

            # Ensure the vote refers to blocks that actually exist on our chain.
            #
            # The attestation must match our canonical chain.
            # Both the source root and target root must equal the recorded block roots.
            # The recorded roots are the ones stored for those slots in history.
            #
            # This prevents votes about unknown or conflicting forks.
            # It also rejects zero-hash source or target roots.
            if not attestation_data_matches_chain(
                attestation.data, state.historical_block_hashes.data
            ):
                continue

            # Ensure time flows forward.
            #
            # A target must always lie strictly after its source slot.
            # Otherwise the vote makes no chronological sense.
            if target.slot <= source.slot:
                continue

            # Ensure the target falls on a slot that can be justified after the finalized one.
            #
            # In 3SF-mini, justification does not advance freely through time.
            #
            # Only certain positions beyond the finalized slot are allowed to
            # receive new votes. These positions form a small, structured set:
            #
            #   - the immediate steps right after finalization,
            #   - the square-number distances,
            #   - and the pronic-number distances.
            #
            # Any target outside this pattern is not eligible for justification,
            # so votes for it are simply ignored.
            if not target.slot.is_justifiable_after(finalized_slot):
                continue

            # Resolve the participating validators from the aggregation bits.
            #
            # An aggregation with no set bits names no voter at all.
            # Such an attestation is malformed and rejects the whole block.
            voting_validator_indices = attestation.aggregation_bits.to_validator_indices()

            # Reject set bits that point outside the validator registry.
            #
            # The tally below holds one flag per registered validator.
            # A vote from a nonexistent validator has no flag to set,
            # so the whole block is invalid.
            # Trailing unset bits beyond the registry are harmless padding.
            for validator_index in voting_validator_indices:
                if not validator_index.is_within_registry(Uint64(len(state.validators))):
                    raise SpecRejectionError(
                        RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE,
                        "Attestation aggregation bits reference a validator outside the registry",
                    )

            # Record the vote.
            #
            # If this is the first vote for the target block, create a fresh tally sheet:
            # - one boolean per validator, all initially False.
            if target.root not in justifications:
                justifications[target.root] = [Boolean(False)] * len(state.validators)

            # Mark that each validator in this aggregation has voted for the target.
            #
            # A vote is a boolean flag set to True.
            # Re-marking an existing voter is idempotent, so no guard is needed.
            for validator_index in voting_validator_indices:
                justifications[target.root][validator_index] = Boolean(True)

            # Check whether the vote count crosses the supermajority threshold.
            #
            # A block becomes justified when at least two-thirds of validators
            # have voted for it.
            #
            # We compare integers to avoid floating-point division:
            #
            # 3 * (number of votes) ≥ 2 * (total validators)
            count = sum(bool(justified) for justified in justifications[target.root])

            if 3 * count >= (2 * len(state.validators)):
                # The block becomes justified
                #
                # The chain now considers this block part of its safe head.
                # Only advance the checkpoint forward.
                # Attestations within a block can resolve in any order, and
                # an earlier target processed after a later one must not
                # drag latest_justified backwards.
                if target.slot > latest_justified.slot:
                    latest_justified = target

                # The justifiable filter above guarantees an in-range index.
                justified_index = target.slot.justified_index_after(finalized_slot)
                assert justified_index is not None

                # Rebind to a copy so the pre-state bitfield is never mutated.
                updated_justified_bits = list(justified_slots.data)
                updated_justified_bits[justified_index] = Boolean(True)
                justified_slots = JustifiedSlots(data=updated_justified_bits)

                # There is no longer any need to track individual votes for this block.
                del justifications[target.root]

                # Consider whether finalization can advance
                #
                # Finalization requires a continuous chain of trust from the
                # previously finalized checkpoint up to the new justified point.
                #
                # Finalization advances only when the source lies past the old finalized point.
                # A source at or behind that boundary is already final.
                # Such a source may still justify a newer target, but it must not re-finalize.
                # When the source is newer and every slot in between is justifiable
                # relative to that old finalized point, the source checkpoint becomes finalized.
                #
                # In short:
                #
                #     If there is no break in the chain, advance finalization.
                if source.slot > finalized_slot and not any(
                    Slot(slot).is_justifiable_after(finalized_slot)
                    for slot in range(source.slot + Slot(1), target.slot)
                ):
                    old_finalized_slot = finalized_slot
                    latest_finalized = source
                    finalized_slot = latest_finalized.slot

                    # Rebase/prune justification tracking across the new finalized boundary.
                    #
                    # The state stores justified slot flags starting at (finalized_slot + 1),
                    # so when finalization advances by `delta`, we drop the first `delta` bits.
                    #
                    # We also prune any pending justifications whose latest slot
                    # is now finalized (latest <= finalized_slot).
                    delta = int(finalized_slot - old_finalized_slot)
                    if delta > 0:
                        justified_slots = JustifiedSlots(data=justified_slots.data[delta:])
                        assert all(root in root_to_slot for root in justifications), (
                            "Justification root missing from root_to_slot"
                        )
                        justifications = {
                            root: votes
                            for root, votes in justifications.items()
                            if root_to_slot[root] > finalized_slot
                        }

        # Convert the vote structure back into SSZ format
        #
        # Internally, we used a mapping:
        #
        #       block root → list of votes
        #
        # SSZ requires:
        #
        #   - a sorted list of block roots
        #   - a single flat list of votes (all roots concatenated in sorted order)
        #
        # Sorting ensures that every node produces identical state representation.
        sorted_roots = sorted(justifications.keys())

        # Construct and return the updated state.
        return state.model_copy(
            update={
                "justifications_roots": JustificationRoots(data=sorted_roots),
                "justifications_validators": JustificationValidators(
                    data=[vote for root in sorted_roots for vote in justifications[root]]
                ),
                "justified_slots": justified_slots,
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
            }
        )

    def state_transition(
        self,
        state: State,
        block: Block,
    ) -> State:
        """
        Apply the complete state transition function for a block.

        This method represents the full state transition function:
        1. Process slots up to the block's slot
        2. Process the block header and body
        3. Validate the computed state root

        Signatures are verified outside this function, before it is called.

        Raises:
            SpecRejectionError: If slot or header validation fails, or STATE_ROOT_MISMATCH
                if the block's state root does not match the computed post-state root.
        """
        with observe_state_transition():
            # First, process any intermediate slots.
            advanced = self.process_slots(state, block.slot)

            # Process the block itself.
            new_state = self.process_block(advanced, block)

            # Validate that the block's state root matches the computed state
            computed_state_root = hash_tree_root(new_state)
            if block.state_root != computed_state_root:
                raise SpecRejectionError(
                    RejectionReason.STATE_ROOT_MISMATCH, "Invalid block state root"
                )

        return new_state
