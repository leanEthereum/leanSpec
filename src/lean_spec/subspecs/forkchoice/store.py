"""
Forkchoice store for tracking chain state and votes.

The Store tracks all information required for the LMD GHOST forkchoice algorithm.
"""

import copy
from typing import Dict, cast

from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    SECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
    SignedVote,
    State,
    Vote,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, StakerIndex, Uint64, is_proposer
from lean_spec.types.container import Container

from .helpers import get_fork_choice_head, get_latest_justified


class Store(Container):
    """
    Forkchoice store tracking chain state and validator votes.

    Maintains all data needed for LMD GHOST fork choice algorithm including
    blocks, states, checkpoints, and validator voting records.
    """

    time: Uint64
    """Current time in intervals since genesis."""

    config: Config
    """Chain configuration parameters."""

    head: Bytes32
    """Root of the current canonical chain head block."""

    safe_target: Bytes32
    """Root of the current safe target for attestation voting."""

    latest_justified: Checkpoint
    """Highest slot justified checkpoint known to the store."""

    latest_finalized: Checkpoint
    """Highest slot finalized checkpoint known to the store."""

    blocks: Dict[Bytes32, Block] = {}
    """Mapping from block root to Block objects."""

    states: Dict[Bytes32, "State"] = {}
    """Mapping from state root to State objects."""

    latest_known_votes: Dict[StakerIndex, Checkpoint] = {}
    """Latest votes by validator that have been processed."""

    latest_new_votes: Dict[StakerIndex, Checkpoint] = {}
    """Latest votes by validator that are pending processing."""

    @classmethod
    def get_forkchoice_store(cls, state: State, anchor_block: Block) -> "Store":
        """
        Initialize forkchoice store from an anchor state and block.

        The anchor serves as a trusted starting point for the forkchoice. This
        class method acts as a factory for creating a new Store instance.

        Args:
            state: The trusted state object to initialize the store from.
            anchor_block: The trusted block corresponding to the state.

        Returns:
            A new, initialized Store object.

        Raises:
            AssertionError: If the anchor block's state root does not match the
                            hash of the anchor state.
        """
        # Validate that the anchor block corresponds to the anchor state
        assert anchor_block.state_root == hash_tree_root(state), (
            "Anchor block state root must match anchor state hash"
        )

        anchor_root = hash_tree_root(anchor_block)
        anchor_slot = anchor_block.slot

        return cls(
            time=Uint64(anchor_slot * INTERVALS_PER_SLOT),
            config=state.config,
            head=anchor_root,
            safe_target=anchor_root,
            latest_justified=state.latest_justified,
            latest_finalized=state.latest_finalized,
            blocks={anchor_root: copy.copy(anchor_block)},
            states={anchor_root: copy.copy(state)},
        )

    def validate_attestation(self, signed_vote: "SignedVote") -> None:
        """
        Validate incoming attestation before processing.

        Performs basic validation checks on attestation structure and timing.

        Args:
            signed_vote: Attestation to validate.

        Raises:
            AssertionError: If attestation fails validation.
        """
        vote = signed_vote.data

        # Validate vote targets exist in store
        assert vote.source.root in self.blocks, f"Unknown source block: {vote.source.root}"
        assert vote.target.root in self.blocks, f"Unknown target block: {vote.target.root}"

        # Validate slot relationships
        source_block = self.blocks[vote.source.root]
        target_block = self.blocks[vote.target.root]

        assert source_block.slot <= target_block.slot, "Source slot must not exceed target slot"
        assert vote.source.slot <= vote.target.slot, "Source checkpoint slot must not exceed target"

        # Validate checkpoint slots match block slots
        assert source_block.slot == vote.source.slot, "Source checkpoint slot mismatch"
        assert target_block.slot == vote.target.slot, "Target checkpoint slot mismatch"

        # Validate attestation is not too far in the future
        current_slot = Slot(self.time // SECONDS_PER_INTERVAL)
        assert vote.slot <= Slot(current_slot + Slot(1)), "Attestation too far in future"

    def process_attestation(self, signed_vote: "SignedVote", is_from_block: bool = False) -> None:
        """
        Process new attestation (signed vote).

        Handles attestations from blocks or network gossip, updating vote tracking
        according to timing and precedence rules.

        Args:
            signed_vote: Attestation to process.
            is_from_block: True if attestation came from block, False if from network.
        """
        # Validate attestation structure and constraints
        self.validate_attestation(signed_vote)

        validator_id = StakerIndex(signed_vote.data.validator_id)
        vote = signed_vote.data

        if is_from_block:
            # On-chain attestation processing

            # Update known votes if this is the latest from validator
            latest_known = self.latest_known_votes.get(validator_id)
            if latest_known is None or latest_known.slot < vote.slot:
                self.latest_known_votes[validator_id] = vote.target

            # Remove from new votes if this supersedes it
            latest_new = self.latest_new_votes.get(validator_id)
            if latest_new is not None and latest_new.slot <= vote.target.slot:
                del self.latest_new_votes[validator_id]

        else:
            # Network gossip attestation processing

            # Ensure forkchoice is current before processing gossip
            time_slots = self.time // SECONDS_PER_INTERVAL
            assert vote.slot <= time_slots, "Attestation from future slot"

            # Update new votes if this is latest from validator
            latest_new = self.latest_new_votes.get(validator_id)
            if latest_new is None or latest_new.slot < vote.target.slot:
                self.latest_new_votes[validator_id] = vote.target

    def process_block(self, block: Block) -> None:
        """
        Process new block and update forkchoice state.

        Adds block to store, processes included attestations, and updates head.

        Args:
            block: Block to process.
        """
        block_hash = hash_tree_root(block)

        # Skip if block already known
        if block_hash in self.blocks:
            return

        # Ensure parent state is available
        parent_state = self.states.get(block.parent_root)
        assert parent_state is not None, "Parent state not found - sync parent chain first"

        # Apply state transition to get post-block state
        state = copy.deepcopy(parent_state).process_block(block)

        # Add block and state to store
        self.blocks[block_hash] = block
        self.states[block_hash] = state

        # Process block's attestations as on-chain votes
        for signed_vote_untyped in block.body.attestations:
            signed_vote = cast(SignedVote, signed_vote_untyped)
            self.process_attestation(signed_vote, is_from_block=True)

        # Update forkchoice head
        self.update_head()

    def update_head(self) -> None:
        """Update store's head based on latest justified checkpoint and votes."""
        # Get latest justified checkpoint
        latest_justified = get_latest_justified(self.states)
        if latest_justified:
            object.__setattr__(self, "latest_justified", latest_justified)

        # Use LMD GHOST to find new head
        new_head = get_fork_choice_head(
            self.blocks, self.latest_justified.root, self.latest_known_votes
        )
        object.__setattr__(self, "head", new_head)

        # Update finalized checkpoint from head state
        if new_head in self.states:
            object.__setattr__(self, "latest_finalized", self.states[new_head].latest_finalized)

    def advance_time(self, time: Uint64, has_proposal: bool) -> None:
        """
        Advance forkchoice store time to given timestamp.

        Ticks store forward interval by interval, performing appropriate
        actions for each interval type.

        Args:
            time: Target time in seconds since genesis.
            has_proposal: Whether node has proposal for current slot.
        """
        # Calculate target time in intervals
        tick_interval_time = (time - self.config.genesis_time) // SECONDS_PER_INTERVAL

        # Tick forward one interval at a time
        while self.time < tick_interval_time:
            # Check if proposal should be signaled for next interval
            should_signal_proposal = has_proposal and (self.time + Uint64(1)) == tick_interval_time

            # Advance by one interval with appropriate signaling
            self.tick_interval(should_signal_proposal)

    def tick_interval(self, has_proposal: bool) -> None:
        """
        Advance store time by one interval and perform interval-specific actions.

        Different actions are performed based on interval within slot:
        - Interval 0: Process votes if proposal exists
        - Interval 1: Validator voting period (no action)
        - Interval 2: Update safe target
        - Interval 3: Process votes

        Args:
            has_proposal: Whether a proposal exists for this interval.
        """
        object.__setattr__(self, "time", self.time + Uint64(1))
        current_interval = self.time % INTERVALS_PER_SLOT

        if current_interval == Uint64(0):
            # Start of slot - process votes if proposal exists
            if has_proposal:
                self.accept_new_votes()
        elif current_interval == Uint64(1):
            # Validator voting interval - no action
            pass
        elif current_interval == Uint64(2):
            # Update safe target for next votes
            self.update_safe_target()
        else:
            # End of slot - process accumulated votes
            self.accept_new_votes()

    def accept_new_votes(self) -> None:
        """
        Process pending votes and update forkchoice head.

        Moves votes from latest_new_votes to latest_known_votes and triggers
        head update.
        """
        # Move all new votes to known votes
        for validator_id, vote in self.latest_new_votes.items():
            self.latest_known_votes[validator_id] = vote

        # Clear pending votes and update head
        self.latest_new_votes.clear()
        self.update_head()

    def update_safe_target(self) -> None:
        """
        Update the safe target for attestation votes.

        Computes target that has sufficient (2/3+ majority) vote support.
        """
        # Calculate 2/3 majority threshold (ceiling division)
        min_target_score = -(-self.config.num_validators * 2 // 3)

        # Find head with minimum vote threshold
        safe_target = get_fork_choice_head(
            self.blocks,
            self.latest_justified.root,
            self.latest_new_votes,
            min_score=min_target_score,
        )
        object.__setattr__(self, "safe_target", safe_target)

    def get_proposal_head(self, slot: Slot) -> Bytes32:
        """
        Get the head for block proposal at given slot.

        Ensures store is up-to-date and processes any pending votes.

        Args:
            slot: Slot for which to get proposal head.

        Returns:
            Root of block to build upon.
        """
        slot_time = self.config.genesis_time + slot * SECONDS_PER_SLOT

        # Tick store to current time (no-op if already current)
        self.advance_time(slot_time, True)

        # Process any pending votes (no-op if already processed)
        self.accept_new_votes()

        return self.head

    def get_vote_target(self) -> Checkpoint:
        """
        Calculate target checkpoint for validator votes.

        Determines appropriate attestation target based on head, safe target,
        and finalization constraints.

        Returns:
            Target checkpoint for voting.
        """
        # Start from current head
        target_block_root = self.head

        # Walk back up to 3 steps if safe target is newer
        for _ in range(3):
            if self.blocks[target_block_root].slot > self.blocks[self.safe_target].slot:
                target_block_root = self.blocks[target_block_root].parent_root

        # Ensure target is in justifiable slot range
        while not self.blocks[target_block_root].slot.is_justifiable_after(
            self.latest_finalized.slot
        ):
            target_block_root = self.blocks[target_block_root].parent_root

        target_block = self.blocks[target_block_root]
        return Checkpoint(root=hash_tree_root(target_block), slot=target_block.slot)

    def produce_block(self, slot: Slot, validator_index: StakerIndex) -> Block:
        """
        Produce a new block for the given slot and validator.

        Algorithm Overview:
        1. Validate proposer authorization for the target slot
        2. Get the current chain head as the parent block
        3. Iteratively build attestation set:
           - Create candidate block with current attestations
           - Apply state transition (slot advancement + block processing)
           - Find new valid attestations matching post-state requirements
           - Continue until no new attestations can be added
        4. Finalize block with computed state root and store it

        Args:
            slot: Target slot number for block production
            validator_index: Index of validator authorized to propose this block

        Returns:
            Complete block with maximal attestation set and valid state root

        Raises:
            AssertionError: If validator lacks proposer authorization for slot
        """
        # Validate proposer authorization for this slot
        if not is_proposer(validator_index, slot, self.config.num_validators):
            msg = f"Validator {validator_index} is not the proposer for slot {slot}"
            raise AssertionError(msg)

        # Get parent block and state to build upon
        head_root = self.get_proposal_head(slot)
        head_state = self.states[head_root]

        # Initialize empty attestation set for iterative collection
        attestations: list[SignedVote] = []

        # Iteratively collect valid attestations using fixed-point algorithm
        #
        # Continue until no new attestations can be added to the block
        while True:
            # Create candidate block with current attestation set
            candidate_block = Block(
                slot=slot,
                proposer_index=validator_index,
                parent_root=head_root,
                state_root=Bytes32.zero(),  # Temporary; updated after state computation
                body=BlockBody(attestations=attestations),
            )

            # Apply state transition to get the post-block state
            # First advance state to target slot, then process the block
            advanced_state = head_state.process_slots(slot)
            post_state = advanced_state.process_block(candidate_block)

            # Find new valid attestations matching post-state justification
            new_attestations: list[SignedVote] = []
            for validator_id, checkpoint in self.latest_known_votes.items():
                # Skip if target block is unknown in our store
                if checkpoint.root not in self.blocks:
                    continue

                # Create attestation with post-state's latest justified as source
                vote = Vote(
                    validator_id=validator_id,
                    slot=checkpoint.slot,
                    head=checkpoint,
                    target=checkpoint,
                    source=post_state.latest_justified,
                )
                signed_vote = SignedVote(data=vote, signature=Bytes32.zero())

                # Include if not already in attestation set
                if signed_vote not in attestations:
                    new_attestations.append(signed_vote)

            # Fixed point reached: no new attestations found
            if not new_attestations:
                break

            # Add new attestations and continue iteration
            attestations.extend(new_attestations)

        # Create final block with all collected attestations
        final_state = head_state.process_slots(slot)
        final_block = Block(
            slot=slot,
            proposer_index=validator_index,
            parent_root=head_root,
            state_root=Bytes32.zero(),  # Will be updated with computed hash
            body=BlockBody(attestations=attestations),
        )

        # Apply state transition to get final post-state and compute state root
        final_post_state = final_state.process_block(final_block)
        finalized_block = final_block.model_copy(
            update={"state_root": hash_tree_root(final_post_state)}
        )

        # Store block and state in forkchoice store
        block_hash = hash_tree_root(finalized_block)
        self.blocks[block_hash] = finalized_block
        self.states[block_hash] = final_post_state

        return finalized_block

    def produce_attestation_vote(self, slot: Slot, validator_index: StakerIndex) -> Vote:
        """
        Produce an attestation vote for the given slot and validator.

        This method constructs a Vote object according to the lean protocol
        specification for attestation voting. The vote represents the
        validator's view of the chain state and their choice for the
        next justified checkpoint.

        The algorithm:
        1. Get the current head block for proposal
        2. Calculate the appropriate vote target using current forkchoice state
        3. Use the store's latest justified checkpoint as the vote source
        4. Construct and return the complete Vote object

        Args:
            slot: The slot for which to produce the attestation vote.
            validator_index: The validator index producing the vote.

        Returns:
            A fully constructed Vote object ready for signing and broadcast.
        """
        # Get the head block the validator sees for this slot
        head_root = self.get_proposal_head(slot)
        head_checkpoint = Checkpoint(
            root=head_root,
            slot=self.blocks[head_root].slot,
        )

        # Calculate the target checkpoint for this vote
        #
        # This uses the store's current forkchoice state to determine
        # the appropriate attestation target
        target_checkpoint = self.get_vote_target()

        # Create the vote using current forkchoice state
        return Vote(
            validator_id=validator_index,
            slot=slot,
            head=head_checkpoint,
            target=target_checkpoint,
            source=self.latest_justified,
        )
