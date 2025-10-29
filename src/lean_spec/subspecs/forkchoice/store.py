"""
Forkchoice store for tracking chain state and attestations.

The Store tracks all information required for the LMD GHOST forkchoice algorithm.
"""

__all__ = [
    "Store",
    "SECONDS_PER_SLOT",
    "SECONDS_PER_INTERVAL",
    "INTERVALS_PER_SLOT",
]

import copy
from typing import Dict

from pydantic import BaseModel

from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    SECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    Config,
    SignedAttestation,
    SignedBlockWithAttestation,
    State,
)
from lean_spec.subspecs.containers.block import Attestations, BlockSignatures
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import (
    Bytes32,
    Bytes4000,
    Uint64,
    ValidatorIndex,
    is_proposer,
)

from .helpers import get_fork_choice_head, get_latest_justified


class Store(BaseModel):
    """
    Forkchoice store tracking chain state and validator attestations.

    Maintains all data needed for LMD GHOST fork choice algorithm including
    blocks, states, checkpoints, and validator attestation records.
    """

    time: Uint64
    """Current time in intervals since genesis."""

    config: Config
    """Chain configuration parameters."""

    head: Bytes32
    """Root of the current canonical chain head block."""

    safe_target: Bytes32
    """Root of the current safe target for attestation."""

    latest_justified: Checkpoint
    """Highest slot justified checkpoint known to the store."""

    latest_finalized: Checkpoint
    """Highest slot finalized checkpoint known to the store."""

    blocks: Dict[Bytes32, Block] = {}
    """Mapping from block root to Block objects."""

    states: Dict[Bytes32, "State"] = {}
    """Mapping from state root to State objects."""

    latest_known_attestations: Dict[ValidatorIndex, SignedAttestation] = {}
    """Latest signed attestations by validator that have been processed."""

    latest_new_attestations: Dict[ValidatorIndex, SignedAttestation] = {}
    """Latest signed attestations by validator that are pending processing."""

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

        # Create checkpoint from anchor block
        # The anchor block becomes the initial justified and finalized checkpoint
        anchor_checkpoint = Checkpoint(root=anchor_root, slot=anchor_slot)

        return cls(
            time=Uint64(anchor_slot * INTERVALS_PER_SLOT),
            config=state.config,
            head=anchor_root,
            safe_target=anchor_root,
            latest_justified=anchor_checkpoint,
            latest_finalized=anchor_checkpoint,
            blocks={anchor_root: copy.copy(anchor_block)},
            states={anchor_root: copy.copy(state)},
        )

    def validate_attestation(self, signed_attestation: SignedAttestation) -> None:
        """
        Validate incoming attestation before processing.

        Performs basic validation checks on attestation structure and timing.

        Args:
            signed_attestation: Attestation to validate.

        Raises:
            AssertionError: If attestation fails validation.
        """
        attestation = signed_attestation.message
        data = attestation.data

        # Validate attestation targets exist in store
        assert data.source.root in self.blocks, f"Unknown source block: {data.source.root.hex()}"
        assert data.target.root in self.blocks, f"Unknown target block: {data.target.root.hex()}"
        assert data.head.root in self.blocks, f"Unknown head block: {data.head.root.hex()}"

        # Validate slot relationships
        source_block = self.blocks[data.source.root]
        target_block = self.blocks[data.target.root]

        assert source_block.slot <= target_block.slot, "Source slot must not exceed target"
        assert data.source.slot <= data.target.slot, "Source checkpoint slot must not exceed target"

        # Validate checkpoint slots match block slots
        assert source_block.slot == data.source.slot, "Source checkpoint slot mismatch"
        assert target_block.slot == data.target.slot, "Target checkpoint slot mismatch"

        # Validate attestation is not too far in the future
        current_slot = Slot(self.time // INTERVALS_PER_SLOT)
        assert data.slot <= Slot(current_slot + Slot(1)), "Attestation too far in future"

    def process_attestation(
        self,
        signed_attestation: SignedAttestation,
        is_from_block: bool = False,
    ) -> None:
        """
        Process new attestation (signed validator attestation).

        Handles attestations from blocks or network gossip, updating attestation tracking
        according to timing and precedence rules.

        Args:
            signed_attestation: Attestation to process.
            is_from_block: True if attestation came from block, False if from network.
        """
        # Validate attestation structure and constraints
        self.validate_attestation(signed_attestation)

        attestation = signed_attestation.message
        validator_id = ValidatorIndex(attestation.validator_id)
        attestation_slot = attestation.data.slot

        if is_from_block:
            # On-chain attestation processing

            # Update known attestations if this is the latest from validator
            latest_known = self.latest_known_attestations.get(validator_id)
            if latest_known is None or latest_known.message.data.slot < attestation_slot:
                self.latest_known_attestations[validator_id] = signed_attestation

            # Remove from new attestations if this supersedes it
            latest_new = self.latest_new_attestations.get(validator_id)
            if latest_new is not None and latest_new.message.data.slot <= attestation_slot:
                del self.latest_new_attestations[validator_id]
        else:
            # Network gossip attestation processing

            # Ensure forkchoice is current before processing gossip
            time_slots = self.time // INTERVALS_PER_SLOT
            assert attestation_slot <= time_slots, "Attestation from future slot"

            # Update new attestations if this is latest from validator
            latest_new = self.latest_new_attestations.get(validator_id)
            if latest_new is None or latest_new.message.data.slot < attestation_slot:
                self.latest_new_attestations[validator_id] = signed_attestation

    @staticmethod
    def _is_valid_signature(signature: Bytes4000) -> bool:
        """Return True when the placeholder signature is the zero value."""
        # TODO: Replace placeholder check once aggregated signatures are
        # wired in as part of the multi-proof integration work.
        return signature == Bytes4000.zero()

    def _validate_block_signatures(
        self,
        block: Block,
        signatures: BlockSignatures,
    ) -> bool:
        """Temporary stub for aggregated signature validation."""
        # TODO: Integrate actual aggregated signature verification.
        return all(self._is_valid_signature(signature) for signature in signatures)

    def process_block(self, signed_block_with_attestation: SignedBlockWithAttestation) -> None:
        """
        Process new block and update forkchoice state.

        Adds block to store, processes included attestations, and updates head.

        Args:
            signed_block_with_attestation: Block to process.
        """
        block = signed_block_with_attestation.message.block
        proposer_attestation = signed_block_with_attestation.message.proposer_attestation
        signatures = signed_block_with_attestation.signature

        block_hash = hash_tree_root(block)

        # Skip if block already known
        if block_hash in self.blocks:
            return

        # Ensure parent state is available
        parent_state = self.states.get(block.parent_root)
        # at this point parent state should be available so node should
        # sync parent chain if not available before adding block to forkchoice
        assert parent_state is not None, "Parent state not found - sync parent chain first"

        valid_signatures = self._validate_block_signatures(block, signatures)

        # Get post state from STF (State Transition Function)
        state = copy.deepcopy(parent_state).state_transition(block, valid_signatures)

        # Add block and state to store
        self.blocks[block_hash] = block
        self.states[block_hash] = state

        # Process block's attestations as on-chain attestations
        for index, attestation in enumerate(block.body.attestations):
            signature = signatures[index]
            signed_attestation = SignedAttestation(
                message=attestation,
                # eventually one would be able to associate and consume an
                # aggregated signature for individual attestation validity with that
                # information encoded in the signature
                signature=signature,
            )
            self.process_attestation(signed_attestation, is_from_block=True)

        # Update forkchoice head
        self.update_head()

        proposer_signature = signatures[len(block.body.attestations)]
        # the proposer attestation for the current slot and block as head is to be
        # treated as the attestation is independently casted in the second interval
        signed_proposer_attestation = SignedAttestation(
            message=proposer_attestation,
            signature=proposer_signature,
        )
        # note that we pass False here as this is a proposer attestation casted with
        # block, but to treated as casted independently after the proposal in the next
        # interval and to be hopefully included in some future block (most likely next)
        #
        # Hence make sure this gets added to the new attestations so that this doesn't influence
        # this node's validators upcoming attestations
        self.process_attestation(signed_proposer_attestation, is_from_block=False)

    def update_head(self) -> None:
        """Update store's head based on latest justified checkpoint and attestations."""
        # Get latest justified checkpoint
        latest_justified = get_latest_justified(self.states)
        if latest_justified:
            self.latest_justified = latest_justified

        # Use LMD GHOST to find new head
        new_head = get_fork_choice_head(
            self.blocks, self.latest_justified.root, self.latest_known_attestations
        )
        self.head = new_head

        # Update finalized checkpoint from head state
        if new_head in self.states:
            self.latest_finalized = self.states[new_head].latest_finalized

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
        - Interval 0: Process attestations if proposal exists
        - Interval 1: Validator attesting period (no action)
        - Interval 2: Update safe target
        - Interval 3: Process accumulated attestations

        Args:
            has_proposal: Whether a proposal exists for this interval.
        """
        self.time += Uint64(1)
        current_interval = self.time % INTERVALS_PER_SLOT

        if current_interval == Uint64(0):
            # Start of slot - process attestations if proposal exists
            if has_proposal:
                self.accept_new_attestations()
        elif current_interval == Uint64(1):
            # Validator attesting interval - no action
            pass
        elif current_interval == Uint64(2):
            # Update safe target for next attestations
            self.update_safe_target()
        else:
            # End of slot - process accumulated attestations
            self.accept_new_attestations()

    def accept_new_attestations(self) -> None:
        """
        Process pending attestations and update forkchoice head.

        Moves attestations from latest_new_attestations to latest_known_attestations and triggers
        head update.
        """
        # Move all new attestations to known attestations
        for validator_id, signed_attestation in self.latest_new_attestations.items():
            self.latest_known_attestations[validator_id] = signed_attestation

        # Clear pending attestations and update head
        self.latest_new_attestations.clear()
        self.update_head()

    def update_safe_target(self) -> None:
        """
        Update the safe target for attestations.

        Computes target that has sufficient (2/3+ majority) attestation support.
        """
        # Get validator count from head state
        head_state = self.states[self.head]
        num_validators = head_state.validators.count

        # Calculate 2/3 majority threshold (ceiling division)
        min_target_score = -(-num_validators * 2 // 3)

        # Find head with minimum attestation threshold
        safe_target = get_fork_choice_head(
            self.blocks,
            self.latest_justified.root,
            self.latest_new_attestations,
            min_score=min_target_score,
        )
        self.safe_target = safe_target

    def get_proposal_head(self, slot: Slot) -> Bytes32:
        """
        Get the head for block proposal at given slot.

        Ensures store is up-to-date and processes any pending attestations.

        Args:
            slot: Slot for which to get proposal head.

        Returns:
            Root of block to build upon.
        """
        slot_time = self.config.genesis_time + slot * SECONDS_PER_SLOT

        # Tick store to current time (no-op if already current)
        self.advance_time(slot_time, True)

        # Process any pending attestations (no-op if already processed)
        self.accept_new_attestations()

        return self.head

    def get_attestation_target(self) -> Checkpoint:
        """
        Calculate target checkpoint for validator attestations.

        Determines appropriate attestation target based on head, safe target,
        and finalization constraints.

        Returns:
            Target checkpoint for attestation.
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

    def produce_block_with_signatures(
        self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> tuple[Block, list[Bytes4000]]:
        """
        Produce a block and attestation signatures for the target slot.

        The proposer returns the block and a naive signature list so it can
        later craft its `SignedBlockWithAttestation` with minimal extra work.

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
        # Get parent block and state to build upon
        head_root = self.get_proposal_head(slot)
        head_state = self.states[head_root]

        # Validate proposer authorization for this slot
        num_validators = Uint64(head_state.validators.count)
        if not is_proposer(validator_index, slot, num_validators):
            msg = f"Validator {validator_index} is not the proposer for slot {slot}"
            raise AssertionError(msg)

        # Initialize empty attestation set for iterative collection
        attestations: list[Attestation] = []
        signatures: list[Bytes4000] = []

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
                body=BlockBody(attestations=Attestations(data=attestations)),
            )

            # Apply state transition to get the post-block state
            # First advance state to target slot, then process the block
            advanced_state = head_state.process_slots(slot)
            post_state = advanced_state.process_block(candidate_block)

            # Find new valid attestations matching post-state justification
            new_attestations: list[Attestation] = []
            new_signatures: list[Bytes4000] = []
            for signed_attestation in self.latest_known_attestations.values():
                # Skip if target block is unknown in our store
                data = signed_attestation.message.data
                if data.head.root not in self.blocks:
                    continue

                # Skip if attestation source does not match post-state's latest justified
                if data.source != post_state.latest_justified:
                    continue

                if signed_attestation.message not in attestations:
                    new_attestations.append(signed_attestation.message)
                    new_signatures.append(signed_attestation.signature)

            # Fixed point reached: no new attestations found
            if not new_attestations:
                break

            # Add new attestations and continue iteration
            attestations.extend(new_attestations)
            signatures.extend(new_signatures)

        # Create final block with all collected attestations
        final_state = head_state.process_slots(slot)
        final_block = Block(
            slot=slot,
            proposer_index=validator_index,
            parent_root=head_root,
            state_root=Bytes32.zero(),  # Will be updated with computed hash
            body=BlockBody(attestations=Attestations(data=attestations)),
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

        return finalized_block, signatures

    def produce_attestation(
        self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> Attestation:
        """
        Produce an attestation for the given slot and validator.

        This method constructs an Attestation object according to the lean protocol
        specification for attestation. The attestation represents the
        validator's view of the chain state and their choice for the
        next justified checkpoint.

        The algorithm:
        1. Get the current head
        2. Calculate the appropriate attestation target using current forkchoice state
        3. Use the store's latest justified checkpoint as the attestation source
        4. Construct and return the complete Attestation object

        Args:
            slot: The slot for which to produce the attestation.
            validator_index: The validator index producing the attestation.

        Returns:
            A fully constructed Attestation object ready for signing and broadcast.
        """
        # Get the head block the validator sees for this slot
        head_root = self.head
        head_checkpoint = Checkpoint(
            root=head_root,
            slot=self.blocks[head_root].slot,
        )

        # Calculate the target checkpoint for this attestation
        #
        # This uses the store's current forkchoice state to determine
        # the appropriate attestation target
        target_checkpoint = self.get_attestation_target()

        attestation_data = AttestationData(
            slot=slot,
            head=head_checkpoint,
            target=target_checkpoint,
            source=self.latest_justified,
        )

        # Create the attestation using current forkchoice state
        return Attestation(
            validator_id=validator_index,
            data=attestation_data,
        )
