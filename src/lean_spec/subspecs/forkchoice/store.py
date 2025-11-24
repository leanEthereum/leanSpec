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

from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    JUSTIFICATION_LOOKBACK_SLOTS,
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
    Signature,
    SignedAttestation,
    SignedBlockWithAttestation,
    State,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import (
    Bytes32,
    Uint64,
    ValidatorIndex,
    is_proposer,
)
from lean_spec.types.container import Container

from .helpers import get_fork_choice_head


class Store(Container):
    """
    Forkchoice store tracking chain state and validator attestations.

    This is the "local view" that a node uses to run LMD GHOST. It contains:

    - which blocks and states are known,
    - which checkpoints are justified and finalized,
    - which block is currently considered the head,
    - and, for each validator, their latest attestation that should influence fork choice.

    The `Store` is updated whenever:
    - a new block is processed,
    - an attestation is received (via a block or gossip),
    - an interval tick occurs (activating new attestations),
    - or when the head is recomputed.
    """

    time: Uint64
    """Current time in intervals since genesis."""

    config: Config
    """Chain configuration parameters."""

    head: Bytes32
    """
    Root of the current canonical chain head block.

    This is the result of running the fork choice algorithm on the current contents of the `Store`.
    """

    safe_target: Bytes32
    """
    Root of the current safe target for attestation.

    This can be used by higher-level logic to restrict which blocks are
    considered safe to attest to, based on additional safety conditions.
    """

    latest_justified: Checkpoint
    """
    Highest slot justified checkpoint known to the store.

    LMD GHOST starts from this checkpoint when computing the head.

    Only descendants of this checkpoint are considered viable.
    """

    latest_finalized: Checkpoint
    """
    Highest slot finalized checkpoint known to the store.

    Everything strictly before this checkpoint can be considered immutable.

    Fork choice will never revert finalized history.
    """

    blocks: Dict[Bytes32, Block] = {}
    """
    Mapping from block root to Block objects.

    This is the set of blocks that the node currently knows about.

    Every block that might participate in fork choice must appear here.
    """

    states: Dict[Bytes32, State] = {}
    """
    Mapping from state root to State objects.

    For each known block, we keep its post-state.

    These states carry justified and finalized checkpoints that we use to update the
    `Store`'s latest justified and latest finalized checkpoints.
    """

    latest_known_attestations: Dict[ValidatorIndex, SignedAttestation] = {}
    """
    Latest signed attestations by validator that have been processed.

    - These attestations are "known" and contribute to fork choice weights.
    - Keyed by validator index to enforce one attestation per validator.
    """

    latest_new_attestations: Dict[ValidatorIndex, SignedAttestation] = {}
    """
    Latest signed attestations by validator that are pending processing.

    - These attestations are "new" and do not yet contribute to fork choice.
    - They migrate to `latest_known_attestations` via interval ticks.
    - Keyed by validator index to enforce one attestation per validator.
    """

    @classmethod
    def get_forkchoice_store(cls, state: State, anchor_block: Block) -> "Store":
        """
        Initialize forkchoice store from an anchor state and block.

        The anchor block and its state form the starting point for fork choice.
        We treat this anchor as both justified and finalized.

        Args:
            state:
                The trusted post-state corresponding to the anchor block.
            anchor_block:
                The trusted block acting as the initial chain root.

        Returns:
            A new Store instance, ready to accept blocks and attestations.

        Raises:
            AssertionError:
                If the anchor block's state root does not match the hash
                of the provided state.
        """
        # Compute the SSZ root of the given state.
        #
        # This is the canonical hash that should appear in the block's state root.
        computed_state_root = hash_tree_root(state)

        # Check that the block actually points to this state.
        #
        # If this fails, the caller has supplied inconsistent inputs.
        assert anchor_block.state_root == computed_state_root, (
            "Anchor block state root must match anchor state hash"
        )

        # Compute the SSZ root of the anchor block itself.
        #
        # This root will be used as:
        # - the key in the blocks/states maps,
        # - the initial head,
        # - the root of the initial checkpoints.
        anchor_root = hash_tree_root(anchor_block)

        # Read the slot at which the anchor block was proposed.
        anchor_slot = anchor_block.slot

        # Build an initial checkpoint using the anchor block.
        #
        # Both the root and the slot come directly from the anchor.
        anchor_checkpoint = Checkpoint(root=anchor_root, slot=anchor_slot)

        return cls(
            time=Uint64(anchor_slot * SECONDS_PER_SLOT),
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

        Ensures the vote respects the basic laws of time and topology:
            1. The blocks voted for must exist in our store.
            2. A vote cannot span backwards in time (source > target).
            3. A vote cannot be for a future slot.

        Args:
            signed_attestation: Attestation to validate.

        Raises:
            AssertionError: If attestation fails validation.
        """
        data = signed_attestation.message.data

        # Availability Check
        #
        # We cannot count a vote if we haven't seen the blocks involved.
        assert data.source.root in self.blocks, f"Unknown source block: {data.source.root.hex()}"
        assert data.target.root in self.blocks, f"Unknown target block: {data.target.root.hex()}"
        assert data.head.root in self.blocks, f"Unknown head block: {data.head.root.hex()}"

        # Topology Check
        #
        # History is linear and monotonic. Source must be older than Target.
        assert data.source.slot <= data.target.slot, "Source checkpoint slot must not exceed target"

        # Consistency Check
        #
        # Validate checkpoint slots match block slots
        source_block = self.blocks[data.source.root]
        target_block = self.blocks[data.target.root]
        assert source_block.slot == data.source.slot, "Source checkpoint slot mismatch"
        assert target_block.slot == data.target.slot, "Target checkpoint slot mismatch"

        # Time Check
        #
        # Validate attestation is not too far in the future
        # We allow a small margin for clock disparity (1 slot), but no further.
        current_slot = Slot(self.time // SECONDS_PER_SLOT)
        assert data.slot <= current_slot + Slot(1), "Attestation too far in future"

    def on_attestation(
        self,
        signed_attestation: SignedAttestation,
        is_from_block: bool = False,
    ) -> "Store":
        """
        Process a new attestation and place it into the correct attestation stage.

        Attestations can come from:
        - a block body (on-chain, `is_from_block=True`), or
        - the gossip network (off-chain, `is_from_block=False`).

        The Attestation Pipeline
        -------------------------
        Attestations always live in exactly one of two dictionaries:

        Stage 1: latest new attestations
            - Holds *pending* attestations that are not yet counted in fork choice.
            - Includes the proposer's attestation for the block they just produced.
            - Await activation by an interval tick before they influence weights.

        Stage 2: latest known attestations
            - Contains all *active* attestations used by LMD-GHOST.
            - Updated during interval ticks, which promote new → known.
            - Directly contributes to fork-choice subtree weights.

        Key Behaviors
        --------------
        Migration:
            - Attestations always move forward (new → known), never backwards.

        Superseding:
            - For each validator, only the attestation from the highest slot is kept.
            - A newer attestation overwrites an older one in either dictionary.

        Accumulation:
            - Attestations from different validators accumulate independently.
            - Only same-validator comparisons result in replacement.

        Args:
            signed_attestation:
                The attestation message to ingest.
            is_from_block:
                - True if embedded in a block body (on-chain),
                - False if from gossip.

        Returns:
            A new Store with updated attestation sets.
        """
        # First, ensure the attestation is structurally and temporally valid.
        self.validate_attestation(signed_attestation)

        # Extract the validator index that produced this attestation.
        validator_id = ValidatorIndex(signed_attestation.message.validator_id)

        # Extract the attestation's slot:
        # - used to decide if this attestation is "newer" than a previous one.
        attestation_slot = signed_attestation.message.data.slot

        # Copy the known attestation map:
        # - we build a new Store immutably,
        # - changes are applied on this local copy.
        new_known = self.latest_known_attestations

        # Copy the new attestation map:
        # - holds pending attestations that are not yet active.
        new_new = self.latest_new_attestations

        if is_from_block:
            # On-chain attestation processing
            #
            # These are historical attestations from other validators included by the proposer.
            # - They are processed immediately as "known" attestations,
            # - They contribute to fork choice weights.

            # Fetch the currently known attestation for this validator, if any.
            latest_known = new_known.get(validator_id)

            # Update the known attestation for this validator if:
            # - there is no known attestation yet, or
            # - this attestation is from a later slot than the known one.
            if latest_known is None or latest_known.message.data.slot < attestation_slot:
                new_known[validator_id] = signed_attestation

            # Fetch any pending ("new") attestation for this validator.
            existing_new = new_new.get(validator_id)

            # Remove the pending attestation if:
            # - it exists, and
            # - it is from an equal or earlier slot than this on-chain attestation.
            #
            # In that case, the on-chain attestation supersedes it.
            if existing_new is not None and existing_new.message.data.slot <= attestation_slot:
                del new_new[validator_id]
        else:
            # Network gossip attestation processing
            #
            # These are attestations received via the gossip network.
            # - They enter the "new" stage,
            # - They must wait for interval tick acceptance before
            #   contributing to fork choice weights.

            # Convert Store time to slots to check for "future" attestations.
            time_slots = self.time // SECONDS_PER_SLOT

            # Reject the attestation if:
            # - its slot is strictly greater than our current slot.
            assert attestation_slot <= time_slots, "Attestation from future slot"

            # Fetch the previously stored "new" attestation for this validator.
            latest_new = new_new.get(validator_id)

            # Update the pending attestation for this validator if:
            # - there is no pending attestation yet, or
            # - this one is from a later slot than the pending one.
            if latest_new is None or latest_new.message.data.slot < attestation_slot:
                new_new[validator_id] = signed_attestation

        # Return a new Store with updated "known" and "new" attestation maps.
        return self.model_copy(
            update={
                "latest_known_attestations": new_known,
                "latest_new_attestations": new_new,
            }
        )

    def on_block(self, signed_block_with_attestation: SignedBlockWithAttestation) -> "Store":
        """
        Process a new block and update the forkchoice state.

        This method integrates a block into the forkchoice store by:
        1. Validating the block's parent exists
        2. Computing the post-state via the state transition function
        3. Processing attestations included in the block body (on-chain)
        4. Updating the forkchoice head
        5. Processing the proposer's attestation (as if gossiped)

        Algorithm Overview
        ------------------
        The key insight is that blocks contain two types of attestations:

        **Block Body Attestations** (processed as on-chain):
            - These are attestations from other validators included by the proposer
            - They are historical and have already influenced prior fork choice
            - Processed immediately as "known" attestations

        **Proposer Attestation** (processed as gossip):
            - The proposer's attestation for their own block
            - Cast during interval 1 (after block proposal in interval 0)
            - Should NOT influence this block's fork choice position
            - Treated as pending until interval 3 (end of slot)
            - Will be included in a future block

        This separation ensures:
        - The proposer's attestation doesn't create circular weight
        - Fork choice head is computed before counting proposer attestation
        - The attestation is available for the next block producer

        Args:
            signed_block_with_attestation: Complete signed block with proposer attestation.

        Returns:
            New Store with block integrated and head updated.

        Raises:
            AssertionError: If parent block/state not found in store.
        """
        # Unpack block components
        block = signed_block_with_attestation.message.block
        proposer_attestation = signed_block_with_attestation.message.proposer_attestation
        signatures = signed_block_with_attestation.signature
        block_root = hash_tree_root(block)

        # Skip duplicate blocks (idempotent operation)
        if block_root in self.blocks:
            return self

        # Verify parent chain is available
        #
        # The parent state must exist before processing this block.
        # If missing, the node must sync the parent chain first.
        parent_state = self.states.get(block.parent_root)
        assert parent_state is not None, (
            f"Parent state not found (root={block.parent_root.hex()}). "
            f"Sync parent chain before processing block at slot {block.slot}."
        )

        # Validate cryptographic signatures
        valid_signatures = signed_block_with_attestation.verify_signatures(parent_state)

        # Execute state transition function to compute post-block state
        post_state = copy.deepcopy(parent_state).state_transition(block, valid_signatures)

        # Create new store with block and state
        store = self.model_copy(
            update={
                "blocks": self.blocks | {block_root: block},
                "states": self.states | {block_root: post_state},
            }
        )

        # Process block body attestations
        #
        # Iterate over attestations and their corresponding signatures.
        for attestation, signature in zip(
            signed_block_with_attestation.message.block.body.attestations,
            signed_block_with_attestation.signature,
            strict=False,
        ):
            # Process as on-chain attestation (immediately becomes "known")
            store = store.on_attestation(
                signed_attestation=SignedAttestation(
                    message=attestation,
                    signature=signature,
                ),
                is_from_block=True,
            )

        # Update forkchoice head based on new block and attestations
        #
        # IMPORTANT: This must happen BEFORE processing proposer attestation
        # to prevent the proposer from gaining circular weight advantage.
        store = store.update_head()

        # Process proposer attestation as if received via gossip
        #
        # The proposer casts their attestation in interval 1, after block
        # proposal. This attestation should:
        # 1. NOT affect this block's fork choice position (processed as "new")
        # 2. Be available for inclusion in future blocks
        # 3. Influence fork choice only after interval 3 (end of slot)
        store = store.on_attestation(
            signed_attestation=SignedAttestation(
                message=proposer_attestation,
                signature=signatures[len(block.body.attestations)],
            ),
            is_from_block=False,
        )

        return store

    def update_head(self) -> "Store":
        """
        Compute updated store with new canonical head.

        This method implements the core fork choice algorithm, selecting the canonical
        chain head based on:
        1. Latest justified checkpoint (from state analysis)
        2. LMD-GHOST fork choice rule (heaviest subtree)
        3. Finalization status (from head state)

        Algorithm
        ---------
        1. **Justification**: Scan all states to find highest justified checkpoint
        2. **Fork Choice**: Run LMD-GHOST from justified root using attestation weights
        3. **Finalization**: Extract finalized checkpoint from selected head state
        4. **Return**: New Store instance with updated checkpoints and head

        Returns:
            New Store with updated head, latest_justified, and latest_finalized.

        """
        # Find the Latest Justified Checkpoint
        #
        # We must first determine the anchor point for our fork choice algorithm.
        # This anchor is the justified checkpoint (a block root and slot) with the
        # highest slot number known across *all* known states.
        #
        # We find this by:
        # a) Scanning all known states.
        # b) Finding the state that contains the justified checkpoint with the
        #    highest slot number.
        # c) Extracting that specific checkpoint object to use as our anchor.
        #
        # If there are no states to scan (e.g., at initialization), the
        # operation would fail. In this case, we fall back to using the
        # store's currently recorded justified checkpoint, preserving the
        # last known good anchor.
        latest_justified = (
            max(self.states.values(), key=lambda s: s.latest_justified.slot).latest_justified
            if self.states
            else self.latest_justified
        )

        # Run LMD-GHOST fork choice algorithm
        #
        # Selects canonical head by walking the tree from the justified root,
        # choosing the heaviest child at each fork based on attestation weights.
        new_head = get_fork_choice_head(
            self.blocks,
            latest_justified.root,
            self.latest_known_attestations,
        )

        # Extract finalized checkpoint from head state
        #
        # The head state tracks the highest finalized checkpoint. If the
        # head changed, we may have a new finalized checkpoint.
        #
        # Fallback to current finalized if head state unavailable (defensive).
        latest_finalized = (
            self.states[new_head].latest_finalized
            if new_head in self.states
            else self.latest_finalized
        )

        # Return new Store instance with updated values (immutable update)
        return self.model_copy(
            update={
                "head": new_head,
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
            }
        )

    def accept_new_attestations(self) -> "Store":
        """
        Process pending attestations and update forkchoice head.

        Moves attestations from latest_new_attestations to latest_known_attestations,
        making them eligible to contribute to fork choice weights. This migration
        happens at specific interval ticks.

        The Interval Tick System
        -------------------------
        Attestations progress through intervals:
        - Interval 0: Block proposal
        - Interval 1: Validators cast attestations (enter "new")
        - Interval 2: Safe target update
        - Interval 3: Attestations accepted (move to "known")

        This staged progression ensures proper timing and prevents premature
        influence on fork choice decisions.

        Returns:
            New Store with migrated attestations and updated head.
        """
        # Create store with migrated attestations
        store = self.model_copy(
            update={
                "latest_known_attestations": self.latest_known_attestations
                | self.latest_new_attestations,
                "latest_new_attestations": {},
            }
        )

        # Update head with newly accepted attestations
        return store.update_head()

    def update_safe_target(self) -> "Store":
        """
        Update the safe target for attestations.

        Computes target that has sufficient (2/3+ majority) attestation support.
        The safe target represents a block with enough attestation weight to be
        considered "safe" for validators to attest to.

        Algorithm
        ---------
        1. Get validator count from head state
        2. Calculate 2/3 majority threshold (ceiling division)
        3. Run fork choice with minimum score requirement
        4. Return new Store with updated safe_target

        Returns:
            New Store with updated safe_target.
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

        return self.model_copy(update={"safe_target": safe_target})

    def tick_interval(self, has_proposal: bool) -> "Store":
        """
        Advance store time by one interval and perform interval-specific actions.

        Different actions are performed based on interval within slot:
        - Interval 0: Process attestations if proposal exists
        - Interval 1: Validator attesting period (no action)
        - Interval 2: Update safe target
        - Interval 3: Process accumulated attestations

        The Four-Interval System
        -------------------------
        Each slot is divided into 4 intervals:

        **Interval 0 (Block Proposal)**:
            - Block proposer publishes their block
            - If proposal exists, immediately accept new attestations
            - This ensures validators see the block before attesting

        **Interval 1 (Validator Attesting)**:
            - Validators create and gossip attestations
            - No store action (waiting for attestations to arrive)

        **Interval 2 (Safe Target Update)**:
            - Compute safe target with 2/3+ majority
            - Provides validators with a stable attestation target

        **Interval 3 (Attestation Acceptance)**:
            - Accept accumulated attestations (new → known)
            - Update head based on new attestation weights
            - Prepare for next slot

        Args:
            has_proposal: Whether a proposal exists for this interval.

        Returns:
            New Store with advanced time and interval-specific updates applied.
        """
        # Advance time by one interval
        store = self.model_copy(update={"time": self.time + Uint64(1)})
        current_interval = store.time % SECONDS_PER_SLOT % INTERVALS_PER_SLOT

        if current_interval == Uint64(0):
            # Start of slot - process attestations if proposal exists
            if has_proposal:
                store = store.accept_new_attestations()
        elif current_interval == Uint64(2):
            # Mid-slot - update safe target for validators
            store = store.update_safe_target()
        elif current_interval == Uint64(3):
            # End of slot - accept accumulated attestations
            store = store.accept_new_attestations()

        return store

    def on_tick(self, time: Uint64, has_proposal: bool) -> "Store":
        """
        Advance forkchoice store time to given timestamp.

        Ticks store forward interval by interval, performing appropriate
        actions for each interval type. This method handles time progression
        incrementally to ensure all interval-specific actions are performed.

        Args:
            time: Target time in seconds since genesis.
            has_proposal: Whether node has proposal for current slot.

        Returns:
            New Store with time advanced and all interval actions performed.

        Example:
            >>> # Advance from slot 0 to slot 5
            >>> slot_5_time = config.genesis_time + 5 * SECONDS_PER_SLOT
            >>> store = store.on_tick(slot_5_time, has_proposal=True)
        """
        # Calculate target time in intervals
        tick_interval_time = (time - self.config.genesis_time) // SECONDS_PER_INTERVAL

        # Tick forward one interval at a time
        store = self
        while store.time < tick_interval_time:
            # Check if proposal should be signaled for next interval
            should_signal_proposal = has_proposal and (store.time + Uint64(1)) == tick_interval_time

            # Advance by one interval with appropriate signaling
            store = store.tick_interval(should_signal_proposal)

        return store

    def get_proposal_head(self, slot: Slot) -> tuple["Store", Bytes32]:
        """
        Get the head for block proposal at given slot.

        Ensures store is up-to-date and processes any pending attestations
        before returning the canonical head. This guarantees the proposer
        builds on the most recent view of the chain.

        Algorithm
        ---------
        1. Calculate slot time from slot number
        2. Advance store time to current slot (ticking intervals)
        3. Accept any pending attestations
        4. Return updated store and head root

        Args:
            slot: Slot for which to get proposal head.

        Returns:
            Tuple of (new Store with updated time, head root for building).
        """
        # Calculate time corresponding to this slot
        slot_time = self.config.genesis_time + slot * SECONDS_PER_SLOT

        # Advance time to current slot (ticking intervals)
        store = self.on_tick(slot_time, True)

        # Process any pending attestations before proposal
        store = store.accept_new_attestations()

        return store, store.head

    def get_attestation_target(self) -> Checkpoint:
        """
        Calculate target checkpoint for validator attestations.

        Determines appropriate attestation target based on head, safe target,
        and finalization constraints. The target selection algorithm balances
        between advancing the chain head and maintaining safety guarantees.

        Attestation Target Algorithm
        -----------------------------
        The algorithm walks back from the current head toward the safe target,
        ensuring the target is in a justifiable slot range:

        1. **Start at Head**: Begin with the current head block
        2. **Walk Toward Safe**: Move backward (up to `JUSTIFICATION_LOOKBACK_SLOTS` steps)
           if safe target is newer
        3. **Ensure Justifiable**: Continue walking back until slot is justifiable
        4. **Return Checkpoint**: Create checkpoint from selected block

        Justifiability Rules (see Slot.is_justifiable_after)
        ------------------------------------------------------
        A slot is justifiable at distance delta from finalization if:
        1. delta ≤ 5 (first 5 slots always justifiable)
        2. delta is a perfect square (1, 4, 9, 16, 25, ...)
        3. delta is a pronic number (2, 6, 12, 20, 30, ...)

        These rules prevent long-range attacks by restricting which checkpoints
        validators can attest to relative to finalization.

        Returns:
            Target checkpoint for attestation.
        """
        # Start from current head
        target_block_root = self.head

        # Walk back toward safe target (up to `JUSTIFICATION_LOOKBACK_SLOTS` steps)
        #
        # This ensures the target doesn't advance too far ahead of safe target,
        # providing a balance between liveness and safety.
        for _ in range(JUSTIFICATION_LOOKBACK_SLOTS):
            if self.blocks[target_block_root].slot > self.blocks[self.safe_target].slot:
                target_block_root = self.blocks[target_block_root].parent_root

        # Ensure target is in justifiable slot range
        #
        # Walk back until we find a slot that satisfies justifiability rules
        # relative to the latest finalized checkpoint.
        while not self.blocks[target_block_root].slot.is_justifiable_after(
            self.latest_finalized.slot
        ):
            target_block_root = self.blocks[target_block_root].parent_root

        # Create checkpoint from selected target block
        target_block = self.blocks[target_block_root]
        return Checkpoint(root=hash_tree_root(target_block), slot=target_block.slot)

    def produce_block_with_signatures(
        self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> tuple["Store", Block, list[Signature]]:
        """
        Produce a block and attestation signatures for the target slot.

        The proposer returns the block and a naive signature list so it can
        later craft its `SignedBlockWithAttestation` with minimal extra work.

        Algorithm Overview
        ------------------
        1. **Validate Authorization**: Verify proposer is authorized for slot
        2. **Get Proposal Head**: Retrieve current chain head as parent
        3. **Iteratively Build Attestation Set**:
           - Create candidate block with current attestations
           - Apply state transition (slot advancement + block processing)
           - Find new valid attestations matching post-state requirements
           - Continue until no new attestations can be added (fixed point)
        4. **Finalize Block**: Compute state root and store block

        The Fixed-Point Algorithm
        --------------------------
        Attestations are collected iteratively because:
        - Block processing updates the justified checkpoint
        - Some attestations only become valid after this update
        - We repeat until no new valid attestations are found

        This ensures the block includes the maximal valid attestation set,
        maximizing the block's contribution to chain consensus.

        Args:
            slot: Target slot number for block production.
            validator_index: Index of validator authorized to propose this block.

        Returns:
            Tuple of (new Store with block stored, finalized Block, signature list).

        Raises:
            AssertionError: If validator lacks proposer authorization for slot.
        """
        # Get parent block and state to build upon
        store, head_root = self.get_proposal_head(slot)
        head_state = store.states[head_root]

        # Validate proposer authorization for this slot
        num_validators = Uint64(head_state.validators.count)
        assert is_proposer(validator_index, slot, num_validators), (
            f"Validator {validator_index} is not the proposer for slot {slot}"
        )

        # Initialize empty attestation set for iterative collection
        attestations: list[Attestation] = []
        signatures: list[Signature] = []

        # Iteratively collect valid attestations using fixed-point algorithm
        #
        # Continue until no new attestations can be added to the block.
        # This ensures we include the maximal valid attestation set.
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
            new_signatures: list[Signature] = []

            for signed_attestation in store.latest_known_attestations.values():
                data = signed_attestation.message.data

                # Skip if target block is unknown in our store
                if data.head.root not in store.blocks:
                    continue

                # Skip if attestation source does not match post-state's latest justified
                if data.source != post_state.latest_justified:
                    continue

                # Add attestation if not already included
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

        # Store block and state immutably
        block_hash = hash_tree_root(finalized_block)
        store = store.model_copy(
            update={
                "blocks": {**store.blocks, block_hash: finalized_block},
                "states": {**store.states, block_hash: final_post_state},
            }
        )

        return store, finalized_block, signatures

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
        head_checkpoint = Checkpoint(
            root=self.head,
            slot=self.blocks[self.head].slot,
        )

        # Calculate the target checkpoint for this attestation
        #
        # This uses the store's current forkchoice state to determine
        # the appropriate attestation target, balancing between head
        # advancement and safety guarantees.
        target_checkpoint = self.get_attestation_target()

        # Construct attestation data
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
