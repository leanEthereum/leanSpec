"""State Container for the Lean Ethereum consensus specification."""

from typing import TYPE_CHECKING, AbstractSet, Iterable

from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import (
    ZERO_HASH,
    Boolean,
    Bytes32,
    Container,
    Uint64,
    is_proposer,
)

from ..attestation import (
    Attestation,
    SignedAttestation,
    aggregate_attestations_by_data,
    aggregated_attestations_to_plain,
)

if TYPE_CHECKING:
    from lean_spec.subspecs.xmss.containers import Signature
from ..block import Block, BlockBody, BlockHeader
from ..block.types import AggregatedAttestationsList
from ..checkpoint import Checkpoint
from ..config import Config
from ..slot import Slot
from .types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Validators,
)


class State(Container):
    """The main consensus state object."""

    # Configuration
    config: Config
    """The chain's configuration parameters."""

    # Slot and block tracking
    slot: Slot
    """The current slot number."""

    latest_block_header: BlockHeader
    """The header of the most recent block."""

    # Checkpoints
    latest_justified: Checkpoint
    """The latest justified checkpoint."""

    latest_finalized: Checkpoint
    """The latest finalized checkpoint."""

    # Historical data
    historical_block_hashes: HistoricalBlockHashes
    """A list of historical block root hashes."""

    justified_slots: JustifiedSlots
    """A bitfield indicating which historical slots were justified."""

    validators: Validators
    """Registry of validators tracked by the state."""

    # Justification tracking (flattened for SSZ compatibility)
    justifications_roots: JustificationRoots
    """Roots of justified blocks."""

    justifications_validators: JustificationValidators
    """A bitlist of validators who participated in justifications."""

    @classmethod
    def generate_genesis(cls, genesis_time: Uint64, validators: Validators) -> "State":
        """
        Generate a genesis state with empty history and proper initial values.

        Parameters
        ----------
        genesis_time : Uint64
            The genesis timestamp.
        validators : Validators
            The list of validators in the genesis state.

        Returns:
        -------
        State
            A properly initialized genesis state.
        """
        # Configure the genesis state.
        genesis_config = Config(
            genesis_time=genesis_time,
        )

        # Build the genesis block header for the state.
        genesis_header = BlockHeader(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(BlockBody(attestations=AggregatedAttestationsList(data=[]))),
        )

        # Assemble and return the full genesis state.
        return cls(
            config=genesis_config,
            slot=Slot(0),
            latest_block_header=genesis_header,
            latest_justified=Checkpoint.default(),
            latest_finalized=Checkpoint.default(),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=validators,
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        )

    def process_slots(self, target_slot: Slot) -> "State":
        """
        Advance the state through empty slots up to, but not including, target_slot.

        The loop:
          - Performs per-slot maintenance (e.g., state root caching).
          - Increments the slot counter after each call.
        The function returns a new state with slot == target_slot.

        Parameters
        ----------
        target_slot : Slot
            The slot to reach by processing empty slots.

        Returns:
        -------
        State
            A new state that has progressed to target_slot.

        Raises:
        ------
        AssertionError
            If target_slot is not in the future.
        """
        # The target must be strictly greater than the current slot.
        assert self.slot < target_slot, "Target slot must be in the future"

        # Work on a local variable. Do not mutate self.
        state = self

        # Step through each missing slot:
        while state.slot < target_slot:
            # Per-Slot Housekeeping & Slot Increment
            #
            # This single statement performs two tasks for each empty slot
            # in a single, immutable update:
            #
            # 1. State Root Caching (Conditional):
            #    It checks if the latest block header has an empty state root.
            #    This is true only for the *first* empty slot immediately
            #    following a block.
            #
            #    - If it is empty, we must cache the pre-block state root
            #    (the hash of the state *before* this slot increment) into that
            #    header. We do this by:
            #    a) Computing the root of the current (pre-block) state.
            #    b) Creating a *new* header object with this computed state root
            #       to be included in the update.
            #
            #    - If the state root is *not* empty, it means we are in a
            #    sequence of empty slots, and we simply use the existing header.
            #
            # 2. Slot Increment:
            #    It always increments the slot number by one.
            state = state.model_copy(
                update={
                    "latest_block_header": (
                        state.latest_block_header.model_copy(
                            update={"state_root": hash_tree_root(state)}
                        )
                        if state.latest_block_header.state_root == Bytes32.zero()
                        else state.latest_block_header
                    ),
                    "slot": Slot(state.slot + Slot(1)),
                }
            )

        # Reached the target slot. Return the advanced state.
        return state

    def process_block_header(self, block: Block) -> "State":
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

        Parameters
        ----------
        block : Block
            The block whose header is being processed.

        Returns:
        -------
        State
            A new state with header-related fields updated.

        Raises:
        ------
        AssertionError
            If any header check fails.
        """
        # Validation
        #
        # - Retrieve the header of the previous block (the parent).
        # - Compute the parent root hash.
        parent_header = self.latest_block_header
        parent_root = hash_tree_root(parent_header)

        # Consensus checks

        # Verify the block corresponds to the current state slot.
        #
        # To move to this slot, we have processed any intermediate slots before.
        assert block.slot == self.slot, "Block slot mismatch"

        # The block must be newer than the current latest header.
        assert block.slot > parent_header.slot, "Block is older than latest header"

        # Verify the block proposer.
        #
        # Ensures the block was proposed by the assigned validator for this round.
        assert is_proposer(
            validator_index=block.proposer_index,
            slot=self.slot,
            num_validators=Uint64(self.validators.count),
        ), "Incorrect block proposer"

        # Verify the chain link.
        #
        # The block must cryptographically point to the known parent.
        assert block.parent_root == parent_root, "Block parent root mismatch"

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
            new_latest_justified = self.latest_justified.model_copy(update={"root": parent_root})
            new_latest_finalized = self.latest_finalized.model_copy(update={"root": parent_root})
        else:
            new_latest_justified = self.latest_justified
            new_latest_finalized = self.latest_finalized

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
        new_historical_hashes_data = (
            self.historical_block_hashes + [parent_root] + [ZERO_HASH] * num_empty_slots
        )

        # Update the list of justified slot flags.
        #
        # Structure: [Existing flags] + [Is genesis parent?] + [False for gaps]
        #
        # We construct the new history list by concatenating three segments:
        #
        # 1. The existing history:
        #    We preserve the flags for all previously processed blocks.
        #
        # 2. The parent block status (one entry):
        #    We append the status of the block immediately preceding any gaps.
        #    - If Genesis: True (Justified by definition).
        #    - If Normal: False (Pending). It remains unjustified until validators
        #      vote for it later in the process.
        #
        # 3. The skipped slots status (multiple entries):
        #    We append False for every empty slot between the parent and the
        #    current block. Since no blocks exist there, they are permanently
        #    unjustified.
        new_justified_slots_data = (
            self.justified_slots + [Boolean(is_genesis_parent)] + [Boolean(False)] * num_empty_slots
        )

        # Construct the new latest block header.
        #
        # The new header object represents the tip of the chain.
        #
        # Leave state root empty.
        # It is not computed until the block body is fully processed or the next slot begins.
        new_header = BlockHeader(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            body_root=hash_tree_root(block.body),
            state_root=Bytes32.zero(),
        )

        # Final Immutable Copy
        #
        # Return a new immutable state instance.
        # All calculated updates are applied atomically here.
        return self.model_copy(
            update={
                "latest_justified": new_latest_justified,
                "latest_finalized": new_latest_finalized,
                "historical_block_hashes": HistoricalBlockHashes(data=new_historical_hashes_data),
                "justified_slots": JustifiedSlots(data=new_justified_slots_data),
                "latest_block_header": new_header,
            }
        )

    def process_block(self, block: Block) -> "State":
        """
        Apply full block processing including header and body.

        Parameters
        ----------
        block : Block
            The block to process.

        Returns:
        -------
        State
            A new state with the processed block.

        Raises:
        ------
        AssertionError
            If block contains duplicate AttestationData.
        """
        # First process the block header.
        state = self.process_block_header(block)

        # Process justification attestations by converting aggregated payloads
        attestations: list[Attestation] = []
        attestations_data = set()
        for aggregated_att in block.body.attestations:
            # No partial aggregation is allowed.
            if aggregated_att.data in attestations_data:
                raise AssertionError("Block contains duplicate AttestationData")

            attestations_data.add(aggregated_att.data)
            attestations.extend(aggregated_attestations_to_plain(aggregated_att))

        return state.process_attestations(attestations)

    def process_attestations(
        self,
        attestations: Iterable[Attestation],
    ) -> "State":
        """
        Apply attestations and update justification/finalization
        according to the Lean Consensus 3SF-mini rules.

        This simplified consensus mechanism:
        1. Processes each attestation
        2. Updates justified status for target checkpoints
        3. Applies finalization rules based on justified status

        Parameters
        ----------
        attestations : Iterable[Attestation]
            The attestations to process.

        Returns:
        -------
        State
            A new state with updated justification/finalization.
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
        justifications = (
            {
                root: self.justifications_validators[
                    i * self.validators.count : (i + 1) * self.validators.count
                ]
                for i, root in enumerate(self.justifications_roots)
            }
            if self.justifications_roots
            else {}
        )

        # Track state changes to be applied at the end
        latest_justified = self.latest_justified
        latest_finalized = self.latest_finalized
        justified_slots = self.justified_slots

        # Process each attestation independently
        #
        # Every attestation is a claim:
        #
        # "I vote to extend the chain from SOURCE to TARGET."
        #
        # The rules below filter out invalid or irrelevant votes.
        for attestation in attestations:
            source = attestation.data.source
            target = attestation.data.target

            # Check that the source is already trusted
            #
            # A vote may only originate from a point in history that is already justified.
            # A source that lacks existing justification cannot be used to anchor a new vote.
            if not justified_slots[source.slot]:
                continue

            # Ignore votes for targets that have already reached consensus
            #
            # If a block is already justified, additional votes do not change anything.
            # We simply skip them.
            if justified_slots[target.slot]:
                continue

            # Ensure the vote refers to blocks that actually exist on our chain
            #
            # The attestation must match our canonical chain.
            # Both the source root and target root must equal the recorded block roots
            # stored for those slots in history.
            #
            # This prevents votes about unknown or conflicting forks.
            if (
                source.root != self.historical_block_hashes[source.slot]
                and target.root != self.historical_block_hashes[target.slot]
            ):
                continue

            # Ensure time flows forward
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
            if not target.slot.is_justifiable_after(self.latest_finalized.slot):
                continue

            # Record the vote
            #
            # If this is the first vote for the target block, create a fresh tally sheet:
            # - one boolean per validator, all initially False.
            if target.root not in justifications:
                justifications[target.root] = [Boolean(False)] * self.validators.count

            # Mark that this validator has voted for the target.
            #
            # A vote is represented as a boolean flag.
            # If it was previously absent, flip it to True.
            if not justifications[target.root][attestation.validator_id]:
                justifications[target.root][attestation.validator_id] = Boolean(True)

            # Check whether the vote count crosses the supermajority threshold
            #
            # A block becomes justified when more than two-thirds of validators
            # have voted for it.
            #
            # We compare integers to avoid floating-point division:
            #
            # 3 * (number of votes) ≥ 2 * (total validators)
            count = sum(bool(justified) for justified in justifications[target.root])

            if 3 * count >= (2 * self.validators.count):
                # The block becomes justified
                #
                # The chain now considers this block part of its safe head.
                latest_justified = target
                justified_slots[target.slot] = True

                # There is no longer any need to track individual votes for this block.
                del justifications[target.root]

                # Consider whether finalization can advance
                #
                # Finalization requires a continuous chain of trust from the
                # previously finalized checkpoint up to the new justified point.
                #
                # If every slot in between is justifiable relative to the old
                # finalized point, then the earlier source checkpoint becomes finalized.
                #
                # In short:
                #
                #     If there is no break in the chain, advance finalization.
                if not any(
                    Slot(slot).is_justifiable_after(self.latest_finalized.slot)
                    for slot in range(source.slot + Slot(1), target.slot)
                ):
                    latest_finalized = source

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

        # Construct and return the updated state
        return self.model_copy(
            update={
                "justifications_roots": JustificationRoots(data=sorted_roots),
                "justifications_validators": JustificationValidators(
                    data=[vote for root in sorted_roots for vote in justifications[root]]
                ),
                "justified_slots": JustifiedSlots(data=justified_slots),
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
            }
        )

    def state_transition(self, block: Block, valid_signatures: bool = True) -> "State":
        """
        Apply the complete state transition function for a block.

        This method represents the full state transition function:
        1. Validate signatures if required
        2. Process slots up to the block's slot
        3. Process the block header and body
        4. Validate the computed state root

        Parameters
        ----------
        block : Block
            The block to apply to the state.
        valid_signatures : bool, optional
            Whether to validate block signatures. Defaults to True.

        Returns:
        -------
        State
            A new state after applying the block.

        Raises:
        ------
        AssertionError
            If signature validation fails or state root is invalid.
        """
        # Validate signatures if required
        if not valid_signatures:
            raise AssertionError("Block signatures must be valid")

        # First, process any intermediate slots.
        state = self.process_slots(block.slot)

        # Process the block itself.
        new_state = state.process_block(block)

        # Validate that the block's state root matches the computed state
        computed_state_root = hash_tree_root(new_state)
        if block.state_root != computed_state_root:
            raise AssertionError("Invalid block state root")

        return new_state

    def build_block(
        self,
        slot: Slot,
        proposer_index: Uint64,
        parent_root: Bytes32,
        attestations: list[Attestation] | None = None,
        available_signed_attestations: Iterable[SignedAttestation] | None = None,
        known_block_roots: AbstractSet[Bytes32] | None = None,
    ) -> tuple[Block, "State", list[Attestation], list["Signature"]]:
        """
        Build a valid block on top of this state.

        Computes the post-state and creates a block with the correct state root.

        If `available_signed_attestations` and `known_block_roots` are provided,
        performs fixed-point attestation collection: iteratively adds valid
        attestations until no more can be included. This is necessary because
        processing attestations may update the justified checkpoint, which may
        make additional attestations valid.

        Args:
            slot: Target slot for the block.
            proposer_index: Validator index of the proposer.
            parent_root: Root of the parent block.
            attestations: Initial attestations to include.
            available_signed_attestations: Pool of attestations to collect from.
            known_block_roots: Set of known block roots for attestation validation.

        Returns:
            Tuple of (Block, post-State, collected attestations, signatures).
        """
        # Initialize empty attestation set for iterative collection
        attestations = list(attestations or [])
        signatures: list[Signature] = []

        # Iteratively collect valid attestations using fixed-point algorithm
        #
        # Continue until no new attestations can be added to the block.
        # This ensures we include the maximal valid attestation set.
        while True:
            # Create candidate block with current attestation set
            candidate_block = Block(
                slot=slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=Bytes32.zero(),
                body=BlockBody(
                    attestations=AggregatedAttestationsList(
                        data=aggregate_attestations_by_data(attestations)
                    )
                ),
            )

            # Apply state transition to get the post-block state
            post_state = self.process_slots(slot).process_block(candidate_block)

            # No attestation source provided: done after computing post_state
            if available_signed_attestations is None or known_block_roots is None:
                break

            # Find new valid attestations matching post-state justification
            new_attestations: list[Attestation] = []
            new_signatures: list[Signature] = []

            for signed_attestation in available_signed_attestations:
                data = signed_attestation.message
                attestation = Attestation(
                    validator_id=signed_attestation.validator_id,
                    data=data,
                )

                # Skip if target block is unknown
                if data.head.root not in known_block_roots:
                    continue

                # Skip if attestation source does not match post-state's latest justified
                if data.source != post_state.latest_justified:
                    continue

                # Add attestation if not already included
                if attestation not in attestations:
                    new_attestations.append(attestation)
                    new_signatures.append(signed_attestation.signature)

            # Fixed point reached: no new attestations found
            if not new_attestations:
                break

            # Add new attestations and continue iteration
            attestations.extend(new_attestations)
            signatures.extend(new_signatures)

        # Sort attestations and signatures by validator_id to ensure
        # consistent ordering for signature validation.
        # Only sort if we have signatures (i.e., attestation collection was performed)
        if signatures:
            attestations_with_sigs = sorted(
                zip(attestations, signatures, strict=True), key=lambda x: x[0].validator_id
            )
            sorted_attestations = [att for att, _ in attestations_with_sigs]
            sorted_signatures = [sig for _, sig in attestations_with_sigs]
        else:
            sorted_attestations = attestations
            sorted_signatures = signatures

        # Store the post state root in the block
        final_block = candidate_block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return final_block, post_state, sorted_attestations, sorted_signatures
