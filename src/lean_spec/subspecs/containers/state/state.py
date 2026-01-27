"""State Container for the Lean Ethereum consensus specification."""

from typing import AbstractSet, Iterable

from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import (
    AggregatedSignatureProof,
    SignatureKey,
)
from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.types import (
    ZERO_HASH,
    Boolean,
    Bytes32,
    Container,
    Uint64,
)

from ..attestation import AggregatedAttestation, AggregationBits, Attestation
from ..block import Block, BlockBody, BlockHeader
from ..block.types import AggregatedAttestations
from ..checkpoint import Checkpoint
from ..config import Config
from ..slot import Slot
from ..validator import ValidatorIndex
from .types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Validators,
)
from ...chain.config import ATTESTATION_COMMITTEE_COUNT


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
            attestation_subnet_count=ATTESTATION_COMMITTEE_COUNT,
        )

        # Build the genesis block header for the state.
        genesis_header = BlockHeader(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(BlockBody(attestations=AggregatedAttestations(data=[]))),
        )

        # Assemble and return the full genesis state.
        return cls(
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
        assert block.proposer_index.is_proposer_for(
            slot=self.slot,
            num_validators=len(self.validators),
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
        new_justified_slots_data = self.justified_slots.extend_to_slot(
            self.latest_finalized.slot,
            last_materialized_slot,
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
                "historical_block_hashes": new_historical_hashes_data,
                "justified_slots": new_justified_slots_data,
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
            If block contains duplicate aggregated attestations with no unique participant.
        """
        # First process the block header.
        state = self.process_block_header(block)

        return state.process_attestations(block.body.attestations)

    def process_attestations(
        self,
        attestations: Iterable[AggregatedAttestation],
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
        attestations : Iterable[AggregatedAttestation]
            The aggregated attestations to process.

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
        assert not any(root == ZERO_HASH for root in self.justifications_roots), (
            "zero hash is not allowed in justifications roots"
        )
        justifications = (
            {
                root: self.justifications_validators[
                    i * len(self.validators) : (i + 1) * len(self.validators)
                ]
                for i, root in enumerate(self.justifications_roots)
            }
            if self.justifications_roots
            else {}
        )

        # Track state changes to be applied at the end
        latest_justified = self.latest_justified
        latest_finalized = self.latest_finalized
        finalized_slot = latest_finalized.slot
        justified_slots = self.justified_slots

        # Map roots to their latest slot for pruning.
        #
        # Votes for zero hash are ignored, so we only need the most recent slot
        # where a root appears to decide whether it is still unfinalized.
        start_slot = int(finalized_slot) + 1
        root_to_slot: dict[Bytes32, Slot] = {}
        for i in range(start_slot, len(self.historical_block_hashes)):
            root = self.historical_block_hashes[i]
            slot = Slot(i)
            if root not in root_to_slot or slot > root_to_slot[root]:
                root_to_slot[root] = slot

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
            if not justified_slots.is_slot_justified(finalized_slot, source.slot):
                continue

            # Ignore votes for targets that have already reached consensus
            #
            # If a block is already justified, additional votes do not change anything.
            # We simply skip them.
            if justified_slots.is_slot_justified(finalized_slot, target.slot):
                continue

            # Ignore votes that reference zero-hash slots.
            if source.root == ZERO_HASH or target.root == ZERO_HASH:
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
                or target.root != self.historical_block_hashes[target.slot]
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
                justifications[target.root] = [Boolean(False)] * len(self.validators)

            # Mark that each validator in this aggregation has voted for the target.
            #
            # A vote is represented as a boolean flag.
            # If it was previously absent, flip it to True.
            for validator_id in attestation.aggregation_bits.to_validator_indices():
                if not justifications[target.root][validator_id]:
                    justifications[target.root][validator_id] = Boolean(True)

            # Check whether the vote count crosses the supermajority threshold
            #
            # A block becomes justified when more than two-thirds of validators
            # have voted for it.
            #
            # We compare integers to avoid floating-point division:
            #
            # 3 * (number of votes) ≥ 2 * (total validators)
            count = sum(bool(justified) for justified in justifications[target.root])

            if 3 * count >= (2 * len(self.validators)):
                # The block becomes justified
                #
                # The chain now considers this block part of its safe head.
                latest_justified = target
                justified_slots = justified_slots.with_justified(
                    finalized_slot,
                    target.slot,
                    Boolean(True),
                )

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
                        justified_slots = justified_slots.shift_window(delta)
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

        # Construct and return the updated state
        return self.model_copy(
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
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        attestations: list[Attestation] | None = None,
        available_attestations: Iterable[Attestation] | None = None,
        known_block_roots: AbstractSet[Bytes32] | None = None,
        gossip_signatures: dict[SignatureKey, "Signature"] | None = None,
        aggregated_payloads: dict[SignatureKey, list[AggregatedSignatureProof]] | None = None,
    ) -> tuple[Block, "State", list[AggregatedAttestation], list[AggregatedSignatureProof]]:
        """
        Build a valid block on top of this state.

        Computes the post-state and creates a block with the correct state root.

        If `available_attestations` and `known_block_roots` are provided,
        performs fixed-point attestation collection: iteratively adds valid
        attestations until no more can be included. This is necessary because
        processing attestations may update the justified checkpoint, which may
        make additional attestations valid.

        Signatures are looked up from the provided signature maps using
        (validator_id, attestation_data_root) as the key.

        Args:
            slot: Target slot for the block.
            proposer_index: Validator index of the proposer.
            parent_root: Root of the parent block.
            attestations: Initial attestations to include.
            available_attestations: Pool of attestations to collect from.
            known_block_roots: Set of known block roots for attestation validation.
            gossip_signatures: Per-validator XMSS signatures learned from gossip.
            aggregated_payloads: Aggregated signature payloads learned from blocks.

        Returns:
            Tuple of (Block, post-State, collected attestations, signatures).
        """
        # Initialize empty attestation set for iterative collection.
        attestations = list(attestations or [])

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
                    attestations=AggregatedAttestations(
                        data=AggregatedAttestation.aggregate_by_data(attestations)
                    )
                ),
            )

            # Apply state transition to get the post-block state
            post_state = self.process_slots(slot).process_block(candidate_block)

            # No attestation source provided: done after computing post_state
            if available_attestations is None or known_block_roots is None:
                break

            # Find new valid attestations matching post-state justification
            new_attestations: list[Attestation] = []

            for attestation in available_attestations:
                data = attestation.data
                validator_id = attestation.validator_id
                data_root = data.data_root_bytes()
                sig_key = SignatureKey(validator_id, data_root)

                # Skip if target block is unknown
                if data.head.root not in known_block_roots:
                    continue

                # Skip if attestation source does not match post-state's latest justified
                if data.source != post_state.latest_justified:
                    continue

                # Avoid adding duplicates of attestations already in the candidate set
                if attestation in attestations:
                    continue

                # We can only include an attestation if we have some way to later provide
                # an aggregated proof for its group:
                # - either a per validator XMSS signature from gossip, or
                # - at least one aggregated proof learned from a block that references
                #   this validator+data.
                has_gossip_sig = bool(gossip_signatures and sig_key in gossip_signatures)
                has_block_proof = bool(aggregated_payloads and sig_key in aggregated_payloads)

                if has_gossip_sig or has_block_proof:
                    new_attestations.append(attestation)

            # Fixed point reached: no new attestations found
            if not new_attestations:
                break

            # Add new attestations and continue iteration
            attestations.extend(new_attestations)

        # Select aggregated attestations and proofs for the final block
        aggregated_attestations, aggregated_signatures = self.select_aggregated_proofs(
            attestations,
            aggregated_payloads,
        )

        # Create the final block with aggregated attestations and proofs
        final_block = Block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=BlockBody(
                attestations=AggregatedAttestations(
                    data=aggregated_attestations,
                ),
            ),
        )

        # Recompute state from the final block
        post_state = self.process_slots(slot).process_block(final_block)

        final_block = final_block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return final_block, post_state, aggregated_attestations, aggregated_signatures

    def aggregate_gossip_signatures(
        self,
        attestations: list[Attestation],
        gossip_signatures: dict[SignatureKey, "Signature"] | None = None,
    ) -> list[tuple[AggregatedAttestation, AggregatedSignatureProof]]:
        """
        Collect aggregated signatures from gossip network and aggregate them.

        For each attestation group, attempt to collect individual XMSS signatures
        from the gossip network. These are fresh signatures that validators
        broadcast when they attest.

        Parameters
        ----------
        attestations : list[Attestation]
            Individual attestations to aggregate and sign.
        gossip_signatures : dict[SignatureKey, Signature] | None
            Per-validator XMSS signatures learned from the gossip network.

        Returns:
        -------
        list[tuple[AggregatedAttestation, AggregatedSignatureProof]]
            - List of (attestation, proof) pairs from gossip collection.
        """
        results: list[tuple[AggregatedAttestation, AggregatedSignatureProof]] = []

        # Group individual attestations by data
        #
        # Multiple validators may attest to the same data (slot, head, target, source).
        # We aggregate them into groups so each group can share a single proof.
        for aggregated in AggregatedAttestation.aggregate_by_data(attestations):
            # Extract the common attestation data and its hash.
            #
            # All validators in this group signed the same message (the data root).
            data = aggregated.data
            data_root = data.data_root_bytes()

            # Get the list of validators who attested to this data.
            validator_ids = aggregated.aggregation_bits.to_validator_indices()

            # When a validator creates an attestation, it broadcasts the
            # individual XMSS signature over the gossip network. If we have
            # received these signatures, we can aggregate them ourselves.
            #
            # This is the preferred path: fresh signatures from the network.

            # Parallel lists for signatures, public keys, and validator IDs.
            gossip_sigs: list[Signature] = []
            gossip_keys: list[PublicKey] = []
            gossip_ids: list[ValidatorIndex] = []

            # Track validators we couldn't find signatures for.
            #
            # These will need to be covered by Phase 2 (existing proofs).
            remaining: set[ValidatorIndex] = set()

            # Attempt to collect each validator's signature from gossip.
            #
            # Signatures are keyed by (validator ID, data root).
            # - If a signature exists, we add it to our collection.
            if gossip_signatures:
                for vid in validator_ids:
                    key = SignatureKey(vid, data_root)
                    if (sig := gossip_signatures.get(key)) is not None:
                        # Found a signature: collect it along with the public key.
                        gossip_sigs.append(sig)
                        gossip_keys.append(self.validators[vid].get_pubkey())
                        gossip_ids.append(vid)

            # If we collected any gossip signatures, aggregate them into a proof.
            #
            # The aggregation combines multiple XMSS signatures into a single
            # compact proof that can verify all participants signed the message.
            if gossip_ids:
                participants = AggregationBits.from_validator_indices(gossip_ids)
                proof = AggregatedSignatureProof.aggregate(
                    participants=participants,
                    public_keys=gossip_keys,
                    signatures=gossip_sigs,
                    message=data_root,
                    epoch=data.slot,
                )
                attestation = AggregatedAttestation(aggregation_bits=participants, data=data)
                results.append((attestation, proof))

        return results

    def select_aggregated_proofs(
        self,
        attestations: list[Attestation],
        aggregated_payloads: dict[SignatureKey, list[AggregatedSignatureProof]] | None = None,
    ) -> tuple[list[AggregatedAttestation], list[AggregatedSignatureProof]]:
        """
        Select aggregated proofs for a set of attestations.

        This method selects aggregated proofs from aggregated_payloads,
        prioritizing proofs from the most recent blocks.

        Strategy:
        1. For each attestation group, aggregate as many signatures as possible
           from the most recent block's proofs.
        2. If remaining validators exist after step 1, include proofs from
           previous blocks that cover them.

        Parameters:
        ----------
        attestations : list[Attestation]
            Individual attestations to aggregate and sign.
        aggregated_payloads : dict[SignatureKey, list[AggregatedSignatureProof]] | None
            Aggregated proofs learned from previously-seen blocks.
            The list for each key should be ordered with most recent proofs first.

        Returns:
        -------
        tuple[list[AggregatedAttestation], list[AggregatedSignatureProof]]
            Paired attestations and their corresponding proofs.
        """
        results: list[tuple[AggregatedAttestation, AggregatedSignatureProof]] = []

        # Group individual attestations by data
        for aggregated in AggregatedAttestation.aggregate_by_data(attestations):
            data = aggregated.data
            data_root = data.data_root_bytes()
            validator_ids = aggregated.aggregation_bits.to_validator_indices() # validators contributed to this attestation

            # Validators that are missing in the current aggregation are put into remaining.
            remaining: set[Uint64] = set(validator_ids)

            # Fallback to existing proofs
            #
            # Some validators may not have broadcast their signatures over gossip,
            # but we might have seen proofs for them in previously-received blocks.
            #
            # Example scenario:
            #
            #   - We need signatures from validators {0, 1, 2, 3, 4}.
            #   - Gossip gave us signatures for {0, 1}.
            #   - Remaining: {2, 3, 4}.
            #   - From old blocks, we have:
            #       • Proof A covering {2, 3}
            #       • Proof B covering {3, 4}
            #       • Proof C covering {4}
            #
            # We want to cover {2, 3, 4} with as few proofs as possible.
            # A greedy approach: always pick the proof with the largest overlap.
            #
            #   - Iteration 1: Proof A covers {2, 3} (2 validators). Pick it.
            #                  Remaining: {4}.
            #   - Iteration 2: Proof B covers {4} (1 validator). Pick it.
            #                  Remaining: {} → done.
            #
            # Result: 2 proofs instead of 3.

            while remaining and aggregated_payloads:
                # Step 1: Find candidate proofs for a remaining validator.
                #
                # Proofs are indexed by (validator ID, data root). We pick any
                # validator still in the remaining set and look up proofs that
                # include them.
                target_id = next(iter(remaining))
                candidates = aggregated_payloads.get(SignatureKey(target_id, data_root), [])

                # No proofs found for this validator.
                # Remove it and try another validator.
                if not candidates:
                    remaining.discard(target_id)
                    continue

                # Step 2: Pick the proof covering the most remaining validators.
                #
                # At each step, we select the single proof that eliminates the highest
                # number of *currently missing* validators from our list.
                #
                # The 'score' of a candidate proof is defined as the size of the
                # intersection between:
                #   A. The validators inside the proof (`p.participants`)
                #   B. The validators we still need (`remaining`)
                #
                # Example:
                #   Remaining needed : {Alice, Bob, Charlie}
                #   Proof 1 covers   : {Alice, Dave}         -> Score: 1 (Only Alice counts)
                #   Proof 2 covers   : {Bob, Charlie, Eve}   -> Score: 2 (Bob & Charlie count)
                #   -> Result: We pick Proof 2 because it has the highest score.
                best, covered = max(
                    ((p, set(p.participants.to_validator_indices())) for p in candidates),
                    # Calculate the intersection size (A ∩ B) for every candidate.
                    key=lambda pair: len(pair[1] & remaining),
                )

                # Guard: If the best proof has zero overlap with remaining, stop.
                if covered.isdisjoint(remaining):
                    break

                # Step 3: Record the proof and remove covered validators.
                #
                # TODO: We don't support recursive aggregation yet.
                # In the future, we should be able to aggregate the proofs into a single proof.
                results.append(
                    (
                        AggregatedAttestation(aggregation_bits=best.participants, data=data),
                        best,
                    )
                )
                remaining -= covered

        # Final Assembly
        if not results:
            return [], []

        # Unzip the results into parallel lists.
        aggregated_attestations, aggregated_proofs = zip(*results, strict=True)
        return list(aggregated_attestations), list(aggregated_proofs)

