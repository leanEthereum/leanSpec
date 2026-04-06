"""State Container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Set as AbstractSet
from typing import TYPE_CHECKING

from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import (
    ZERO_HASH,
    Boolean,
    Bytes32,
    Container,
    Uint64,
)

from ..attestation import AggregatedAttestation, AggregationBits, AttestationData
from ..block import Block, BlockBody, BlockHeader
from ..block.types import AggregatedAttestations
from ..checkpoint import Checkpoint
from ..config import Config
from ..slot import Slot
from ..validator import ValidatorIndex, ValidatorIndices
from .types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Validators,
)

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice import AttestationSignatureEntry


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
    def generate_genesis(cls, genesis_time: Uint64, validators: Validators) -> State:
        """
        Generate a genesis state with empty history and proper initial values.

        Args:
            genesis_time: The genesis timestamp.
            validators: The list of validators in the genesis state.

        Returns:
            A properly initialized genesis state.
        """
        # Configure the genesis state.
        genesis_config = Config(
            genesis_time=genesis_time,
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

    def process_slots(self, target_slot: Slot) -> State:
        """
        Advance the state through empty slots up to, but not including, target_slot.

        The loop:
          - Performs per-slot maintenance (e.g., state root caching).
          - Increments the slot counter after each call.
        The function returns a new state with slot == target_slot.

        Args:
            target_slot: The slot to reach by processing empty slots.

        Returns:
            A new state that has progressed to target_slot.

        Raises:
            AssertionError: If target_slot is not in the future.
        """
        # The target must be strictly greater than the current slot.
        assert self.slot < target_slot, "Target slot must be in the future"

        # Work on a local variable. Do not mutate self.
        state = self

        # Step through each missing slot.
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
            needs_state_root = state.latest_block_header.state_root == Bytes32.zero()
            cached_state_root = (
                hash_tree_root(state) if needs_state_root else state.latest_block_header.state_root
            )

            state = state.model_copy(
                update={
                    "latest_block_header": (
                        state.latest_block_header.model_copy(
                            update={"state_root": cached_state_root}
                        )
                        if needs_state_root
                        else state.latest_block_header
                    ),
                    "slot": Slot(state.slot + Slot(1)),
                }
            )

        # Reached the target slot. Return the advanced state.
        return state

    def process_block_header(self, block: Block) -> State:
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

        Args:
            block: The block whose header is being processed.

        Returns:
            A new state with header-related fields updated.

        Raises:
            AssertionError: If any header check fails.
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
            num_validators=Uint64(len(self.validators)),
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

    def process_block(self, block: Block) -> State:
        """
        Apply full block processing including header and body.

        Args:
            block: The block to process.

        Returns:
            A new state with the processed block.

        Raises:
            AssertionError: If block contains duplicate aggregated attestations
                with no unique participant.
        """
        # First process the block header.
        state = self.process_block_header(block)

        return state.process_attestations(block.body.attestations)

    def process_attestations(
        self,
        attestations: Iterable[AggregatedAttestation],
    ) -> State:
        """
        Apply attestations and update justification/finalization
        according to the Lean Consensus 3SF-mini rules.

        This simplified consensus mechanism:
        1. Processes each attestation
        2. Updates justified status for target checkpoints
        3. Applies finalization rules based on justified status

        Args:
            attestations: The aggregated attestations to process.

        Returns:
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
            root_to_slot[self.historical_block_hashes[i]] = Slot(i)

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

            # Ignore votes that reference zero-hash slots.
            if source.root == ZERO_HASH or target.root == ZERO_HASH:
                continue

            # Ensure the vote refers to blocks that actually exist on our chain.
            #
            # The attestation must match our canonical chain.
            # Both the source root and target root must equal the recorded block roots
            # stored for those slots in history.
            #
            # This prevents votes about unknown or conflicting forks.
            source_slot_int = int(source.slot)
            target_slot_int = int(target.slot)
            source_matches = (
                source.root == self.historical_block_hashes[source_slot_int]
                if source_slot_int < len(self.historical_block_hashes)
                else False
            )
            target_matches = (
                target.root == self.historical_block_hashes[target_slot_int]
                if target_slot_int < len(self.historical_block_hashes)
                else False
            )

            if not source_matches or not target_matches:
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

            # Record the vote.
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

            # Check whether the vote count crosses the supermajority threshold.
            #
            # A block becomes justified when at least two-thirds of validators
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

    def state_transition(self, block: Block, valid_signatures: bool = True) -> State:
        """
        Apply the complete state transition function for a block.

        This method represents the full state transition function:
        1. Validate signatures if required
        2. Process slots up to the block's slot
        3. Process the block header and body
        4. Validate the computed state root

        Args:
            block: The block to apply to the state.
            valid_signatures: Whether to validate block signatures. Defaults to True.

        Returns:
            A new state after applying the block.

        Raises:
            AssertionError: If signature validation fails or state root is invalid.
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
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]] | None = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[AggregatedSignatureProof]]:
        """
        Build a valid block on top of this state.

        Computes the post-state and creates a block with the correct state root.

        Uses a fixed-point algorithm: finds attestation_data entries whose source
        matches the current justified checkpoint, greedily selects proofs maximizing
        new validator coverage, then applies the STF. If justification advances,
        repeats with the new checkpoint.

        Args:
            slot: Target slot for the block.
            proposer_index: Validator index of the proposer.
            parent_root: Root of the parent block.
            known_block_roots: Set of known block roots for attestation validation.
            aggregated_payloads: Aggregated signature payloads keyed by attestation data.

        Returns:
            Tuple of (Block, post-State, collected attestations, signatures).
        """
        aggregated_attestations: list[AggregatedAttestation] = []
        aggregated_signatures: list[AggregatedSignatureProof] = []

        if aggregated_payloads:
            # Fixed-point loop: find attestation_data entries matching the current
            # justified checkpoint and greedily select proofs. Processing attestations
            # may advance justification, unlocking more entries.
            # When building on top of genesis (slot 0), process_block_header
            # updates the justified root to parent_root. Apply the same
            # derivation here so attestation sources match.
            if self.latest_block_header.slot == Slot(0):
                current_justified = self.latest_justified.model_copy(update={"root": parent_root})
            else:
                current_justified = self.latest_justified

            processed_att_data: set[AttestationData] = set()

            while True:
                found_entries = False

                for att_data, proofs in sorted(
                    aggregated_payloads.items(), key=lambda item: item[0].target.slot
                ):
                    if att_data.head.root not in known_block_roots:
                        continue

                    if att_data.source != current_justified:
                        continue

                    if att_data in processed_att_data:
                        continue
                    processed_att_data.add(att_data)

                    found_entries = True

                    selected, _ = self._select_proofs_greedily(proofs)
                    aggregated_signatures.extend(selected)
                    for proof in selected:
                        aggregated_attestations.append(
                            AggregatedAttestation(
                                aggregation_bits=proof.participants,
                                data=att_data,
                            )
                        )

                if not found_entries:
                    break

                # Build candidate block and check if justification changed.
                candidate_block = Block(
                    slot=slot,
                    proposer_index=proposer_index,
                    parent_root=parent_root,
                    state_root=Bytes32.zero(),
                    body=BlockBody(
                        attestations=AggregatedAttestations(data=list(aggregated_attestations))
                    ),
                )
                post_state = self.process_slots(slot).process_block(candidate_block)

                if post_state.latest_justified != current_justified:
                    current_justified = post_state.latest_justified
                    continue

                break

            # Compact: merge all proofs sharing the same AttestationData into one
            # using recursive children aggregation.
            proof_groups: dict[AttestationData, list[AggregatedSignatureProof]] = {}
            for att, sig in zip(aggregated_attestations, aggregated_signatures, strict=True):
                proof_groups.setdefault(att.data, []).append(sig)

            compacted_attestations: list[AggregatedAttestation] = []
            compacted_signatures: list[AggregatedSignatureProof] = []
            for att_data, proofs in proof_groups.items():
                if len(proofs) == 1:
                    compacted_signatures.append(proofs[0])
                else:
                    children = [
                        (
                            proof,
                            [
                                self.validators[vid].get_attestation_pubkey()
                                for vid in proof.participants.to_validator_indices()
                            ],
                        )
                        for proof in proofs
                    ]
                    merged = AggregatedSignatureProof.aggregate(
                        xmss_participants=None,
                        children=children,
                        raw_xmss=[],
                        message=att_data.data_root_bytes(),
                        slot=att_data.slot,
                    )
                    compacted_signatures.append(merged)
                compacted_attestations.append(
                    AggregatedAttestation(
                        aggregation_bits=compacted_signatures[-1].participants,
                        data=att_data,
                    )
                )

            aggregated_attestations = compacted_attestations
            aggregated_signatures = compacted_signatures

        # Create the final block with selected attestations.
        final_block = Block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=BlockBody(
                attestations=AggregatedAttestations(data=aggregated_attestations),
            ),
        )

        # Recompute state from the final block.
        post_state = self.process_slots(slot).process_block(final_block)
        final_block = final_block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return final_block, post_state, aggregated_attestations, aggregated_signatures

    @staticmethod
    def _select_proofs_greedily(
        *proof_sets: set[AggregatedSignatureProof] | None,
    ) -> tuple[list[AggregatedSignatureProof], set[ValidatorIndex]]:
        """
        Greedy set-cover selection of signature proofs to maximize validator coverage.

        Repeatedly selects the proof covering the most uncovered validators until
        no proof adds new coverage. Earlier proof sets are prioritized.

        Args:
            proof_sets: Candidate proof sets in priority order.

        Returns:
            Selected proofs and the set of covered validator indices.
        """
        selected: list[AggregatedSignatureProof] = []
        covered: set[ValidatorIndex] = set()
        for proofs in proof_sets:
            if not proofs:
                continue
            remaining = list(proofs)
            while remaining:
                # Pick the proof that covers the most new validators.
                best = max(
                    remaining,
                    key=lambda p: len(set(p.participants.to_validator_indices()) - covered),
                )
                new_coverage = set(best.participants.to_validator_indices()) - covered
                # Stop when no proof in this set adds new coverage.
                if not new_coverage:
                    break
                selected.append(best)
                covered.update(new_coverage)
                remaining.remove(best)
        return selected, covered

    def aggregate(
        self,
        attestation_signatures: dict[AttestationData, set[AttestationSignatureEntry]] | None = None,
        new_payloads: dict[AttestationData, set[AggregatedSignatureProof]] | None = None,
        known_payloads: dict[AttestationData, set[AggregatedSignatureProof]] | None = None,
    ) -> list[tuple[AggregatedAttestation, AggregatedSignatureProof]]:
        """
        Aggregate gossip signatures using new payloads, with known payloads as helpers.

        Args:
            attestation_signatures: Raw XMSS signatures from gossip, keyed by attestation data.
            new_payloads: Aggregated proofs pending processing (child proofs).
            known_payloads: Known aggregated proofs already accepted.

        Returns:
            List of (attestation, proof) pairs from aggregation.
        """
        gossip_sigs = attestation_signatures or {}
        new = new_payloads or {}
        known = known_payloads or {}

        attestation_keys = new.keys() | gossip_sigs.keys()
        if not attestation_keys:
            return []

        results: list[tuple[AggregatedAttestation, AggregatedSignatureProof]] = []

        for data in attestation_keys:
            # Phase 1: Greedily select child proofs for maximum validator coverage.
            # New payloads are prioritized over known payloads.
            child_proofs, covered = self._select_proofs_greedily(new.get(data), known.get(data))

            # Phase 2: Collect raw XMSS signatures for validators not yet covered.
            # Sorted by validator index for deterministic output.
            raw_entries = [
                (
                    e.validator_id,
                    self.validators[e.validator_id].get_attestation_pubkey(),
                    e.signature,
                )
                for e in sorted(gossip_sigs.get(data, set()), key=lambda e: e.validator_id)
                if e.validator_id not in covered
            ]

            # Need at least one raw signature, or two child proofs to aggregate.
            if not raw_entries and len(child_proofs) < 2:
                continue

            xmss_participants = AggregationBits.from_validator_indices(
                ValidatorIndices(data=[vid for vid, _, _ in raw_entries])
            )
            raw_xmss = [(pk, sig) for _, pk, sig in raw_entries]

            # Phase 3: Build recursive children with their public keys from the registry.
            children = [
                (
                    child,
                    [
                        self.validators[vid].get_attestation_pubkey()
                        for vid in child.participants.to_validator_indices()
                    ],
                )
                for child in child_proofs
            ]
            proof = AggregatedSignatureProof.aggregate(
                xmss_participants=xmss_participants,
                children=children,
                raw_xmss=raw_xmss,
                message=data.data_root_bytes(),
                slot=data.slot,
            )
            attestation = AggregatedAttestation(aggregation_bits=proof.participants, data=data)
            results.append((attestation, proof))

        return results
