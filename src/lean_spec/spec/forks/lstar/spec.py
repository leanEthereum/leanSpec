"""Lstar fork — identity and construction facade."""

import copy
import math
from collections import defaultdict
from collections.abc import Iterable, Sequence, Set as AbstractSet
from typing import Any, ClassVar

from lean_spec.node.chain.clock import Interval
from lean_spec.node.chain.config import (
    GOSSIP_DISPARITY_INTERVALS,
    INTERVALS_PER_SLOT,
    JUSTIFICATION_LOOKBACK_SLOTS,
    MAX_ATTESTATIONS_DATA,
)
from lean_spec.node.observability import (
    observe_on_attestation,
    observe_on_block,
    observe_state_transition,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.crypto.xmss.interface import TARGET_SIGNATURE_SCHEME
from lean_spec.spec.forks.lstar.aggregation_select import select_greedily
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AggregationError,
    AttestationData,
    AttestationSignatureEntry,
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    SingleMessageAggregate,
    Slot,
    State,
    Store,
    ValidatorIndex,
    Validators,
)
from lean_spec.spec.ssz import ZERO_HASH, Boolean, Bytes32, SSZList, Uint8, Uint64

from ..protocol import ForkProtocol, SpecBlockType, SpecStateType

LstarStore = Store[State, Block]
"""Concrete Store specialization owned by the lstar fork."""


class LstarSpec(ForkProtocol):
    """Lstar fork."""

    NAME: ClassVar[str] = "lstar"
    VERSION: ClassVar[int] = 4
    GOSSIP_DIGEST: ClassVar[str] = "12345678"

    previous: ClassVar[type[ForkProtocol] | None] = None

    state_class: type[State] = State
    block_class: type[Block] = Block
    block_body_class: type[BlockBody] = BlockBody
    block_header_class: type[BlockHeader] = BlockHeader
    aggregated_attestations_class: type[AggregatedAttestations] = AggregatedAttestations
    store_class: type[Store[State, Block]] = LstarStore

    attestation_data_class: type[AttestationData] = AttestationData
    aggregated_attestation_class: type[AggregatedAttestation] = AggregatedAttestation

    config_class: type[Config] = Config

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
        genesis_config = self.config_class(
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
            AssertionError: If target_slot is not in the future.
        """
        # The target must be strictly greater than the current slot.
        assert state.slot < target_slot, "Target slot must be in the future"

        # Work on a copy so the caller's state is untouched.
        state = copy.deepcopy(state)

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

            if needs_state_root:
                state.latest_block_header.state_root = cached_state_root
            state.slot = Slot(state.slot + Slot(1))

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
            AssertionError: If any header check fails.
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
        assert block.slot == state.slot, "Block slot mismatch"

        # The block must be newer than the current latest header.
        assert block.slot > parent_header.slot, "Block is older than latest header"

        # Verify the block proposer.
        #
        # Ensures the block was proposed by the assigned validator for this round.
        assert block.proposer_index.is_proposer_for(
            slot=state.slot,
            num_validators=Uint64(len(state.validators)),
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
            state.latest_justified = Checkpoint(slot=state.latest_justified.slot, root=parent_root)
            state.latest_finalized = Checkpoint(slot=state.latest_finalized.slot, root=parent_root)

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
        state.historical_block_hashes = (
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
        state.justified_slots = state.justified_slots.extend_to_slot(
            state.latest_finalized.slot,
            last_materialized_slot,
        )

        # Construct the new latest block header.
        #
        # The new header object represents the tip of the chain.
        #
        # Leave state root empty.
        # It is not computed until the block body is fully processed or the next slot begins.
        state.latest_block_header = self.block_header_class(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            body_root=hash_tree_root(block.body),
            state_root=Bytes32.zero(),
        )

        return state

    def process_block(self, state: State, block: Block) -> State:
        """
        Apply full block processing including header and body.

        Raises:
            AssertionError: If block contains duplicate aggregated attestations
                with no unique participant.
        """
        # First process the block header.
        state = self.process_block_header(state, block)

        return self.process_attestations(state, block.body.attestations)

    @staticmethod
    def _attestation_data_matches_chain(
        attestation_data: AttestationData,
        historical_block_hashes: Sequence[Bytes32],
    ) -> bool:
        """Check that source and target checkpoints point to blocks on a chain.

        Args:
            attestation_data: The attestation being validated.
            historical_block_hashes: Chain view indexed by slot.
                Empty slots carry the zero hash.

        Returns:
            True when both checkpoint roots match the chain at their slot.
            False when either root is the zero hash.
            False when either checkpoint slot is past the end of the chain view.
        """
        # Reject zero-hash checkpoints up front.
        #
        # Empty slots carry the zero hash on the chain.
        # A vote whose recorded root equals the zero hash is meaningless.
        if attestation_data.source.root == ZERO_HASH or attestation_data.target.root == ZERO_HASH:
            return False

        # Reject checkpoints whose slot is beyond the chain view.
        #
        # Without this guard, indexed access raises IndexError.
        source_slot = int(attestation_data.source.slot)
        target_slot = int(attestation_data.target.slot)
        if source_slot >= len(historical_block_hashes):
            return False
        if target_slot >= len(historical_block_hashes):
            return False

        # Both checkpoint roots must match the chain at their slot.
        return (
            attestation_data.source.root == historical_block_hashes[source_slot]
            and attestation_data.target.root == historical_block_hashes[target_slot]
        )

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
        justifications = (
            {
                root: state.justifications_validators[
                    i * len(state.validators) : (i + 1) * len(state.validators)
                ]
                for i, root in enumerate(state.justifications_roots)
            }
            if state.justifications_roots
            else {}
        )

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
        root_to_slot: dict[Bytes32, Slot] = {}
        for i, root in enumerate(state.historical_block_hashes[start_slot:], start=start_slot):
            root_to_slot[root] = Slot(i)

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
            if not self._attestation_data_matches_chain(
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

            # Record the vote.
            #
            # If this is the first vote for the target block, create a fresh tally sheet:
            # - one boolean per validator, all initially False.
            if target.root not in justifications:
                justifications[target.root] = [Boolean(False)] * len(state.validators)

            # Mark that each validator in this aggregation has voted for the target.
            #
            # A vote is represented as a boolean flag.
            # If it was previously absent, flip it to True.
            for validator_index in attestation.aggregation_bits.to_validator_indices():
                if not justifications[target.root][validator_index]:
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

        # Apply the updated state
        state.justifications_roots = JustificationRoots(data=sorted_roots)
        state.justifications_validators = JustificationValidators(
            data=[vote for root in sorted_roots for vote in justifications[root]]
        )
        state.justified_slots = justified_slots
        state.latest_justified = latest_justified
        state.latest_finalized = latest_finalized
        return state

    def state_transition(
        self,
        state: State,
        block: Block,
        valid_signatures: bool = True,
    ) -> State:
        """
        Apply the complete state transition function for a block.

        This method represents the full state transition function:
        1. Validate signatures if required
        2. Process slots up to the block's slot
        3. Process the block header and body
        4. Validate the computed state root

        Raises:
            AssertionError: If signature validation fails or state root is invalid.
        """
        # Validate signatures if required
        if not valid_signatures:
            raise AssertionError("Block signatures must be valid")

        with observe_state_transition():
            # First, process any intermediate slots.
            advanced = self.process_slots(state, block.slot)

            # Process the block itself.
            new_state = self.process_block(advanced, block)

            # Validate that the block's state root matches the computed state
            computed_state_root = hash_tree_root(new_state)
            if block.state_root != computed_state_root:
                raise AssertionError("Invalid block state root")

        return new_state

    def build_block(
        self,
        state: State,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] | None = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[SingleMessageAggregate]]:
        """
        Build a valid block on top of the given pre-state.

        Computes the post-state and creates a block with the correct state root.

        Uses a fixed-point algorithm: finds attestation_data entries whose source
        matches the current justified checkpoint, greedily selects proofs maximizing
        new validator coverage, then applies the STF. If justification advances,
        repeats with the new checkpoint.
        """
        aggregated_attestations: list[AggregatedAttestation] = []
        aggregated_signatures: list[SingleMessageAggregate] = []

        if aggregated_payloads:
            # Fixed-point loop: find attestation_data entries matching the current
            # justified checkpoint and greedily select proofs. Processing attestations
            # may advance justification, unlocking more entries.
            # When building on top of genesis (slot 0), process_block_header
            # updates the justified root to parent_root. Apply the same
            # derivation here so attestation sources match.
            if state.latest_block_header.slot == Slot(0):
                current_justified = Checkpoint(slot=state.latest_justified.slot, root=parent_root)
            else:
                current_justified = state.latest_justified

            # Track the justified-slot bitfield to skip already-justified targets.
            #
            # Extend the bitfield to cover every slot we might query.
            # The range runs from the finalized boundary up to slot - 1 inclusive.
            current_finalized_slot = state.latest_finalized.slot
            current_justified_slots = state.justified_slots.extend_to_slot(
                current_finalized_slot, slot - Slot(1)
            )

            # Build the chain view as it will appear on the candidate block.
            #
            # The view is the recorded history up to the parent.
            # Then comes the parent root at the parent's slot.
            # Then zero-hash entries for any skipped slots up to the new block.
            # The chain-match helper uses this view to validate source and target roots.
            num_empty_slots = int(slot - state.latest_block_header.slot - Slot(1))
            extended_historical_block_hashes: list[Bytes32] = (
                list(state.historical_block_hashes) + [parent_root] + [ZERO_HASH] * num_empty_slots
            )

            processed_attestation_data: set[AttestationData] = set()

            while True:
                found_entries = False

                for attestation_data, proofs in sorted(
                    aggregated_payloads.items(), key=lambda item: item[0].target.slot
                ):
                    if attestation_data in processed_attestation_data:
                        continue

                    if Uint8(len(processed_attestation_data)) >= MAX_ATTESTATIONS_DATA:
                        break

                    if attestation_data.head.root not in known_block_roots:
                        continue

                    # Chain-match runs first.
                    #
                    # It rejects checkpoints whose slot is past the chain view.
                    # That prevents the bounded queries below from indexing out of range.
                    if not self._attestation_data_matches_chain(
                        attestation_data, extended_historical_block_hashes
                    ):
                        continue

                    # The source slot must already be justified on this chain.
                    if not current_justified_slots.is_slot_justified(
                        current_finalized_slot, attestation_data.source.slot
                    ):
                        continue

                    # Genesis-anchored votes have source.slot = target.slot = 0.
                    #
                    # They cannot advance justification: the state transition drops them.
                    # They still carry head-vote weight for fork choice.
                    # Including them in the body propagates them into peers' payload pool.
                    # The bypass below keeps them past the target-already-justified check,
                    # since slot 0 is implicitly justified and would otherwise filter them.
                    is_genesis_self_vote = attestation_data.source.slot == Slot(0) and (
                        attestation_data.target.slot == Slot(0)
                    )

                    # Skip attestations whose target slot is already justified.
                    #
                    # Justification adds nothing for them.
                    # Entries the state transition will later drop are still kept here.
                    # They carry head-vote weight for fork choice.
                    if not is_genesis_self_vote and current_justified_slots.is_slot_justified(
                        current_finalized_slot, attestation_data.target.slot
                    ):
                        continue

                    processed_attestation_data.add(attestation_data)

                    found_entries = True

                    selected, _ = select_greedily(proofs)
                    aggregated_signatures.extend(selected)
                    for proof in selected:
                        aggregated_attestations.append(
                            self.aggregated_attestation_class(
                                aggregation_bits=proof.participants,
                                data=attestation_data,
                            )
                        )

                if not found_entries:
                    break

                # Build candidate block and check if justification changed.
                candidate_block = self.block_class(
                    slot=slot,
                    proposer_index=proposer_index,
                    parent_root=parent_root,
                    state_root=Bytes32.zero(),
                    body=self.block_body_class(
                        attestations=self.aggregated_attestations_class(
                            data=list(aggregated_attestations)
                        )
                    ),
                )
                post_state = self.process_block(self.process_slots(state, slot), candidate_block)

                # Re-run the filter when justification or finalization advanced.
                #
                # Both quantities are monotonic in 3SF-mini, so the loop is bounded.
                # Finalization advancement shifts the justified window forward.
                # That can unlock attestations whose target slot was outside it before.
                if (
                    post_state.latest_justified != current_justified
                    or post_state.latest_finalized.slot != current_finalized_slot
                ):
                    current_justified = post_state.latest_justified
                    current_justified_slots = post_state.justified_slots
                    current_finalized_slot = post_state.latest_finalized.slot
                    continue

                break

            # Compact: merge all proofs sharing the same AttestationData into one
            # using recursive children aggregation.
            #
            # During the fixed-point loop above, multiple proofs may have been
            # selected for the same AttestationData across iterations. Group them
            # and merge each group into a single recursive proof.
            proof_groups: dict[AttestationData, list[SingleMessageAggregate]] = {}
            for attestation, signature in zip(
                aggregated_attestations, aggregated_signatures, strict=True
            ):
                proof_groups.setdefault(attestation.data, []).append(signature)

            aggregated_attestations = []
            aggregated_signatures = []
            for attestation_data, proofs in proof_groups.items():
                if len(proofs) == 1:
                    signature = proofs[0]
                else:
                    # Multiple proofs for the same data were aggregated separately.
                    # Merge them into one recursive proof using children-only
                    # aggregation (no new raw signatures).
                    children = [
                        (
                            proof,
                            [
                                state.validators[validator_index].get_attestation_public_key()
                                for validator_index in proof.participants.to_validator_indices()
                            ],
                        )
                        for proof in proofs
                    ]
                    signature = SingleMessageAggregate.aggregate(
                        children=children,
                        raw_xmss=[],
                        message=hash_tree_root(attestation_data),
                        slot=attestation_data.slot,
                    )
                aggregated_signatures.append(signature)
                aggregated_attestations.append(
                    self.aggregated_attestation_class(
                        aggregation_bits=signature.participants, data=attestation_data
                    )
                )

        # Create the final block with selected attestations.
        final_block = self.block_class(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=self.block_body_class(
                attestations=self.aggregated_attestations_class(data=aggregated_attestations),
            ),
        )

        # Recompute state from the final block.
        post_state = self.process_block(self.process_slots(state, slot), final_block)
        final_block.state_root = hash_tree_root(post_state)

        return final_block, post_state, aggregated_attestations, aggregated_signatures

    def verify_signatures(
        self,
        signed_block: SignedBlock,
        validators: Validators,
    ) -> bool:
        """
        Verify the merged multi-message aggregate proof carried by a signed block.

        The block envelope holds one multi-message aggregate proof binding
        every body attestation plus the proposer's signature over the
        block root.

        Args:
            signed_block: The signed block whose merged proof is checked.
            validators: Validator registry providing public keys for verification.

        Returns:
            True if the merged proof is valid.

        Raises:
            AssertionError: On any structural or cryptographic mismatch.
        """
        block = signed_block.block
        aggregated_attestations = block.body.attestations

        num_validators = Uint64(len(validators))
        public_keys_per_message: list[list[PublicKey]] = []

        # Each component is bound to the message and slot it signed.
        #
        # Without this binding a proposer could pair honest signatures
        # with attacker-chosen attestation data that resolves to the same
        # public_keys, crediting validators for votes they never cast.
        message_bindings: list[tuple[Bytes32, Slot]] = []

        # One public_key set per attestation, in body order.
        #
        # The attestation list and the proof component list are parallel.
        # Each attestation names the validators that voted for its data.
        # Its matching proof component proves those validators signed.
        for aggregated_attestation in aggregated_attestations:
            validator_indices = aggregated_attestation.aggregation_bits.to_validator_indices()
            for validator_index in validator_indices:
                assert validator_index.is_valid(num_validators), "Validator index out of range"

            public_keys_per_message.append(
                [
                    validators[validator_index].get_attestation_public_key()
                    for validator_index in validator_indices
                ]
            )
            message_bindings.append(
                (
                    hash_tree_root(aggregated_attestation.data),
                    aggregated_attestation.data.slot,
                )
            )

        # Final component: the proposer's signature over the block root.
        #
        # The proposer signs the block root with their proposal key.
        # This proves the proposer endorsed this specific block.
        # It is a single-participant entry, distinct from the vote entries.
        proposer_index = block.proposer_index
        assert proposer_index.is_valid(num_validators), "Proposer index out of range"

        public_keys_per_message.append([validators[proposer_index].get_proposal_public_key()])
        message_bindings.append((hash_tree_root(block), block.slot))

        try:
            signed_block.proof.verify(
                public_keys_per_message=public_keys_per_message,
                messages=message_bindings,
            )
        except AggregationError as exc:
            raise AssertionError(f"Block proof verification failed: {exc}") from exc

        return True

    # Pydantic fields don't structurally match Protocol @property in ty;
    # the concrete return is Liskov-safe (Store satisfies SpecStoreType structurally).
    def create_store(  # type: ignore[override]  # ty: ignore[invalid-method-override]
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_index: ValidatorIndex | None,
    ) -> LstarStore:
        """Initialize a forkchoice store from an anchor state and block.

        The anchor block and state form the starting point for fork choice.
        Both are treated as justified and finalized.

        Raises:
            AssertionError:
                If the anchor block's state root does not match the hash
                of the state.
        """
        assert isinstance(state, State)
        assert isinstance(anchor_block, Block)

        # Compute the SSZ root of this state.
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

        # Seed both checkpoints from the anchor block itself.
        #
        # The store treats the anchor as the new genesis for fork choice:
        # all history below it is pruned. The justified and finalized checkpoints
        # therefore point at the anchor block with the anchor's own slot,
        # regardless of what the anchor state's embedded checkpoints say.
        anchor_checkpoint = Checkpoint(root=anchor_root, slot=anchor_slot)

        return self.store_class(
            time=Interval.from_slot(anchor_slot),
            config=state.config,
            head=anchor_root,
            safe_target=anchor_root,
            latest_justified=anchor_checkpoint,
            latest_finalized=anchor_checkpoint,
            blocks={anchor_root: anchor_block},
            states={anchor_root: state},
            validator_index=validator_index,
        )

    def prune_stale_attestation_data(self, store: LstarStore) -> LstarStore:
        """Remove attestation data that can no longer influence fork choice.

        An attestation becomes stale when its target checkpoint falls at or before
        the finalized slot. Such attestations cannot affect chain selection since
        the target is already finalized.

        Pruning removes all attestation-related data:

        - Attestation signatures
        - Pending aggregated payloads
        - Processed aggregated payloads
        """
        # Filter out stale entries from all attestation-related mappings.
        #
        # Each mapping is keyed by attestation data, so we check membership by slot
        # against the finalized slot.
        store.attestation_signatures = {
            attestation_data: signatures
            for attestation_data, signatures in store.attestation_signatures.items()
            if attestation_data.target.slot > store.latest_finalized.slot
        }
        store.latest_new_aggregated_payloads = {
            attestation_data: proofs
            for attestation_data, proofs in store.latest_new_aggregated_payloads.items()
            if attestation_data.target.slot > store.latest_finalized.slot
        }
        store.latest_known_aggregated_payloads = {
            attestation_data: proofs
            for attestation_data, proofs in store.latest_known_aggregated_payloads.items()
            if attestation_data.target.slot > store.latest_finalized.slot
        }
        return store

    def validate_attestation(self, store: LstarStore, attestation_data: AttestationData) -> None:
        """Validate incoming attestation before processing.

        Ensures the vote respects the basic laws of time and topology:
            1. The blocks voted for must exist in our store.
            2. A vote cannot span backwards in time (source > target).
            3. The head must be at least as recent as source and target.
            4. Checkpoint slots must match the actual block slots.
            5. The vote's slot must have started locally (a small disparity margin is allowed).

        Raises:
            AssertionError: If attestation fails validation.
        """
        data = attestation_data

        # Availability Check
        #
        # We cannot count a vote if we haven't seen the blocks involved.
        assert data.source.root in store.blocks, f"Unknown source block: {data.source.root.hex()}"
        assert data.target.root in store.blocks, f"Unknown target block: {data.target.root.hex()}"
        assert data.head.root in store.blocks, f"Unknown head block: {data.head.root.hex()}"

        # Topology Check
        #
        # History is linear and monotonic: source <= target <= head.
        # The second check implies head >= source by transitivity.
        assert data.source.slot <= data.target.slot, "Source checkpoint slot must not exceed target"
        assert data.head.slot >= data.target.slot, "Head checkpoint must not be older than target"

        # Consistency Check
        #
        # Validate checkpoint slots match block slots.
        source_block = store.blocks[data.source.root]
        target_block = store.blocks[data.target.root]
        head_block = store.blocks[data.head.root]
        assert source_block.slot == data.source.slot, "Source checkpoint slot mismatch"
        assert target_block.slot == data.target.slot, "Target checkpoint slot mismatch"
        assert head_block.slot == data.head.slot, "Head checkpoint slot mismatch"

        # Time Check
        #
        # Honest validators emit votes only after their slot has begun.
        # Allow a small disparity margin for clock skew between peers.
        #
        # The bound is in intervals, not slots: a whole-slot margin would
        # let an adversary pre-publish next-slot aggregates ahead of any
        # honest validator.
        attestation_start_interval = Interval.from_slot(data.slot)
        gossip_disparity = Interval(int(GOSSIP_DISPARITY_INTERVALS))
        assert attestation_start_interval <= store.time + gossip_disparity, (
            "Attestation too far in future"
        )

    def on_gossip_attestation(
        self,
        store: LstarStore,
        signed_attestation: SignedAttestation,
        is_aggregator: bool = False,
    ) -> LstarStore:
        """Process a signed attestation received via gossip network.

        This method:

        1. Verifies the XMSS signature
        2. Stores the signature when the node is in aggregator mode

        Subnet filtering happens at the p2p subscription layer — only
        attestations from subscribed subnets reach this method. No
        additional subnet check is needed here.

        Args:
            store: The current forkchoice store.
            signed_attestation: The signed attestation to process.
            is_aggregator: True if the node is an aggregator.

        Returns:
            A new store with the attestation signature recorded when in
            aggregator mode, otherwise the input store unchanged.

        Raises:
            ValueError: If validator not found in state.
            AssertionError: If signature verification fails.
        """
        with observe_on_attestation():
            validator_index = signed_attestation.validator_index
            attestation_data = signed_attestation.data
            signature = signed_attestation.signature

            # Validate the attestation first so unknown blocks are rejected cleanly
            # (instead of raising a raw KeyError when state is missing).
            self.validate_attestation(store, attestation_data)

            key_state = store.states.get(attestation_data.target.root)
            assert key_state is not None, (
                f"No state available to verify attestation signature for target block "
                f"{attestation_data.target.root.hex()}"
            )
            assert validator_index.is_valid(Uint64(len(key_state.validators))), (
                f"Validator {validator_index} not found in state "
                f"{attestation_data.target.root.hex()}"
            )
            public_key = key_state.validators[validator_index].get_attestation_public_key()

            assert TARGET_SIGNATURE_SCHEME.verify(
                public_key, attestation_data.slot, hash_tree_root(attestation_data), signature
            ), "Signature verification failed"

            # Aggregators store all received gossip signatures.
            # The p2p layer only delivers attestations from subscribed subnets,
            # so subnet filtering happens at subscription time, not here.
            # Non-aggregator nodes validate and drop — they never store gossip signatures.
            if is_aggregator:
                store.attestation_signatures.setdefault(attestation_data, set()).add(
                    AttestationSignatureEntry(validator_index, signature)
                )

            return store

    def on_gossip_aggregated_attestation(
        self,
        store: LstarStore,
        signed_attestation: SignedAggregatedAttestation,
    ) -> LstarStore:
        """Process a signed aggregated attestation received via aggregation topic.

        This method:
        1. Verifies the aggregated attestation
        2. Stores the aggregation in aggregation_payloads map

        Raises:
            ValueError: If validator not found in state.
            AssertionError: If signature verification fails.
        """
        data = signed_attestation.data
        proof = signed_attestation.proof

        self.validate_attestation(store, data)

        # Get validator IDs who participated in this aggregation
        validator_indices = proof.participants.to_validator_indices()

        # Retrieve the relevant state to look up public keys for verification.
        key_state = store.states.get(data.target.root)
        assert key_state is not None, (
            f"No state available to verify committee aggregation for target "
            f"{data.target.root.hex()}"
        )

        # Ensure all participants exist in the active set
        validators = key_state.validators
        for validator_index in validator_indices:
            assert validator_index.is_valid(Uint64(len(validators))), (
                f"Validator {validator_index} not found in state {data.target.root.hex()}"
            )

        # Prepare public keys for verification
        public_keys = [
            validators[validator_index].get_attestation_public_key()
            for validator_index in validator_indices
        ]

        # Verify the single-message aggregate single-message aggregated proof.
        try:
            proof.verify(
                public_keys=public_keys,
                message=hash_tree_root(data),
                slot=data.slot,
            )
        except AggregationError as exc:
            raise AssertionError(
                f"Committee aggregation signature verification failed: {exc}"
            ) from exc

        store.latest_new_aggregated_payloads.setdefault(data, set()).add(proof)

        return store

    def on_block(
        self,
        store: LstarStore,
        signed_block: SignedBlock,
    ) -> LstarStore:
        """Process a new block and update the forkchoice state.

        This method integrates a block into the forkchoice store by:

        1. Validating the block's parent exists
        2. Computing the post-state via the state transition function
        3. Processing attestations included in the block body (on-chain)
        4. Updating the forkchoice head

        Raises:
            AssertionError: If parent block/state not found in store.
        """
        with observe_on_block():
            block = signed_block.block
            block_root = hash_tree_root(block)

            # Skip duplicate blocks (idempotent operation)
            if block_root in store.blocks:
                return store

            # Capture the finalized slot before any updates so we can decide
            # at the end whether finalization advanced and pruning is needed.
            previous_finalized_slot = store.latest_finalized.slot

            # Verify parent chain is available
            #
            # The parent state must exist before processing this block.
            # If missing, the node must sync the parent chain first.
            parent_state = store.states.get(block.parent_root)
            assert parent_state is not None, (
                f"Parent state not found (root={block.parent_root.hex()}). "
                f"Sync parent chain before processing block at slot {block.slot}."
            )

            # The block body constrains how many distinct AttestationData
            # entries it may carry.
            aggregated_attestations = block.body.attestations
            attestation_data_set = {attestation.data for attestation in aggregated_attestations}
            assert len(attestation_data_set) == len(aggregated_attestations), (
                "Block contains duplicate AttestationData entries; "
                "each AttestationData must appear at most once"
            )
            assert len(attestation_data_set) <= int(MAX_ATTESTATIONS_DATA), (
                f"Block contains {len(attestation_data_set)} distinct AttestationData entries; "
                f"maximum is {MAX_ATTESTATIONS_DATA}"
            )

            # Validate cryptographic signatures
            valid_signatures = self.verify_signatures(signed_block, parent_state.validators)

            # Execute state transition function to compute post-block state
            post_state = self.state_transition(parent_state, block, valid_signatures)

            # Propagate checkpoint advances from the post-state.
            #
            # A candidate replaces the store's checkpoint only when its slot is strictly higher.
            # On slot ties the store's view stays authoritative.
            #
            # Why: the store's checkpoint is pinned at init.
            # It advances only on real justification or finalization events.
            # An incoming tie must not silently swap roots.
            latest_justified = store.latest_justified.advance_to(post_state.latest_justified)
            latest_finalized = store.latest_finalized.advance_to(post_state.latest_finalized)

            store.blocks = store.blocks | {block_root: block}
            store.states = store.states | {block_root: post_state}
            store.latest_justified = latest_justified
            store.latest_finalized = latest_finalized

            # Register each block attestation's data in the known pool.
            #
            # Only the data key is recorded here, with an empty proof set.
            # The block carries one merged proof for all attestations.
            # That proof is verified as a whole and not decomposed at import.
            # Per-attestation proofs reach the pools through the
            # deconstruction and gossip path instead.
            #
            # Consequence: a block's own attestations contribute zero weight
            # to the head computation triggered by this import.
            # Recovered single-message aggregate proofs land in the new pool and migrate to
            # the known pool at the next acceptance tick.
            # Head weight from block-imported votes is therefore deferred
            # by up to one slot.
            for aggregated_attestation in aggregated_attestations:
                store.latest_known_aggregated_payloads.setdefault(
                    aggregated_attestation.data, set()
                )

            # Update forkchoice head based on new block and attestations.
            store = self.update_head(store)

            # Prune stale attestation data when finalization advances
            if store.latest_finalized.slot > previous_finalized_slot:
                store = self.prune_stale_attestation_data(store)

            return store

    def extract_attestations_from_aggregated_payloads(
        self,
        store: LstarStore,
        aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]],
    ) -> dict[ValidatorIndex, AttestationData]:
        """Extract attestations from aggregated payloads.

        Given a mapping of aggregated signature proofs, extract the attestation data
        for each validator that participated in the aggregation.
        """
        attestations: dict[ValidatorIndex, AttestationData] = {}

        for attestation_data, proofs in aggregated_payloads.items():
            for proof in proofs:
                for validator_index in proof.participants.to_validator_indices():
                    existing = attestations.get(validator_index)
                    if existing is None or existing.slot < attestation_data.slot:
                        attestations[validator_index] = attestation_data
        return attestations

    def compute_block_weights(self, store: LstarStore) -> dict[Bytes32, int]:
        """Compute attestation-based weight for each block above the finalized slot.

        Walks backward from each validator's latest head vote, incrementing weight
        for every ancestor above the finalized slot.
        """
        attestations = self.extract_attestations_from_aggregated_payloads(
            store, store.latest_known_aggregated_payloads
        )

        start_slot = store.latest_finalized.slot

        weights: dict[Bytes32, int] = defaultdict(int)

        for attestation_data in attestations.values():
            current_root = attestation_data.head.root

            while current_root in store.blocks and store.blocks[current_root].slot > start_slot:
                weights[current_root] += 1
                current_root = store.blocks[current_root].parent_root

        return dict(weights)

    def _compute_lmd_ghost_head(
        self,
        store: LstarStore,
        start_root: Bytes32,
        attestations: dict[ValidatorIndex, AttestationData],
        min_score: int = 0,
    ) -> Bytes32:
        """Walk the block tree according to the LMD GHOST rule.

        The walk starts from a chosen root.
        At each fork, the child subtree with the highest weight is taken.
        The process stops when a leaf is reached.
        That leaf is the chosen head.

        Weights are derived from votes as follows:
        - Each validator contributes its full weight to its most recent head vote.
        - The weight of that vote also flows to every ancestor of the voted block.
        - The weight of a subtree is the sum of all such contributions inside it.

        An optional threshold can be applied:
        - If a threshold is set, children below this threshold are ignored.

        When two branches have equal weight, the one with the lexicographically
        larger hash is chosen to break ties.
        """
        # Invariant: the anchor must be a block the store already knows.
        # A loud failure here beats a cryptic missing-key error deep in the weight loop.
        assert start_root in store.blocks, f"start_root {start_root.hex()} not in store.blocks"

        # Remember the slot of the anchor once and reuse it during the walk.
        #
        # This avoids repeated lookups inside the inner loop.
        start_slot = store.blocks[start_root].slot

        # Prepare a table that will collect voting weight for each block.
        #
        # Each entry starts conceptually at zero and then accumulates contributions.
        weights: dict[Bytes32, int] = defaultdict(int)

        # For every vote, follow the chosen head upward through its ancestors.
        #
        # Each visited block accumulates one unit of weight from that validator.
        for attestation_data in attestations.values():
            current_root = attestation_data.head.root

            # Climb towards the anchor while staying inside the known tree.
            #
            # This naturally handles partial views and ongoing sync.
            while current_root in store.blocks and store.blocks[current_root].slot > start_slot:
                weights[current_root] += 1
                current_root = store.blocks[current_root].parent_root

        # Build the parent -> children adjacency.
        #
        # Genesis blocks land in the bucket keyed by the zero hash.
        # That bucket is never consulted.
        # The walk anchors at the latest justified root and only descends.
        children_map: dict[Bytes32, list[Bytes32]] = defaultdict(list)

        for root, block in store.blocks.items():
            # Prune low-weight branches early when a threshold is set.
            if min_score > 0 and weights[root] < min_score:
                continue

            children_map[block.parent_root].append(root)

        # Now perform the greedy walk.
        #
        # At each step, pick the child with the highest weight among the candidates.
        head = start_root

        # Descend the tree, choosing the heaviest branch at every fork.
        while children := children_map.get(head):
            # Choose best child: most attestations, then lexicographically highest hash
            head = max(children, key=lambda x: (weights[x], x))

        return head

    def update_head(self, store: LstarStore) -> LstarStore:
        """Compute updated store with new canonical head.

        Selects the canonical chain head using:

        1. Latest justified checkpoint as the starting root
        2. LMD-GHOST fork choice rule (heaviest subtree by attestation weight)
        """
        # Extract attestations from known aggregated payloads
        attestations = self.extract_attestations_from_aggregated_payloads(
            store, store.latest_known_aggregated_payloads
        )

        # Run LMD-GHOST fork choice algorithm.
        #
        # Starts from the justified root and greedily descends to the heaviest
        # leaf. The result is always a descendant of the justified root by
        # construction: the walk only follows child edges within the subtree.
        store.head = self._compute_lmd_ghost_head(
            store,
            start_root=store.latest_justified.root,
            attestations=attestations,
        )
        return store

    def accept_new_attestations(self, store: LstarStore) -> LstarStore:
        """Process pending aggregated payloads and update forkchoice head.

        Moves aggregated payloads from latest_new_aggregated_payloads to
        latest_known_aggregated_payloads, making them eligible to contribute to
        fork choice weights. This migration happens at specific interval ticks.

        The Interval Tick System
        -------------------------
        Aggregated payloads progress through intervals:
        - Interval 0: Block proposal
        - Interval 1: Validators cast attestations (enter "new")
        - Interval 2: Aggregators create proofs & broadcast
        - Interval 3: Safe target update
        - Interval 4: Process accumulated attestations

        This staged progression ensures proper timing and prevents premature
        influence on fork choice decisions.
        """
        # Merge new aggregated payloads into known aggregated payloads
        for attestation_data, proofs in store.latest_new_aggregated_payloads.items():
            store.latest_known_aggregated_payloads.setdefault(attestation_data, set()).update(
                proofs
            )
        store.latest_new_aggregated_payloads = {}

        # Update head with newly accepted aggregated payloads
        return self.update_head(store)

    def update_safe_target(self, store: LstarStore) -> LstarStore:
        """Compute the deepest block that has 2/3+ supermajority attestation weight.

        The safe target is the furthest-from-genesis block where enough validators
        agree. Validators use it to decide which block is safe to attest to.
        Only blocks meeting the supermajority threshold qualify.

        This runs at interval 3 of the slot cycle:

        - Interval 0: Block proposal
        - Interval 1: Validators cast attestation votes
        - Interval 2: Aggregators create proofs, broadcast via gossip
        - Interval 3: Safe target update (HERE)
        - Interval 4: New attestations migrate to "known" pool

        Only the "new" pool counts. Migration into "known" runs at interval 4,
        after this step, so safe target sees only votes received this slot.

        Safe target is an *availability* signal, not durable knowledge:

        - A block is safe when 2/3 of currently online validators vote for a descendant.
        - "Known" carries block-included, previously migrated, and self-attestations.
        - Those reflect historical knowledge, not current liveness.
        - Counting them would advance safe target on stale evidence after a participation collapse.
        """
        # Look up the post-state of the current head block.
        #
        # The validator registry in this state tells us how many active
        # validators exist. We need that count to compute the threshold.
        head_state = store.states[store.head]
        num_validators = Uint64(len(head_state.validators))

        # Compute the 2/3 supermajority threshold.
        #
        # A block needs at least this many attestation votes to be "safe".
        # The threshold is rounded UP so a strict majority is required.
        # For example, 100 validators => threshold is 67, not 66.
        min_target_score = math.ceil(int(num_validators) * 2 / 3)

        # Unpack "new" payloads into a flat validator -> vote mapping.
        # "Known" is excluded by design.
        attestations = self.extract_attestations_from_aggregated_payloads(
            store,
            store.latest_new_aggregated_payloads,
        )

        # Run LMD GHOST with the supermajority threshold.
        #
        # The walk starts from the latest justified checkpoint and descends
        # through the block tree. At each fork, only children with at least
        # `min_target_score` attestation weight are considered. The result
        # is the deepest block that clears the 2/3 bar.
        #
        # If no child meets the threshold at some fork, the walk stops
        # early. The safe target is then shallower than the actual head.
        safe_target = self._compute_lmd_ghost_head(
            store,
            start_root=store.latest_justified.root,
            attestations=attestations,
            min_score=min_target_score,
        )

        # Return a new Store with only the safe target updated.
        #
        # The head and attestation pools remain unchanged.
        store.safe_target = safe_target
        return store

    def aggregate(self, store: LstarStore) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Turn raw validator votes into compact aggregated attestations.

        Validators cast individual signatures over gossip. Before those
        votes can influence fork choice or be included in a block, they
        must be combined into compact cryptographic proofs.

        The store holds three pools of attestation evidence:

        - **Gossip signatures**: individual validator votes arriving in real-time.
        - **New payloads**: aggregated proofs from the current round, not yet
          committed to the chain.
        - **Known payloads**: previously accepted proofs, reusable as building
          blocks for deeper aggregation.

        For each unique piece of attestation data the algorithm proceeds in three phases:

        1. **Select** — greedily pick existing proofs that maximize
           validator coverage (new before known).
        2. **Fill** — collect raw gossip signatures for any validators
           not yet covered.
        3. **Aggregate** — delegate to the XMSS subspec to produce a
           single cryptographic proof.

        After aggregation the store is updated:

        - Consumed gossip signatures are removed.
        - Newly produced proofs are recorded for future reuse.
        """
        validators = store.states[store.head].validators
        gossip_signatures = store.attestation_signatures
        new = store.latest_new_aggregated_payloads
        known = store.latest_known_aggregated_payloads

        new_aggregates: list[SignedAggregatedAttestation] = []

        # Only attestation data with a new payload or a raw gossip signature
        # can trigger aggregation. Known payloads alone cannot — they exist
        # only to help extend coverage when combined with fresh evidence.
        for data in new.keys() | gossip_signatures.keys():
            # Phase 1: Select
            #
            # Start with the cheapest option: reuse proofs that already
            # cover many validators.
            #
            # Child proofs are aggregated signatures from prior rounds.
            # Selecting them first keeps the final proof tree shallow
            # and avoids redundant cryptographic work.
            #
            # New payloads go first because they represent uncommitted
            # work — known payloads fill remaining gaps.

            child_proofs, covered = select_greedily(new.get(data), known.get(data))

            # Phase 2: Fill
            #
            # For every validator not yet covered by a child proof,
            # include its individual gossip signature.
            #
            # Sorting by validator index guarantees deterministic proof
            # construction regardless of network arrival order.
            raw_entries = [
                (
                    e.validator_index,
                    validators[e.validator_index].get_attestation_public_key(),
                    e.signature,
                )
                for e in sorted(gossip_signatures.get(data, set()), key=lambda e: e.validator_index)
                if e.validator_index not in covered
            ]

            # The aggregation layer enforces a minimum: either at least one
            # raw signature, or at least two child proofs to merge.
            #
            # A lone child proof is already a valid proof — nothing to do.
            if not raw_entries and len(child_proofs) < 2:
                continue

            # Phase 3: Aggregate
            #
            # Build the recursive proof tree.
            #
            # Each child proof needs its participants' public keys so
            # the XMSS prover can verify inner proofs while constructing
            # the outer one.
            children = [
                (
                    child,
                    [
                        validators[validator_index].get_attestation_public_key()
                        for validator_index in child.participants.to_validator_indices()
                    ],
                )
                for child in child_proofs
            ]

            # Hand everything to the XMSS subspec.
            # Each fresh entry already carries its validator index alongside its key and signature.
            # Out comes a single proof covering all selected validators.
            proof = SingleMessageAggregate.aggregate(
                children=children,
                raw_xmss=raw_entries,
                message=hash_tree_root(data),
                slot=data.slot,
            )
            new_aggregates.append(SignedAggregatedAttestation(data=data, proof=proof))

        # ── Store bookkeeping ────────────────────────────────────────
        #
        # Record freshly produced proofs so future rounds can reuse them.
        # Remove gossip signatures that were consumed by this aggregation.
        store.latest_new_aggregated_payloads = {}
        for signed_attestation in new_aggregates:
            store.latest_new_aggregated_payloads.setdefault(signed_attestation.data, set()).add(
                signed_attestation.proof
            )

        for data in store.latest_new_aggregated_payloads:
            store.attestation_signatures.pop(data, None)
        return store, new_aggregates

    def tick_interval(
        self,
        store: LstarStore,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Advance store time by one interval and perform interval-specific actions.

        Different actions are performed based on interval within slot:
        - Interval 0: Process attestations if proposal exists
        - Interval 1: Validator attesting period (no action)
        - Interval 2: Aggregators create proofs & broadcast
        - Interval 3: Update safe target (fast confirm)
        - Interval 4: Process accumulated attestations
        """
        # Advance time by one interval
        store.time = store.time + Interval(1)
        current_interval = Interval(int(store.time) % int(INTERVALS_PER_SLOT))
        new_aggregates: list[SignedAggregatedAttestation] = []

        if current_interval == Interval(0) and has_proposal:
            store = self.accept_new_attestations(store)
        elif current_interval == Interval(2) and is_aggregator:
            store, new_aggregates = self.aggregate(store)
        elif current_interval == Interval(3):
            store = self.update_safe_target(store)
        elif current_interval == Interval(4):
            store = self.accept_new_attestations(store)

        return store, new_aggregates

    def on_tick(
        self,
        store: LstarStore,
        target_interval: Interval,
        has_proposal: bool,
        is_aggregator: bool = False,
    ) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Advance forkchoice store time to given interval count.

        Ticks store forward interval by interval, performing appropriate
        actions for each interval type. This method handles time progression
        incrementally to ensure all interval-specific actions are performed.
        """
        all_new_aggregates: list[SignedAggregatedAttestation] = []

        # Tick forward one interval at a time
        while store.time < target_interval:
            # Check if proposal should be signaled for next interval
            next_interval = Interval(int(store.time) + 1)
            should_signal_proposal = has_proposal and next_interval == target_interval

            # Advance by one interval with appropriate signaling
            store, new_aggregates = self.tick_interval(store, should_signal_proposal, is_aggregator)
            all_new_aggregates.extend(new_aggregates)

        return store, all_new_aggregates

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
        for _ in range(JUSTIFICATION_LOOKBACK_SLOTS):
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
