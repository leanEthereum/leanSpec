"""State Container."""

from typing import Dict, List, cast

from typing_extensions import Any

from lean_spec.subspecs.chain import DEVNET_CONFIG
from lean_spec.subspecs.ssz.constants import ZERO_HASH
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import (
    Boolean,
    Bytes32,
    Container,
    SSZList,
    Uint64,
    ValidatorIndex,
    is_proposer,
)
from lean_spec.types.bitfields import BitlistBase

from .block import Attestations, Block, BlockBody, BlockHeader, SignedBlock
from .checkpoint import Checkpoint
from .config import Config
from .slot import Slot
from .vote import SignedVote, Vote


# Domain-specific collection types
class HistoricalBlockHashes(SSZList):
    """List of historical block root hashes up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = 262144  # historical_roots_limit


class JustificationRoots(SSZList):
    """List of justified block roots up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = 262144  # historical_roots_limit


class BooleanList262144Squared(SSZList):
    """List of Boolean with limit 262144^2 (for flattened votes)."""

    ELEMENT_TYPE = Boolean
    LIMIT = 262144 * 262144


# Domain-specific bitfield types
class JustifiedSlots(BitlistBase):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = 262144  # historical_roots_limit


class JustificationValidators(BitlistBase):
    """Bitlist for tracking validator justifications (262144^2 limit)."""

    LIMIT = 262144 * 262144  # For flattened validator justifications


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

    # Fork choice
    latest_justified: Checkpoint
    """The latest justified checkpoint."""

    latest_finalized: Checkpoint
    """The latest finalized checkpoint."""

    # Historical data
    historical_block_hashes: HistoricalBlockHashes
    """A list of historical block root hashes."""

    justified_slots: JustifiedSlots
    """A bitfield indicating which historical slots were justified."""

    # Justification tracking (flattened for SSZ compatibility)
    justifications_roots: JustificationRoots
    """Roots of justified blocks."""

    justifications_validators: JustificationValidators
    """A bitlist of validators who participated in justifications."""

    @classmethod
    def generate_genesis(cls, genesis_time: Uint64, num_validators: Uint64) -> "State":
        """
        Construct the genesis `State` for the chain.

        This factory creates a minimal, self-consistent starting state.
        - It encodes the chain configuration (time and validator count).
        - It seeds a zeroed latest_block_header whose body_root commits to an empty body.
        - It leaves state_root empty to be filled on the first post-genesis slot.
        - It initializes checkpoints and history to their empty defaults.
        - It sets no justifications at genesis.

        Args:
            genesis_time: The configured time for slot 0.
            num_validators: The total number of validators for Devnet 0.

        Returns:
            A new State positioned at slot 0 with empty history and checkpoints.
        """
        # Create the zeroed header that anchors the chain at genesis.
        genesis_header = BlockHeader(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(BlockBody(attestations=Attestations(data=[]))),
        )

        # Assemble and return the full genesis state.
        return cls(
            config=Config(
                genesis_time=genesis_time,
                num_validators=num_validators,
            ),
            slot=Slot(0),
            latest_block_header=genesis_header,
            latest_justified=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            latest_finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        )

    def is_proposer(self, validator_index: ValidatorIndex) -> bool:
        """
        Check if a validator is the proposer for the current slot.

        The proposer selection follows a simple round-robin mechanism based on the
        slot number and the total number of validators.
        """
        return is_proposer(validator_index, Uint64(self.slot.as_int()), self.config.num_validators)

    def get_justifications(self) -> Dict[Bytes32, List[Boolean]]:
        """
        Reconstructs the justification votes map from flattened state data.

        For Simple Serialize (SSZ) compatibility and on-chain efficiency, the
        consensus state stores justification data across two flattened lists:
          - `justifications_roots`: The list of block roots under consideration.
          - `justifications_validators`: A single, contiguous list containing
            the boolean votes for all roots.

        This method efficiently de-flattens this data into a more intuitive
        dictionary, mapping each root to its corresponding list of validator
        votes.

        Example:
            If `justifications_roots` = `[root_A, root_B]` and the validator
            limit is 4, `justifications_validators` would be a single list
            of 8 booleans (votes for A, then votes for B). This function
            would return: `{root_A: [votes...], root_B: [votes...]}`.

        Note:
            Client implementations may consider caching this computed map for
            performance, re-evaluating it only when the underlying state changes.

        Returns:
            A dictionary mapping each block root to a list of boolean votes.
            The index of each list corresponds to the validator index.
        """
        # Cache the validator registry limit for concise slicing calculations.
        #
        # This value determines the size of the block of votes for each root.
        limit = DEVNET_CONFIG.validator_registry_limit.as_int()
        roots = self.justifications_roots
        validators = self.justifications_validators

        # Build the entire justifications map.
        return cast(
            Dict[Bytes32, List[Boolean]],
            {root: validators[i * limit : (i + 1) * limit] for i, root in enumerate(roots)},
        )

    def with_justifications(self, justifications: Dict[Bytes32, List[Boolean]]) -> "State":
        """
        Creates a new state object with updated, flattened justifications.

        This method performs the inverse of `get_justifications`. It takes a
        human-readable dictionary of votes and serializes it into the two
        flattened lists required by the consensus state for SSZ compatibility.

        To ensure deterministic serialization, the roots are sorted before
        being flattened. The method also validates that each list of votes
        matches the required length.

        Args:
            justifications: A dictionary mapping block roots to their
                            corresponding list of validator votes.

        Returns:
            None. This method modifies the state object in-place.

        Raises:
            AssertionError: If any vote list's length does not match the
                            `validator_registry_limit`.
        """
        # Build lists to store the deterministically sorted data
        roots_list = []
        votes_list = []
        limit = DEVNET_CONFIG.validator_registry_limit.as_int()

        # Iterate through the roots in sorted order for deterministic output.
        for root in sorted(justifications.keys()):
            votes = justifications[root]
            # Check for an incorrect vote length.
            assert len(votes) == limit, f"Vote list for root {root.hex()} has incorrect length"

            # Append the root to the list of roots.
            roots_list.append(root)
            # Extend the flattened list with the votes for this root.
            votes_list.extend(votes)

        # Create immutable SSZList instances
        new_roots = JustificationRoots(data=roots_list)
        flat_votes = BooleanList262144Squared(data=votes_list)

        # Return a new state object with the updated fields.
        return self.model_copy(
            update={
                "justifications_roots": new_roots,
                "justifications_validators": flat_votes,
            }
        )

    def state_transition(self, signed_block: SignedBlock, valid_signatures: bool) -> "State":
        """
        Advance the chain state by applying a new signed block.

        This is the entry point of the State Transition Function (STF).
        - It first advances through any empty slots up to the block's slot.
        - It then applies the block to the updated state.
        - Finally, it checks that the resulting state root matches the block header.

        Args:
            signed_block: The envelope that carries the block and its signature.
            valid_signatures: True if all signatures in the block were pre-verified.

        Returns:
            The post-state after processing slots and the block.

        Raises:
            AssertionError:
                - If signatures are not valid.
                - If the computed state root does not match the block's state root.
        """
        # All signatures are verified outside the STF. Enforce that contract here.
        assert valid_signatures, "Block signatures must be valid"

        # Extract the inner block. The signature is not used further in STF.
        block = signed_block.message

        # Process any empty slots between the current state and the block's slot.
        #
        # Returns a new state advanced to the block's slot.
        state = self.process_slots(block.slot)

        # Apply the block header and operations to the advanced state.
        state = state.process_block(block)

        # The block must commit to the exact new state. Compare roots.
        assert block.state_root == hash_tree_root(state), "Invalid block state root"

        # Return the fully updated state.
        return state

    def process_slots(self, target_slot: Slot) -> "State":
        """
        Advance the state through empty slots up to, but not including, target_slot.

        The loop:
          - Calls process_slot once per missing slot.
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

        # Step through each missing slot:
        while state.slot < target_slot:
            # Perform per-slot housekeeping (e.g., cache the state root).
            state = state.process_slot()
            # Increase the slot number by one for the next iteration.
            state = state.model_copy(update={"slot": Slot(state.slot + Slot(1))})

        # Reached the target slot. Return the advanced state.
        return state

    def process_slot(self) -> "State":
        """
        Perform per-slot maintenance tasks.

        If we are on the slot immediately after a block, the latest block header
        has an empty state_root. In that case, cache the pre-block state root into
        that header. Otherwise, no change is required.

        Returns:
            A new state with latest_block_header.state_root set if needed.
        """
        # If the latest block header has no state root, fill it now.
        #
        # This occurs on the first slot after a block.
        if self.latest_block_header.state_root == Bytes32.zero():
            # Compute the root of the current (pre-block) state.
            previous_state_root = hash_tree_root(self)

            # Copy the header and set its state_root to the computed value.
            new_header = self.latest_block_header.model_copy(
                update={"state_root": previous_state_root}
            )

            # Return a new state with the updated header in place.
            return self.model_copy(update={"latest_block_header": new_header})

        # Nothing to do for this slot. Return the state unchanged.
        return self

    def process_block(self, block: Block) -> "State":
        """
        Apply a block to the state.

        The function:
          - Validates and incorporates the block header.
          - Processes the block body operations.

        Args:
            block: The block to apply.

        Returns:
            The new state after header and operations are processed.
        """
        # Validate header linkage and update header-derived fields.
        state = self.process_block_header(block)

        # Process all operations in the block body.
        state = state.process_operations(block.body)

        # Return the updated state.
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

        Args:
            block: The block whose header is being processed.

        Returns:
            A new state with header-related fields updated.

        Raises:
            AssertionError: If any header check fails.
        """
        # The block must be for the current slot.
        assert block.slot == self.slot, "Block slot mismatch"

        # The block must be newer than the current latest header.
        assert block.slot > self.latest_block_header.slot, "Block is older than latest header"

        # The proposer must be the expected validator for this slot.
        assert self.is_proposer(block.proposer_index), "Incorrect block proposer"

        # The declared parent must match the hash of the latest block header.
        assert block.parent_root == hash_tree_root(self.latest_block_header), (
            "Block parent root mismatch"
        )

        # Build a dictionary of field updates to apply in one copy operation.
        updates: Dict[str, Any] = {}

        # Cache the parent root locally for repeated use.
        parent_root = block.parent_root

        # Special case: first block after genesis.
        #
        # Mark genesis as both justified and finalized.
        if self.latest_block_header.slot == Slot(0):
            updates["latest_justified"] = self.latest_justified.model_copy(
                update={"root": parent_root}
            )
            updates["latest_finalized"] = self.latest_finalized.model_copy(
                update={"root": parent_root}
            )

        # Create mutable copies to work with to avoid modifying the original object.
        new_historical_hashes = list(self.historical_block_hashes)
        new_historical_hashes.append(parent_root)

        new_justified_slots = list(self.justified_slots)
        new_justified_slots.append(Boolean(self.latest_block_header.slot == Slot(0)))

        # If there were empty slots between parent and this block, fill them.
        num_empty_slots = (block.slot - self.latest_block_header.slot - Slot(1)).as_int()
        if num_empty_slots > 0:
            new_historical_hashes.extend([ZERO_HASH] * num_empty_slots)
            new_justified_slots.extend([Boolean(False)] * num_empty_slots)

        # Record updated history arrays, ensuring they are cast back to the correct SSZList type.
        updates["historical_block_hashes"] = self.historical_block_hashes.__class__(
            data=new_historical_hashes
        )
        updates["justified_slots"] = self.justified_slots.__class__(data=new_justified_slots)

        # Construct the new latest block header.
        #
        # Leave state_root empty; it will be filled on the next process_slot call.
        updates["latest_block_header"] = BlockHeader(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            body_root=hash_tree_root(block.body),
            state_root=Bytes32.zero(),
        )

        # Return the state with all header updates applied.
        return self.model_copy(update=updates)

    def process_operations(self, body: BlockBody) -> "State":
        """
        Apply the operations contained in a block body.

        Current devnet scope:
          - Only attestations are processed.

        Args:
            body: The block body to process.

        Returns:
            The new state after applying all supported operations.
        """
        # Process justification votes (attestations).
        return self.process_attestations(body.attestations)

    def process_attestations(
        self,
        attestations: Attestations,
    ) -> "State":
        """
        Apply attestation votes and update justification/finalization
        according to the Lean Consensus 3SF-mini rules.

        Overview
        --------
        This method consumes a block's attestations and updates three parts of the state:
          1) The in-progress per-target vote tracker (the "justifications" map),
          2) The latest justified checkpoint,
          3) The latest finalized checkpoint.

        Votes are only counted if they satisfy the following invariants:
          - The vote's source slot is already justified.
          - The target slot is not already justified.
          - The vote's source root matches history at its slot.
          - The vote's target root matches history at its slot, or (if target is the latest header)
            it matches the latest header root.
          - The target slot is strictly after the source slot.
          - The target slot is a justifiable slot with respect to the current finalized slot.

        When a target gathers a 2/3 supermajority (using exact arithmetic: 3 * count >= 2 * N),
        that target becomes justified, the corresponding per-target votes are discarded,
        and the source may become finalized if there exists no other justifiable slot strictly
        between the source and the target.

        Returns:
        -------
        A new State with:
          - updated latest_justified / latest_finalized checkpoints,
          - updated justified_slots bitfield,
          - persisted justifications map re-flattened into SSZ lists.
        """
        # Reconstruct the in-memory map of target_root -> [votes by validator].
        justifications = self.get_justifications()

        # Snapshot moving checkpoints and a mutable copy of the justified bitfield.
        latest_justified = self.latest_justified
        latest_finalized = self.latest_finalized
        justified_slots = list(self.justified_slots)

        # Process every attestation in the block.
        for signed_vote_untyped in attestations:
            # Typed view
            signed_vote = cast(SignedVote, signed_vote_untyped)
            # Convenience alias
            vote: Vote = signed_vote.data

            # Unpack frequently used fields.
            target_slot = vote.target.slot
            source_slot = vote.source.slot
            target_root = vote.target.root
            source_root = vote.source.root

            target_slot_int = target_slot.as_int()
            source_slot_int = source_slot.as_int()

            # Validate the vote.

            # Source must already be justified.
            source_is_justified = justified_slots[source_slot_int]

            # Target must not already be justified (if index exists in bitfield).
            target_already_justified = (
                target_slot_int < len(justified_slots) and justified_slots[target_slot_int]
            )

            # Source root must match history at the source slot.
            source_root_matches_history = (
                source_root == self.historical_block_hashes[source_slot_int]
            )

            # - Target root must match history at the target slot,
            # - Or, if target is the latest header, it must match the latest header's root.
            target_root_matches_history = (
                target_slot_int < len(self.historical_block_hashes)
                and target_root == self.historical_block_hashes[target_slot_int]
            )
            target_matches_latest_header = (
                target_slot == self.latest_block_header.slot
                and target_root == hash_tree_root(self.latest_block_header)
            )
            target_root_is_valid = target_root_matches_history or target_matches_latest_header

            # Target must be strictly after source.
            target_is_after_source = target_slot > source_slot

            # Target must be a justifiable slot with respect to the latest finalized slot.
            target_is_justifiable = target_slot.is_justifiable_after(latest_finalized.slot)

            # Final validity check.
            is_valid_vote = (
                source_is_justified
                and not target_already_justified
                and source_root_matches_history
                and target_root_is_valid
                and target_is_after_source
                and target_is_justifiable
            )
            if not is_valid_vote:
                # Skip invalid or redundant votes.
                continue

            # Track a unique vote for (target_root, validator_id) only
            if target_root not in justifications:
                # Initialize a fresh bitvector for this target root (all False).
                limit = DEVNET_CONFIG.validator_registry_limit.as_int()
                justifications[target_root] = [Boolean(False)] * limit

            validator_id = vote.validator_id.as_int()
            if not justifications[target_root][validator_id]:
                # Record the vote once per validator per target.
                justifications[target_root][validator_id] = Boolean(True)

            # Check for 2/3 supermajority to justify target
            count = sum(int(v) for v in justifications[target_root])
            if 3 * count >= 2 * self.config.num_validators.as_int():
                # Promote target to latest justified.
                latest_justified = vote.target

                # Ensure justified_slots is long enough, then mark the target slot.
                while len(justified_slots) <= target_slot_int:
                    justified_slots.append(Boolean(False))
                justified_slots[target_slot_int] = Boolean(True)

                # Drop per-target tracking once justified.
                del justifications[target_root]

                # Finalization: source becomes finalized
                # If no justifiable slot exists strictly between source and target.
                is_finalizable = not any(
                    Slot(s).is_justifiable_after(latest_finalized.slot)
                    for s in range(source_slot_int + 1, target_slot_int)
                )
                if is_finalizable:
                    # Finalize the source checkpoint.
                    latest_finalized = vote.source

        # Persist the updated justifications map back into flattened SSZ lists.
        final_state = self.with_justifications(justifications)

        # Return the state with updated checkpoints and justified bitfield.
        return final_state.model_copy(
            update={
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
                "justified_slots": self.justified_slots.__class__(data=justified_slots),
            }
        )
