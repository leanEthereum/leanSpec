"""State Container for the Lean Ethereum consensus specification."""

from typing import Any, Dict, List

from lean_spec.subspecs.chain import DEVNET_CONFIG
from lean_spec.subspecs.ssz.constants import ZERO_HASH
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import (
    Boolean,
    Bytes32,
    Container,
    Uint64,
    ValidatorIndex,
    is_proposer,
)

from ..block import Block, BlockBody, BlockHeader, SignedBlock
from ..block.types import Attestations
from ..checkpoint import Checkpoint
from ..config import Config
from ..slot import Slot
from ..vote import Vote
from .types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
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

    # Justification tracking (flattened for SSZ compatibility)
    justifications_roots: JustificationRoots
    """Roots of justified blocks."""

    justifications_validators: JustificationValidators
    """A bitlist of validators who participated in justifications."""

    @classmethod
    def generate_genesis(cls, genesis_time: Uint64, num_validators: Uint64) -> "State":
        """
        Generate a genesis state with empty history and proper initial values.

        Parameters
        ----------
        genesis_time : Uint64
            The genesis timestamp.
        num_validators : Uint64
            The number of validators in the genesis state.

        Returns:
        -------
        State
            A properly initialized genesis state.
        """
        # Configure the genesis state.
        genesis_config = Config(
            num_validators=num_validators,
            genesis_time=genesis_time,
        )

        # Build the genesis block header for the state.
        genesis_header = BlockHeader(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(BlockBody(attestations=Attestations(data=[]))),
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
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        )

    def is_proposer(self, validator_index: ValidatorIndex) -> bool:
        """
        Check if a validator is the proposer for the current slot.

        Parameters
        ----------
        validator_index : ValidatorIndex
            The index of the validator to check.

        Returns:
        -------
        bool
            True if the validator is the proposer for the current slot.
        """
        # Forward to the global proposer function with state context.
        return is_proposer(
            validator_index=validator_index,
            slot=self.slot,
            num_validators=self.config.num_validators,
        )

    def get_justifications(self) -> Dict[Bytes32, List[Boolean]]:
        """
        Reconstruct a map from justified block roots to validator vote lists.

        This method takes the flat state encoding and rebuilds the associative
        structure for easier processing.

        Returns:
        -------
        Dict[Bytes32, List[Boolean]]
            A mapping from justified block root to the list of validator votes.
        """
        # Initialize an empty result.
        justifications: Dict[Bytes32, List[Boolean]] = {}

        # If there are no justified roots, return immediately.
        if not self.justifications_roots:
            return justifications

        # Compute the length of each validator vote slice.
        validator_count = DEVNET_CONFIG.validator_registry_limit.as_int()

        # Extract vote slices for each justified root.
        flat_votes = list(self.justifications_validators)
        for i, root in enumerate(self.justifications_roots):
            # Ensure root is Bytes32 type
            root = Bytes32(root) if not isinstance(root, Bytes32) else root
            # Calculate the slice boundaries for this root.
            start_index = i * validator_count
            end_index = start_index + validator_count

            # Extract the vote slice and associate it with the root.
            vote_slice = flat_votes[start_index:end_index]
            justifications[root] = vote_slice

        return justifications

    def with_justifications(
        self,
        justifications: Dict[Bytes32, List[Boolean]],
    ) -> "State":
        """
        Update the state with a new set of justifications.

        This method flattens the justifications map into the state's flat
        encoding for SSZ compatibility.

        Parameters
        ----------
        justifications : Dict[Bytes32, List[Boolean]]
            A mapping from justified block root to validator vote lists.

        Returns:
        -------
        State
            A new state with updated justification data.
        """
        # Build the flattened lists from the map, with sorted keys for deterministic order.
        roots_list = []
        votes_list = []
        for root in sorted(justifications.keys()):
            votes = justifications[root]
            # Validate that the vote list has the expected length.
            expected_len = DEVNET_CONFIG.validator_registry_limit.as_int()
            if len(votes) != expected_len:
                raise AssertionError(f"Vote list for root {root.hex()} has incorrect length")

            # Add the root to the roots list.
            roots_list.append(root)
            # Extend the flattened list with the votes for this root.
            votes_list.extend(votes)

        # Create immutable SSZList instances
        new_roots = JustificationRoots(data=roots_list)
        flat_votes = JustificationValidators(data=votes_list)

        # Return a new state object with the updated fields.
        return self.model_copy(
            update={
                "justifications_roots": new_roots,
                "justifications_validators": flat_votes,
            }
        )

    def process_slot(self) -> "State":
        """
        Perform per-slot maintenance tasks.

        If we are on the slot immediately after a block, the latest block header
        has an empty state_root. In that case, cache the pre-block state root into
        that header. Otherwise, no change is required.

        Returns:
        -------
        State
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

    def process_slots(self, target_slot: Slot) -> "State":
        """
        Advance the state through empty slots up to, but not including, target_slot.

        The loop:
          - Calls process_slot once per missing slot.
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
            # Perform per-slot housekeeping (e.g., cache the state root).
            state = state.process_slot()
            # Increase the slot number by one for the next iteration.
            state = state.model_copy(update={"slot": Slot(state.slot + Slot(1))})

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

        # Record updated history arrays, ensuring they are cast back to the
        # correct domain-specific type.
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
        """
        # First process the block header.
        state = self.process_block_header(block)

        # Process justification votes (attestations).
        return state.process_attestations(block.body.attestations)

    def process_attestations(
        self,
        attestations: Attestations,
    ) -> "State":
        """
        Apply attestation votes and update justification/finalization
        according to the Lean Consensus 3SF-mini rules.

        This simplified consensus mechanism:
        1. Processes each attestation vote
        2. Updates justified status for target checkpoints
        3. Applies finalization rules based on justified status

        Parameters
        ----------
        attestations : Attestations
            The list of attestation votes to process.

        Returns:
        -------
        State
            A new state with updated justification/finalization.
        """
        # Start with current justifications and finalization state.
        justified_slots = list(self.justified_slots)
        latest_justified = self.latest_justified
        latest_finalized = self.latest_finalized

        # Process each attestation in the block.
        for signed_vote in attestations:
            vote: Vote = signed_vote.data
            source = vote.source
            target = vote.target

            # Validate that this is a reasonable vote (source comes before target).
            if source.slot.as_int() >= target.slot.as_int():
                continue  # Skip invalid votes

            # Check if source checkpoint is justified.
            source_slot_int = source.slot.as_int()
            target_slot_int = target.slot.as_int()

            # Ensure we have enough justified slots history.
            if source_slot_int < len(justified_slots):
                source_is_justified = justified_slots[source_slot_int]
            else:
                continue  # Source is too far in the past

            # If source is justified, consider justifying the target.
            if (
                source_is_justified
                and target_slot_int < len(justified_slots)
                and justified_slots[target_slot_int]
            ):
                # Target is already justified, check for finalization.
                if (
                    source.slot.as_int() + 1 == target.slot.as_int()
                    and latest_justified.slot.as_int() < target.slot.as_int()
                ):
                    # Consecutive justified checkpoints -> finalize the source.
                    latest_finalized = source
                    latest_justified = target

            else:
                # Try to justify the target if source is justified.
                if source_is_justified:
                    # Ensure justified_slots is long enough, then mark the target slot.
                    while len(justified_slots) <= target_slot_int:
                        justified_slots.append(Boolean(False))
                    justified_slots[target_slot_int] = Boolean(True)

                    # Update latest_justified if this target is newer.
                    if target.slot.as_int() > latest_justified.slot.as_int():
                        latest_justified = target

        # Return the updated state.
        return self.model_copy(
            update={
                "justified_slots": self.justified_slots.__class__(data=justified_slots),
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
            }
        )

    def state_transition(self, signed_block: SignedBlock, valid_signatures: bool = True) -> "State":
        """
        Apply the complete state transition function for a signed block.

        This method represents the full state transition function:
        1. Validate signatures if required
        2. Process slots up to the block's slot
        3. Process the block header and body
        4. Validate the computed state root

        Parameters
        ----------
        signed_block : SignedBlock
            The signed block to apply to the state.
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

        block = signed_block.message

        # First, process any intermediate slots.
        state = self.process_slots(block.slot)

        # Process the block itself.
        new_state = state.process_block(block)

        # Validate that the block's state root matches the computed state
        computed_state_root = hash_tree_root(new_state)
        if block.state_root != computed_state_root:
            raise AssertionError("Invalid block state root")

        return new_state
