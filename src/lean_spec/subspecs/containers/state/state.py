"""
State Container for the Lean Ethereum consensus specification.

The state contains everything needed for consensus. It tracks the current slot,
recent blocks, and validator attestations. State also records which blocks are
justified and finalized.
"""

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

from ..block import Block, BlockBody, BlockHeader
from ..block.types import Attestations
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
            latest_justified=Checkpoint.default(),
            latest_finalized=Checkpoint.default(),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=validators,
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
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
        # If the latest block header already has a state root, no action is needed.
        if self.latest_block_header.state_root != Bytes32.zero():
            return self

        # If the latest block header has no state root, fill it now.
        #
        # This occurs on the first slot after a block.
        # - We compute the root of the current (pre-block) state.
        # - We copy the header and set its state_root to the computed value.
        # - We return a new state with the updated header in place.
        return self.model_copy(
            update={
                "latest_block_header": self.latest_block_header.model_copy(
                    update={"state_root": hash_tree_root(self)}
                )
            }
        )

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
        # Validation
        parent_header = self.latest_block_header
        parent_root = hash_tree_root(parent_header)

        # The block must be for the current slot.
        assert block.slot == self.slot, "Block slot mismatch"

        # The block must be newer than the current latest header.
        assert block.slot > parent_header.slot, "Block is older than latest header"

        # The proposer must be the expected validator for this slot.
        assert is_proposer(
            validator_index=block.proposer_index,
            slot=self.slot,
            num_validators=Uint64(self.validators.count),
        ), "Incorrect block proposer"

        # The declared parent must match the hash of the latest block header.
        assert block.parent_root == parent_root, "Block parent root mismatch"

        # State Updates

        # Special case: first block after genesis.
        is_genesis_parent = parent_header.slot == Slot(0)
        new_latest_justified = (
            self.latest_justified.model_copy(update={"root": parent_root})
            if is_genesis_parent
            else self.latest_justified
        )
        new_latest_finalized = (
            self.latest_finalized.model_copy(update={"root": parent_root})
            if is_genesis_parent
            else self.latest_finalized
        )

        # If there were empty slots between parent and this block, fill them.
        num_empty_slots = (block.slot - parent_header.slot - Slot(1)).as_int()

        # Build new historical hashes list
        new_historical_hashes_data = (
            list(self.historical_block_hashes) + [parent_root] + ([ZERO_HASH] * num_empty_slots)
        )

        # Build new justified slots list
        new_justified_slots_data = (
            list(self.justified_slots)
            + [Boolean(is_genesis_parent)]
            + ([Boolean(False)] * num_empty_slots)
        )

        # Construct the new latest block header.
        #
        # Leave state_root empty; it will be filled on the next process_slot call.
        new_header = BlockHeader(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            body_root=hash_tree_root(block.body),
            state_root=Bytes32.zero(),
        )

        # Final Immutable Copy
        #
        # Return the state with all header updates applied in one go.
        return self.model_copy(
            update={
                "latest_justified": new_latest_justified,
                "latest_finalized": new_latest_finalized,
                "historical_block_hashes": self.historical_block_hashes.__class__(
                    data=new_historical_hashes_data
                ),
                "justified_slots": self.justified_slots.__class__(data=new_justified_slots_data),
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
        """
        # First process the block header.
        state = self.process_block_header(block)

        # Process justification attestations.
        return state.process_attestations(block.body.attestations)

    def process_attestations(
        self,
        attestations: Attestations,
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
        attestations : Attestations
            The list of attestations to process.

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
        for attestation in attestations:
            attestation_data = attestation.data
            source = attestation_data.source
            target = attestation_data.target

            # Validate that this is a reasonable attestation (source comes before target).
            if source.slot.as_int() >= target.slot.as_int():
                continue  # Skip invalid attestation

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

    def produce_block(self, target_slot: Slot, is_empty: bool = False) -> Block:
        """
        Build a Block for a given target slot and optionally return empty block.

        This method represents the full state transition function:
        1. Get the state before the target slot
        2. Build the initial block header (empty body, zero state_root)
            2.a. Optionally return the initial block if `is_empty` is true
        3. Process the state with the block to get the final state_root
        4. Return the final, block (which is block with updated state_root)

        Parameters
        ----------
        target_slot : Slot
            The Slot to build a Block for.
        is_empty : bool, optional
            Whether to return initial empty Block.

        Returns:
        -------
        Block
            A new Block build for the target slot
        """
        # 1. Get the state before the target slot
        pre_state = self.process_slots(target_slot)

        # 2. Build the initial block header (empty body, zero state_root)
        block = Block(
            slot=target_slot,
            proposer_index=int(target_slot) % len(self.validators),
            parent_root=hash_tree_root(pre_state.latest_block_header),
            state_root=Bytes32.zero(),
            body=BlockBody(attestations=Attestations(data=[])),
        )

        if is_empty:
            return block

        # 3. Process the state with the block to get the final state_root
        post_state = pre_state.process_block(block)
        state_root = hash_tree_root(post_state)

        # 4. Return the final, block with non-zero state root
        return Block(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            state_root=state_root,
            body=block.body,
        )
