"""Convenience builder tooling for test setup."""

from lean_spec.subspecs.containers.block import Block, BlockBody, SignedBlock
from lean_spec.subspecs.containers.block.types import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.containers.vote import SignedVote
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, ValidatorIndex


class BlockBuilder:
    """
    Test tool for building valid blocks.

    This should be analogous to how a validator/block producer would create blocks.
    It computes state_root by dry-running the spec, then creates the final block.
    """

    def __init__(self, state: State):
        """
        Initialize builder with a state.

        Parameters
        ----------
        state : State
            The current state to build blocks against.
        """
        self.state = state

    def build(
        self,
        slot: Slot,
        attestations: list[SignedVote] | None = None,
        proposer_index: ValidatorIndex | None = None,
    ) -> SignedBlock:
        """
        Build a valid signed block.

        Parameters
        ----------
        slot : Slot
            The slot for this block.
        attestations : list[SignedVote], optional
            Attestations to include. Defaults to empty.
        proposer_index : ValidatorIndex, optional
            The proposer. Defaults to round-robin selection.

        Returns:
        -------
        SignedBlock
            A valid signed block ready for state_transition.
        """
        if attestations is None:
            attestations = []

        # Determine proposer (like a real validator would)
        if proposer_index is None:
            proposer_index = ValidatorIndex(int(slot) % int(self.state.config.num_validators))

        # Dry-run process_slots first to get the state at the target slot
        # (This is important because process_slots may update the block header)
        temp_state = self.state.process_slots(slot)

        # NOW get parent root from the state after processing slots
        parent_root = hash_tree_root(temp_state.latest_block_header)

        # Build body
        body = BlockBody(attestations=Attestations(data=attestations))

        # Create temporary block for dry-run
        temp_block = Block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),  # Will compute this
            body=body,
        )

        # Process the block to get resulting state
        temp_state = temp_state.process_block(temp_block)

        # Compute correct state_root
        correct_state_root = hash_tree_root(temp_state)

        # Create final block with correct state_root
        final_block = Block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=correct_state_root,
            body=body,
        )

        # Sign it (placeholder signature for now)
        signed_block = SignedBlock(
            message=final_block,
            signature=Bytes32.zero(),
        )

        return signed_block

    def build_and_apply(
        self,
        slot: Slot,
        attestations: list[SignedVote] | None = None,
        proposer_index: ValidatorIndex | None = None,
    ) -> tuple[SignedBlock, State]:
        """
        Build a block and apply it to get the new state.

        Convenience method that builds the block and runs state_transition.

        Parameters
        ----------
        slot : Slot
            The slot for this block.
        attestations : list[SignedVote], optional
            Attestations to include.
        proposer_index : ValidatorIndex, optional
            The proposer.

        Returns:
        -------
        tuple[SignedBlock, State]
            The block and the state after processing it.
        """
        block = self.build(slot, attestations, proposer_index)
        new_state = self.state.state_transition(block)
        return block, new_state
