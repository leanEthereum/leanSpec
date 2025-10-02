"""ConsensusEnvironment helper for building consensus test states dynamically."""

from typing import List

from lean_spec.subspecs.containers.block import Block, BlockBody, SignedBlock
from lean_spec.subspecs.containers.block.types import Attestations
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.containers.vote import SignedVote, Vote
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


class ConsensusEnvironment:
    """Dynamic state builder for consensus tests."""

    def __init__(self, state: State):
        """
        Initialize with an existing state.

        Parameters
        ----------
        state : State
            The initial consensus state.
        """
        self.state = state

    @classmethod
    def from_genesis(
        cls,
        genesis_time: Uint64,
        num_validators: Uint64,
    ) -> "ConsensusEnvironment":
        """
        Create a new environment from genesis.

        Parameters
        ----------
        genesis_time : Uint64
            Unix timestamp for genesis.
        num_validators : Uint64
            Number of validators at genesis.

        Returns:
        -------
        ConsensusEnvironment
            A new environment with genesis state.
        """
        genesis_state = State.generate_genesis(
            genesis_time=genesis_time,
            num_validators=num_validators,
        )
        return cls(state=genesis_state)

    def make_block(
        self,
        slot: Slot,
        attestations: List[SignedVote] | None = None,
        proposer_index: ValidatorIndex | None = None,
    ) -> Block:
        """
        Create a block at the given slot.

        Parameters
        ----------
        slot : Slot
            The slot for this block.
        attestations : List[SignedVote], optional
            Attestations to include in the block. Defaults to empty list.
        proposer_index : ValidatorIndex, optional
            The proposer for this block. If None, uses the spec's proposer
            selection for the slot.

        Returns:
        -------
        Block
            A new unsigned block ready to be signed.
        """
        # Default to empty attestations
        if attestations is None:
            attestations = []

        # Determine proposer if not specified
        if proposer_index is None:
            # Use the spec's proposer selection logic
            proposer_index = ValidatorIndex(int(slot) % int(self.state.config.num_validators))

        # Get parent root from latest block header
        parent_root = hash_tree_root(self.state.latest_block_header)

        # Build block body
        body = BlockBody(attestations=Attestations(data=attestations))

        # Create the block (state_root will be filled by state_transition)
        block = Block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),  # Filled during state_transition
            body=body,
        )

        return block

    def make_signed_block(
        self,
        slot: Slot,
        attestations: List[SignedVote] | None = None,
        proposer_index: ValidatorIndex | None = None,
    ) -> SignedBlock:
        """
        Create a signed block at the given slot.

        Parameters
        ----------
        slot : Slot
            The slot for this block.
        attestations : List[SignedVote], optional
            Attestations to include in the block.
        proposer_index : ValidatorIndex, optional
            The proposer for this block.

        Returns:
        -------
        SignedBlock
            A new signed block (signature is placeholder for now).
        """
        block = self.make_block(
            slot=slot,
            attestations=attestations,
            proposer_index=proposer_index,
        )

        # For now, use a zero signature (signature validation not implemented)
        # In the future, this would use proper BLS signatures
        return SignedBlock(
            message=block,
            signature=Bytes32.zero(),  # Placeholder signature
        )

    def make_attestation(
        self,
        slot: Slot,
        head: Checkpoint,
        target: Checkpoint,
        source: Checkpoint,
        validator_index: ValidatorIndex,
    ) -> SignedVote:
        """
        Create a signed attestation (vote).

        Parameters
        ----------
        slot : Slot
            The slot for which this vote is cast.
        head : Checkpoint
            The validator's perceived head of the chain.
        target : Checkpoint
            The justified checkpoint the validator is voting for.
        source : Checkpoint
            The last justified checkpoint known to the validator.
        validator_index : ValidatorIndex
            The validator making this attestation.

        Returns:
        -------
        SignedVote
            A new signed vote (signature is placeholder for now).
        """
        vote = Vote(
            validator_id=validator_index,
            slot=slot,
            head=head,
            target=target,
            source=source,
        )

        # For now, use a zero signature (signature validation not implemented)
        return SignedVote(
            data=vote,
            signature=Bytes32.zero(),  # Placeholder signature
        )

    def apply_block(self, signed_block: SignedBlock) -> "ConsensusEnvironment":
        """
        Apply a block to the state and return updated environment.

        Parameters
        ----------
        signed_block : SignedBlock
            The signed block to apply.

        Returns:
        -------
        ConsensusEnvironment
            A new environment with the updated state.
        """
        new_state = self.state.state_transition(
            signed_block=signed_block,
            valid_signatures=False,  # We use placeholder signatures
        )
        return ConsensusEnvironment(state=new_state)

    def copy(self) -> "ConsensusEnvironment":
        """
        Create a copy of this environment.

        Returns:
        -------
        ConsensusEnvironment
            A new environment with a copy of the current state.
        """
        return ConsensusEnvironment(state=self.state)
