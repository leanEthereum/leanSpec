"""Invalid block processing tests for the devnet fork."""

from lean_spec_tests import BlockBuilder, ConsensusChainTestFiller

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.types import Uint64


def test_invalid_proposer(consensus_chain_test: ConsensusChainTestFiller) -> None:
    """
    Test that blocks with incorrect proposer are rejected.

    The proposer index must match the round-robin selection for that slot.
    """
    from lean_spec.subspecs.containers.block import Block, BlockBody, SignedBlock
    from lean_spec.subspecs.containers.block.types import Attestations
    from lean_spec.types import Bytes32, ValidatorIndex

    genesis = State.generate_genesis(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    # For slot 1, the correct proposer is: 1 % 4 = 1
    # Let's create a block with wrong proposer (index 2)
    wrong_proposer = ValidatorIndex(2)

    # We need to manually construct the block to bypass BlockBuilder's correct logic
    block = SignedBlock(
        message=Block(
            slot=Slot(1),
            proposer_index=wrong_proposer,  # WRONG! Should be 1
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body=BlockBody(attestations=Attestations(data=[])),
        ),
        signature=Bytes32.zero(),
    )

    # This should fail with "Incorrect block proposer"
    consensus_chain_test(
        pre=genesis,
        blocks=[block],
        expect_exception=AssertionError,
    )
