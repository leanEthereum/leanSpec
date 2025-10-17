"""Filler for ConsensusChainTest fixtures."""

from typing import Callable, List

from lean_spec.subspecs.containers.block import SignedBlock
from lean_spec.subspecs.containers.state import State
from lean_spec.types import Uint64

from ..consensus_env import ConsensusEnvironment
from ..spec_fixtures.chain import ConsensusChainTest


def fill_consensus_chain_test(
    genesis_time: Uint64,
    num_validators: Uint64,
    blocks_builder: Callable[[ConsensusEnvironment], List[SignedBlock]],
    expect_invalid: bool = False,
) -> ConsensusChainTest:
    """
    Generate a ConsensusChainTest fixture.

    This filler uses the "spec as oracle" pattern:
    1. Start with genesis state
    2. Use blocks_builder to create blocks
    3. Run the spec's state_transition to get expected post state
    4. Return the complete test fixture

    Parameters
    ----------
    genesis_time : Uint64
        Unix timestamp for genesis.
    num_validators : Uint64
        Number of validators at genesis.
    blocks_builder : Callable[[ConsensusEnvironment], List[SignedBlock]]
        A function that takes a ConsensusEnvironment and returns a list
        of blocks to process. The environment provides helpers to create
        blocks and attestations.
    expect_invalid : bool, optional
        If True, the test expects the chain to be invalid. The filler
        will still try to process blocks, and if any fail, post will be None.

    Returns:
    -------
    ConsensusChainTest
        A complete chain test fixture ready for serialization.
    """
    # Start with genesis
    env = ConsensusEnvironment.from_genesis(
        genesis_time=genesis_time,
        num_validators=num_validators,
    )
    pre_state = env.state

    # Build blocks using the provided builder
    blocks = blocks_builder(env)

    # Run the spec to get expected post state
    post_state: State | None = None
    try:
        state = pre_state
        for block in blocks:
            state = state.state_transition(
                signed_block=block,
                valid_signatures=False,  # We use placeholder signatures
            )
        post_state = state
    except (AssertionError, ValueError) as e:
        # If we expect invalid, this is fine
        if expect_invalid:
            post_state = None
        else:
            # Re-raise if we expected this to be valid
            raise AssertionError(f"Unexpected error processing blocks: {e}") from e

    # If we expected invalid but got valid, that's an error
    if expect_invalid and post_state is not None:
        raise AssertionError("Expected invalid chain but processing succeeded")

    return ConsensusChainTest(
        pre=pre_state,
        blocks=blocks,
        post=post_state,
    )
