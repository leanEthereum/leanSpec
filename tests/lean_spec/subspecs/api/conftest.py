"""Shared test utilities and fixtures for API server tests."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers import Block, BlockBody, State, Validator
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64


@pytest.fixture
def validators() -> Validators:
    """Provide a minimal validator set for tests."""
    return Validators(
        data=[Validator(pubkey=Bytes52(b"\x00" * 52), index=Uint64(i)) for i in range(3)]
    )


@pytest.fixture
def genesis_state(validators: Validators) -> State:
    """Create a genesis state for testing."""
    return State.generate_genesis(Uint64(1704067200), validators)


@pytest.fixture
def genesis_block(genesis_state: State) -> Block:
    """Create a genesis block for testing."""
    return Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


@pytest.fixture
def store(genesis_state: State, genesis_block: Block) -> Store:
    """Create a forkchoice store for testing."""
    return Store.get_forkchoice_store(genesis_state, genesis_block)
