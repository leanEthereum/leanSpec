"""
Shared pytest fixtures for all lean_spec tests.

Provides core fixtures used across multiple test modules.
Import these fixtures automatically via pytest discovery.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers import Block, State
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from tests.lean_spec.helpers import make_genesis_block, make_genesis_state


@pytest.fixture
def genesis_state() -> State:
    """Genesis state with 3 validators at time 0."""
    return make_genesis_state(num_validators=3, genesis_time=0)


@pytest.fixture
def genesis_block(genesis_state: State) -> Block:
    """Genesis block matching the genesis_state fixture."""
    return make_genesis_block(genesis_state)


@pytest.fixture
def base_store(genesis_state: State, genesis_block: Block) -> Store:
    """Fork choice store initialized with genesis."""
    return Store.get_forkchoice_store(
        genesis_state,
        genesis_block,
        validator_id=ValidatorIndex(0),
    )
