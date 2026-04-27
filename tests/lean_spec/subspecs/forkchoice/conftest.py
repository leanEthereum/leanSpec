"""
Shared pytest fixtures for forkchoice tests.

Provides mock state for testing fork choice behavior.
"""

from __future__ import annotations

import pytest

from lean_spec.forks.lstar import Store
from lean_spec.types import Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID, make_store


@pytest.fixture
def pruning_store() -> Store:
    """Store with 3 validators for pruning tests."""
    return make_store(num_validators=3, validator_id=TEST_VALIDATOR_ID)


@pytest.fixture
def sample_store(store_factory):
    """Store with 8 validators, genesis_time=1000, time=100."""
    store = store_factory(num_validators=8, genesis_time=1000)
    return store.model_copy(update={"time": Uint64(100)})
