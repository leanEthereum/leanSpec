"""
Shared pytest fixtures for forkchoice tests.

Provides mock state for testing fork choice behavior.
"""

from __future__ import annotations

import pytest

from lean_spec.node.chain.clock import Interval
from lean_spec.spec.forks.lstar import Store
from tests.lean_spec.helpers import TEST_VALIDATOR_INDEX, make_store


@pytest.fixture
def pruning_store() -> Store:
    """Store with 3 validators for pruning tests."""
    return make_store(num_validators=3, validator_index=TEST_VALIDATOR_INDEX)


@pytest.fixture
def sample_store(store_factory):
    """Store with 8 validators, genesis_time=1000, time=100."""
    store = store_factory(num_validators=8, genesis_time=1000)
    store.time = Interval(100)
    return store
