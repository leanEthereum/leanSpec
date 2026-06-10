"""Pytest configuration and shared fixtures."""

import os

import pytest
from hypothesis import settings

# Select the test signature scheme before any spec module reads LEAN_ENV.
# lean_spec.config captures LEAN_ENV at import time and defaults to prod otherwise.
if "LEAN_ENV" not in os.environ:
    os.environ["LEAN_ENV"] = "test"

from consensus_testing import (  # noqa: E402
    make_genesis_block,
    make_genesis_state,
    make_genesis_store,
)
from consensus_testing.keys import XmssKeyManager  # noqa: E402
from lean_spec.spec.forks import Slot  # noqa: E402
from lean_spec.spec.forks.lstar import State, Store  # noqa: E402
from lean_spec.spec.forks.lstar.containers import Block  # noqa: E402
from lean_spec.spec.forks.lstar.spec import LstarSpec  # noqa: E402

# Disable hypothesis deadlines for the whole suite.
settings.register_profile("no_deadline", deadline=None)
settings.load_profile("no_deadline")


@pytest.fixture(scope="session")
def spec() -> LstarSpec:
    """Active fork spec used to drive state transition and forkchoice operations."""
    return LstarSpec()


@pytest.fixture
def key_manager() -> XmssKeyManager:
    """XMSS key manager for signing attestations."""
    return XmssKeyManager.shared(max_slot=Slot(20))


@pytest.fixture
def genesis_state() -> State:
    """Genesis state with 3 null-key validators at time 0."""
    return make_genesis_state(num_validators=3)


@pytest.fixture
def genesis_block(genesis_state: State) -> Block:
    """Genesis block matching the null-key genesis state."""
    return make_genesis_block(genesis_state)


@pytest.fixture
def base_store() -> Store:
    """Fork choice store on null-key genesis with 3 validators."""
    return make_genesis_store(num_validators=3, keyed=False)


@pytest.fixture
def keyed_store() -> Store:
    """Fork choice store on keyed genesis with 8 validators, owned by validator 0."""
    return make_genesis_store(num_validators=8)
