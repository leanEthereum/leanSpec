"""
Shared pytest fixtures for all lean_spec tests.

Provides core fixtures used across multiple test modules.
Import these fixtures automatically via pytest discovery.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.containers import Block, State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from tests.lean_spec.helpers import (
    GenesisData,
    make_genesis_block,
    make_genesis_data,
    make_genesis_state,
    make_store,
)


@pytest.fixture
def key_manager() -> XmssKeyManager:
    """XMSS key manager for signing attestations."""
    return XmssKeyManager.shared(max_slot=Slot(20))


_DEFAULT_VALIDATOR_ID = ValidatorIndex(0)


@pytest.fixture
def store_factory(key_manager: XmssKeyManager) -> Callable[..., Store]:
    """Factory for creating stores with configurable validators."""

    def _create(
        num_validators: int = 12,
        validator_id: ValidatorIndex | None = _DEFAULT_VALIDATOR_ID,
        genesis_time: int = 0,
    ) -> Store:
        return make_store(
            num_validators=num_validators,
            validator_id=validator_id,
            genesis_time=genesis_time,
            key_manager=key_manager,
        )

    return _create


# Plain genesis (null public keys, no key_manager)


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
    return Store.from_anchor(
        genesis_state,
        genesis_block,
        validator_id=ValidatorIndex(0),
    )


# Keyed genesis (real XMSS keys, 12 validators)


@pytest.fixture
def keyed_genesis(key_manager: XmssKeyManager) -> GenesisData:
    """Genesis data with real XMSS keys (12 validators)."""
    return make_genesis_data(num_validators=12, key_manager=key_manager)


@pytest.fixture
def keyed_genesis_state(keyed_genesis: GenesisData) -> State:
    """Genesis state with real XMSS keys."""
    return keyed_genesis.state


@pytest.fixture
def keyed_genesis_block(keyed_genesis: GenesisData) -> Block:
    """Genesis block matching the keyed genesis state."""
    return keyed_genesis.block


@pytest.fixture
def keyed_store(keyed_genesis: GenesisData) -> Store:
    """Fork choice store with real XMSS keys, validator_id=0."""
    return keyed_genesis.store


@pytest.fixture
def observer_store(keyed_genesis_state: State, keyed_genesis_block: Block) -> Store:
    """Fork choice store with validator_id=None (non-validator observer)."""
    return Store.from_anchor(keyed_genesis_state, keyed_genesis_block, validator_id=None)
