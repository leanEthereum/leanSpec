"""
Shared pytest fixtures for forkchoice tests.

Provides mock state for testing fork choice behavior.
"""

from __future__ import annotations

from typing import Type

import pytest

from lean_spec.subspecs.containers import BlockBody, Checkpoint, State
from lean_spec.subspecs.containers.block import AggregatedAttestations, BlockHeader
from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64


class MockState(State):
    """Mock state with configurable latest_justified checkpoint."""

    def __init__(self, latest_justified: Checkpoint) -> None:
        """Initialize mock state with minimal defaults."""
        genesis_config = Config(
            genesis_time=Uint64(0),
        )

        genesis_header = BlockHeader(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(BlockBody(attestations=AggregatedAttestations(data=[]))),
        )

        super().__init__(
            config=genesis_config,
            slot=Slot(0),
            latest_block_header=genesis_header,
            latest_justified=latest_justified,
            latest_finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=Validators(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        )


@pytest.fixture
def mock_state_factory() -> Type[MockState]:
    """Factory fixture for creating MockState instances."""
    return MockState
