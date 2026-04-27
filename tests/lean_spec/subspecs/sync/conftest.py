"""
Shared pytest fixtures for sync service tests.

Peer ID and connection state fixtures are inherited from the parent conftest.
"""

from __future__ import annotations

import pytest

from lean_spec.forks.lstar.containers import Checkpoint
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.types import Bytes32


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Sample checkpoint for sync tests."""
    return Checkpoint(root=Bytes32.zero(), slot=Slot(100))


@pytest.fixture
def sample_status(sample_checkpoint: Checkpoint) -> Status:
    """Sample Status message for sync tests."""
    return Status(
        finalized=sample_checkpoint,
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
    )
