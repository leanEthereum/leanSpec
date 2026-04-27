"""Shared fixtures for container tests."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.forks.lstar.containers.slot import Slot


@pytest.fixture
def container_key_manager() -> XmssKeyManager:
    """Key manager for container tests."""
    return XmssKeyManager.shared(max_slot=Slot(20))
