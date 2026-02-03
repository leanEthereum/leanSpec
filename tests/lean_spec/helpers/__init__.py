"""Test helpers for leanSpec unit tests."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import TypeVar

from lean_spec.subspecs.containers.validator import ValidatorIndex

from .builders import (
    make_aggregated_attestation,
    make_block,
    make_bytes32,
    make_genesis_block,
    make_genesis_state,
    make_mock_signature,
    make_public_key_bytes,
    make_signature,
    make_signed_attestation,
    make_signed_block,
    make_test_block,
    make_test_status,
    make_validators,
    make_validators_with_keys,
)
from .mocks import MockNoiseSession

TEST_VALIDATOR_ID = ValidatorIndex(0)


_T = TypeVar("_T")


def run_async(coro: Coroutine[object, object, _T]) -> _T:
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


__all__ = [
    # Builders
    "make_aggregated_attestation",
    "make_block",
    "make_bytes32",
    "make_genesis_block",
    "make_genesis_state",
    "make_mock_signature",
    "make_public_key_bytes",
    "make_signature",
    "make_signed_attestation",
    "make_signed_block",
    "make_test_block",
    "make_test_status",
    "make_validators",
    "make_validators_with_keys",
    # Mocks
    "MockNoiseSession",
    # Constants
    "TEST_VALIDATOR_ID",
    # Async utilities
    "run_async",
]
