"""Test helpers for leanSpec unit tests."""

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
    make_validators,
    make_validators_with_keys,
)
from .mocks import MockNoiseSession

TEST_VALIDATOR_ID = ValidatorIndex(0)


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
    "make_validators",
    "make_validators_with_keys",
    # Mocks
    "MockNoiseSession",
    # Constants
    "TEST_VALIDATOR_ID",
]
