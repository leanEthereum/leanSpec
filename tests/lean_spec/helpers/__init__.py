"""Test helpers for leanSpec unit tests."""

from __future__ import annotations

from lean_spec.subspecs.containers.validator import ValidatorIndex

from .builders import (
    GenesisData,
    create_mock_sync_service,
    make_aggregated_attestation,
    make_aggregated_proof,
    make_attestation_data,
    make_attestation_data_simple,
    make_block,
    make_bytes32,
    make_challenge_data,
    make_checkpoint,
    make_empty_block_body,
    make_genesis_block,
    make_genesis_data,
    make_genesis_state,
    make_keyed_genesis_state,
    make_mock_signature,
    make_signed_aggregated_attestation,
    make_signed_attestation,
    make_signed_block,
    make_signed_block_from_store,
    make_store,
    make_store_with_attestation_data,
    make_store_with_attestation_signatures,
    make_test_block,
    make_test_status,
    make_validators,
    make_validators_from_key_manager,
)
from .mocks import (
    MockEventSource,
    MockForkchoiceStore,
    MockNetworkRequester,
    RecordedCall,
    RecordingSyncDatabase,
)

TEST_VALIDATOR_ID = ValidatorIndex(0)


__all__ = [
    # Builders
    "GenesisData",
    "create_mock_sync_service",
    "make_aggregated_attestation",
    "make_aggregated_proof",
    "make_attestation_data",
    "make_attestation_data_simple",
    "make_block",
    "make_bytes32",
    "make_challenge_data",
    "make_checkpoint",
    "make_empty_block_body",
    "make_genesis_block",
    "make_genesis_data",
    "make_genesis_state",
    "make_keyed_genesis_state",
    "make_mock_signature",
    "make_signed_aggregated_attestation",
    "make_signed_attestation",
    "make_signed_block",
    "make_signed_block_from_store",
    "make_store",
    "make_store_with_attestation_data",
    "make_store_with_attestation_signatures",
    "make_test_block",
    "make_test_status",
    "make_validators",
    "make_validators_from_key_manager",
    # Mocks
    "MockEventSource",
    "MockForkchoiceStore",
    "MockNetworkRequester",
    "RecordedCall",
    "RecordingSyncDatabase",
    # Constants
    "TEST_VALIDATOR_ID",
]
