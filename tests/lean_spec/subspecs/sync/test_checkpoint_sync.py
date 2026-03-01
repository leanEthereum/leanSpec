"""Tests for checkpoint sync client functionality."""

from __future__ import annotations

from unittest.mock import MagicMock

from lean_spec.subspecs.api import ApiServer, ApiServerConfig
from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.containers import State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.sync.checkpoint_sync import (
    fetch_finalized_state,
    verify_checkpoint_state,
)


class TestStateVerification:
    """Tests for checkpoint state verification logic."""

    async def test_valid_state_passes_verification(self, genesis_state: State) -> None:
        """Valid state with validators passes verification checks."""
        result = verify_checkpoint_state(genesis_state)
        assert result is True

    async def test_state_without_validators_fails_verification(self, genesis_state: State) -> None:
        """State with no validators fails verification."""
        empty_state = State(
            config=genesis_state.config,
            slot=genesis_state.slot,
            latest_block_header=genesis_state.latest_block_header,
            latest_justified=genesis_state.latest_justified,
            latest_finalized=genesis_state.latest_finalized,
            historical_block_hashes=genesis_state.historical_block_hashes,
            justified_slots=genesis_state.justified_slots,
            validators=Validators(data=[]),
            justifications_roots=genesis_state.justifications_roots,
            justifications_validators=genesis_state.justifications_validators,
        )

        result = verify_checkpoint_state(empty_state)
        assert result is False

    async def test_state_exceeding_validator_limit_fails(self) -> None:
        """State with more validators than VALIDATOR_REGISTRY_LIMIT fails."""
        # Use a mock because SSZList enforces LIMIT at construction time,
        # preventing creation of a real State with too many validators.
        mock_state = MagicMock()
        mock_state.slot = Slot(0)
        mock_validators = MagicMock()
        mock_validators.__len__ = MagicMock(return_value=int(VALIDATOR_REGISTRY_LIMIT) + 1)
        mock_state.validators = mock_validators

        result = verify_checkpoint_state(mock_state)
        assert result is False


class TestCheckpointSyncClientServerIntegration:
    """Integration tests for checkpoint sync client fetching from server."""

    async def test_client_fetches_and_deserializes_state(self, base_store: Store) -> None:
        """Client successfully fetches and deserializes state from server."""
        config = ApiServerConfig(port=15058)
        server = ApiServer(config=config, store_getter=lambda: base_store)

        await server.start()

        try:
            state = await fetch_finalized_state("http://127.0.0.1:15058", State)

            assert state is not None
            assert state.slot == Slot(0)

            is_valid = verify_checkpoint_state(state)
            assert is_valid is True

        finally:
            await server.aclose()
