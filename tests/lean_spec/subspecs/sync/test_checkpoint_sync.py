"""Tests for checkpoint sync client functionality."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from lean_spec.subspecs.api import ApiServer, ApiServerConfig
from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.containers import State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.sync.checkpoint_sync import (
    FINALIZED_STATE_ENDPOINT,
    CheckpointSyncError,
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

    async def test_exception_during_hash_tree_root_returns_false(self) -> None:
        """Unexpected error during state root computation returns False."""
        mock_state = MagicMock()
        mock_state.slot = Slot(0)
        mock_validators = MagicMock()
        mock_validators.__len__ = MagicMock(return_value=3)
        mock_state.validators = mock_validators

        with patch(
            "lean_spec.subspecs.sync.checkpoint_sync.hash_tree_root",
            side_effect=RuntimeError("hash error"),
        ):
            result = verify_checkpoint_state(mock_state)

        assert result is False


class TestFetchFinalizedState:
    """Tests for error handling in fetch_finalized_state."""

    async def test_network_error_raises_checkpoint_sync_error(self) -> None:
        """Network-level failure wraps the error in CheckpointSyncError."""
        real_request = httpx.Request("GET", f"http://example.com{FINALIZED_STATE_ENDPOINT}")
        exc = httpx.RequestError("connection refused", request=real_request)

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=exc)

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=mock_client,
            ),
            pytest.raises(CheckpointSyncError, match="Network error"),
        ):
            await fetch_finalized_state("http://example.com", State)

    @pytest.mark.parametrize(
        ("status_code", "status_text"),
        [
            (404, "Not Found"),
            (500, "Internal Server Error"),
        ],
    )
    async def test_http_error_response_raises_checkpoint_sync_error(
        self, status_code: int, status_text: str
    ) -> None:
        """Non-success HTTP status wraps in CheckpointSyncError with code."""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.text = status_text
        exc = httpx.HTTPStatusError(
            str(status_code),
            request=httpx.Request("GET", "http://example.com"),
            response=mock_response,
        )
        mock_response.raise_for_status = MagicMock(side_effect=exc)

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=mock_client,
            ),
            pytest.raises(CheckpointSyncError, match=f"HTTP error {status_code}"),
        ):
            await fetch_finalized_state("http://example.com", State)

    async def test_corrupt_ssz_raises_checkpoint_sync_error(self) -> None:
        """Corrupt response body wraps deserialization error."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content = b"\xff\xfe corrupt"

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=mock_client,
            ),
            pytest.raises(CheckpointSyncError, match="Failed to fetch state"),
        ):
            await fetch_finalized_state("http://example.com", State)

    async def test_trailing_slash_stripped_from_url(self) -> None:
        """Trailing slash on base URL does not produce double slash."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content = b"\xff\xfe corrupt"

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=mock_client,
            ),
            pytest.raises(CheckpointSyncError),
        ):
            await fetch_finalized_state("http://example.com/", State)

        mock_client.get.assert_called_once_with(
            f"http://example.com{FINALIZED_STATE_ENDPOINT}",
            headers={"Accept": "application/octet-stream"},
        )


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
