"""Tests for checkpoint sync client functionality."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


class _MockTransport(httpx.AsyncBaseTransport):
    """Injects a canned HTTP response or error without a real network.

    Used by fetch_finalized_state tests to exercise error-handling paths
    through real httpx machinery rather than patching context managers.
    """

    def __init__(
        self,
        *,
        status: int = 200,
        content: bytes = b"",
        exc: Exception | None = None,
    ) -> None:
        self._status = status
        self._content = content
        self._exc = exc

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._exc is not None:
            raise self._exc
        return httpx.Response(self._status, content=self._content)


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

    async def test_exception_during_hash_tree_root_returns_false(
        self, genesis_state: State
    ) -> None:
        """Verification never crashes the caller on unexpected hashing errors.

        Any exception from the state root computation is caught and treated
        as a verification failure so startup can abort cleanly.
        """
        with patch(
            "lean_spec.subspecs.sync.checkpoint_sync.hash_tree_root",
            side_effect=RuntimeError("hash error"),
        ):
            result = verify_checkpoint_state(genesis_state)

        assert result is False


class TestFetchFinalizedState:
    """Tests for error handling when fetching checkpoint state over HTTP.

    Each test injects failures via _MockTransport so the real httpx client
    runs unchanged. This exercises the actual error-wrapping logic without
    patching context managers or response internals.
    """

    async def test_network_error_raises_checkpoint_sync_error(self) -> None:
        """TCP-level failure surfaces as CheckpointSyncError with the URL.

        Operators need the URL in the error message to diagnose which endpoint
        is unreachable (DNS failure, firewall block, wrong host).
        """
        transport = _MockTransport(
            exc=httpx.RequestError(
                "connection refused",
                request=httpx.Request("GET", f"http://example.com{FINALIZED_STATE_ENDPOINT}"),
            )
        )

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
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
        """Non-success HTTP status surfaces as CheckpointSyncError with the code.

        Covers both misconfigured endpoints (404) and server-side failures (500).
        The status code in the message helps operators identify the failure tier.
        """
        transport = _MockTransport(status=status_code, content=status_text.encode())

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ),
            pytest.raises(CheckpointSyncError, match=f"HTTP error {status_code}"),
        ):
            await fetch_finalized_state("http://example.com", State)

    async def test_corrupt_ssz_raises_checkpoint_sync_error(self) -> None:
        """Corrupt response body surfaces as CheckpointSyncError.

        A 200 response with malformed SSZ bytes fails at deserialization.
        This catches truncated downloads or servers that return JSON instead
        of the expected binary format.
        """
        transport = _MockTransport(content=b"\xff\xfe corrupt")

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ),
            pytest.raises(CheckpointSyncError, match="Failed to fetch state"),
        ):
            await fetch_finalized_state("http://example.com", State)

    async def test_trailing_slash_stripped_from_url(self) -> None:
        """Trailing slash on base URL does not produce a double slash in the request.

        Operators commonly configure base URLs with trailing slashes.
        The endpoint must be appended cleanly regardless of input format.
        """
        captured: list[str] = []

        class _CapturingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                captured.append(str(request.url))
                return httpx.Response(200, content=b"\xff corrupt")

        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=_CapturingTransport()),
            ),
            pytest.raises(CheckpointSyncError),
        ):
            await fetch_finalized_state("http://example.com/", State)

        assert captured == [f"http://example.com{FINALIZED_STATE_ENDPOINT}"]


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
