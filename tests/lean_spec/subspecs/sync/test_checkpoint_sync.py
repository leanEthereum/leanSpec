"""Tests for checkpoint sync client functionality."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from lean_spec.forks import (
    AttestationSignatures,
    Block,
    BlockSignatures,
    SignedBlock,
)
from lean_spec.forks.lstar import State, Store
from lean_spec.forks.lstar.containers.state import Validators
from lean_spec.subspecs.api import ApiServer, ApiServerConfig
from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.checkpoint_sync import (
    FINALIZED_BLOCK_ENDPOINT,
    FINALIZED_STATE_ENDPOINT,
    CheckpointSyncError,
    fetch_finalized_anchor,
    fetch_finalized_block,
    fetch_finalized_state,
    verify_checkpoint_state,
)
from lean_spec.types import Bytes32, Slot
from tests.lean_spec.helpers import make_mock_signature


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


def _wrap_as_signed_block(block: Block) -> SignedBlock:
    """Build a SignedBlock around a Block using a mock signature.

    The spec retains only Block in Store; tests need a SignedBlock for the
    ``signed_block_getter`` callable, so we construct one with empty
    attestation signatures and a mock proposer signature.
    """
    return SignedBlock(
        block=block,
        signature=BlockSignatures(
            attestation_signatures=AttestationSignatures(data=[]),
            proposer_signature=make_mock_signature(),
        ),
    )


class TestFetchFinalizedBlock:
    """Error-handling and integration tests for ``fetch_finalized_block``."""

    async def test_network_error_raises_checkpoint_sync_error(self) -> None:
        """TCP-level failure surfaces as CheckpointSyncError."""
        transport = _MockTransport(
            exc=httpx.RequestError(
                "connection refused",
                request=httpx.Request("GET", f"http://example.com{FINALIZED_BLOCK_ENDPOINT}"),
            )
        )
        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ),
            pytest.raises(CheckpointSyncError, match="Network error"),
        ):
            await fetch_finalized_block("http://example.com")

    async def test_http_404_raises_checkpoint_sync_error(self) -> None:
        """A 404 (anchor block not retained on server) surfaces clearly."""
        transport = _MockTransport(status=404, content=b"Not Found")
        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ),
            pytest.raises(CheckpointSyncError, match="HTTP error 404"),
        ):
            await fetch_finalized_block("http://example.com")

    async def test_corrupt_ssz_raises_checkpoint_sync_error(self) -> None:
        """Malformed body fails at SignedBlock deserialization."""
        transport = _MockTransport(content=b"\xff\xfe corrupt")
        with (
            patch(
                "lean_spec.subspecs.sync.checkpoint_sync.httpx.AsyncClient",
                return_value=httpx.AsyncClient(transport=transport),
            ),
            pytest.raises(CheckpointSyncError, match="Failed to fetch signed block"),
        ):
            await fetch_finalized_block("http://example.com")

    async def test_client_fetches_signed_block(
        self, base_store: Store, genesis_block: Block
    ) -> None:
        """Client fetches and deserializes the anchor SignedBlock from server."""
        anchor_signed_block = _wrap_as_signed_block(genesis_block)
        anchor_root = hash_tree_root(genesis_block)

        def signed_block_lookup(root: Bytes32) -> SignedBlock | None:
            return anchor_signed_block if root == anchor_root else None

        config = ApiServerConfig(port=15059)
        server = ApiServer(
            config=config,
            store_getter=lambda: base_store,
            signed_block_getter=signed_block_lookup,
        )
        await server.start()
        try:
            signed_block = await fetch_finalized_block("http://127.0.0.1:15059")
            assert signed_block.block.slot == Slot(0)
            assert hash_tree_root(signed_block.block) == anchor_root
        finally:
            await server.aclose()


class TestFetchFinalizedAnchor:
    """Integration tests for the combined ``fetch_finalized_anchor`` helper."""

    async def test_returns_state_block_pair(self, base_store: Store, genesis_block: Block) -> None:
        """Pair satisfies ``signed_block.state_root == hash_tree_root(state)``."""
        anchor_signed_block = _wrap_as_signed_block(genesis_block)
        anchor_root = hash_tree_root(genesis_block)

        def signed_block_lookup(root: Bytes32) -> SignedBlock | None:
            return anchor_signed_block if root == anchor_root else None

        config = ApiServerConfig(port=15060)
        server = ApiServer(
            config=config,
            store_getter=lambda: base_store,
            signed_block_getter=signed_block_lookup,
        )
        await server.start()
        try:
            state, signed_block = await fetch_finalized_anchor("http://127.0.0.1:15060", State)
            assert state.slot == Slot(0)
            assert signed_block.block.state_root == hash_tree_root(state)
        finally:
            await server.aclose()

    async def test_mismatched_pair_raises(self, base_store: Store) -> None:
        """If block.state_root != hash_tree_root(state), raise CheckpointSyncError."""
        # Build a SignedBlock whose state_root deliberately differs from the
        # served state's root, simulating a server that advanced finalization
        # between the two fetches.
        bad_block = Block(
            slot=Slot(0),
            proposer_index=base_store.blocks[base_store.latest_finalized.root].proposer_index,
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"\x01" * 32),
            body=base_store.blocks[base_store.latest_finalized.root].body,
        )
        bad_signed = _wrap_as_signed_block(bad_block)

        def signed_block_lookup(_root: Bytes32) -> SignedBlock | None:
            return bad_signed

        config = ApiServerConfig(port=15061)
        server = ApiServer(
            config=config,
            store_getter=lambda: base_store,
            signed_block_getter=signed_block_lookup,
        )
        await server.start()
        try:
            with pytest.raises(CheckpointSyncError, match="Anchor block / state mismatch"):
                await fetch_finalized_anchor("http://127.0.0.1:15061", State)
        finally:
            await server.aclose()
