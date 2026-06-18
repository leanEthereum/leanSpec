"""Tests for the blocks endpoints."""

import httpx

from consensus_testing import reconstruct_block_from_header, signed_block_with_empty_proof
from lean_spec.spec.forks import SignedBlock
from lean_spec.spec.forks.lstar import State


def get_finalized_block(server_url: str) -> httpx.Response:
    """Fetch the finalized signed block from the server."""
    return httpx.get(
        f"{server_url}/lean/v0/blocks/finalized",
        headers={"Accept": "application/octet-stream"},
    )


class TestFinalizedBlock:
    """Tests for the /lean/v0/blocks/finalized endpoint."""

    def test_returns_200(self, server_url: str) -> None:
        """Finalized block endpoint returns 200 status code."""
        response = get_finalized_block(server_url)
        assert response.status_code == 200

    def test_content_type_is_octet_stream(self, server_url: str) -> None:
        """Finalized block endpoint returns octet-stream content type."""
        response = get_finalized_block(server_url)
        content_type = response.headers.get("content-type", "")
        assert "application/octet-stream" in content_type

    def test_served_block_matches_block_rebuilt_from_finalized_state(self, server_url: str) -> None:
        """
        Served signed block equals the block rebuilt from the finalized state.

        The endpoint serves the genesis anchor wrapped in an empty proof.
        Rebuilding the block from the finalized state header reproduces it exactly.
        A full-object match proves the (state, signed block) pair can bootstrap a store.
        """
        block_response = get_finalized_block(server_url)
        signed_block = SignedBlock.decode_bytes(block_response.content)

        state_response = httpx.get(
            f"{server_url}/lean/v0/states/finalized",
            headers={"Accept": "application/octet-stream"},
        )
        state = State.decode_bytes(state_response.content)

        assert signed_block == signed_block_with_empty_proof(reconstruct_block_from_header(state))
