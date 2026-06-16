"""Tests for the blocks endpoints."""

import httpx

from lean_spec.spec.crypto.merkleization import hash_tree_root
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

    def test_ssz_deserializes(self, server_url: str) -> None:
        """Finalized block SSZ bytes deserialize to a valid SignedBlock object."""
        response = get_finalized_block(server_url)
        signed_block = SignedBlock.decode_bytes(response.content)
        assert signed_block is not None

    def test_state_root_matches_finalized_state(self, server_url: str) -> None:
        """
        Returned block's state root equals the finalized state's hash tree root.

        Store creation from a checkpoint asserts exactly this.
        If it fails, the (state, signed block) pair cannot bootstrap a store.
        """
        block_response = get_finalized_block(server_url)
        signed_block = SignedBlock.decode_bytes(block_response.content)

        state_response = httpx.get(
            f"{server_url}/lean/v0/states/finalized",
            headers={"Accept": "application/octet-stream"},
        )
        state = State.decode_bytes(state_response.content)

        assert signed_block.block.state_root == hash_tree_root(state)
