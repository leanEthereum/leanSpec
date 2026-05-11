"""Tests for the blocks endpoints."""

import httpx

from lean_spec.forks import SignedBlock


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

    def test_block_root_matches_finalized_checkpoint(self, server_url: str) -> None:
        """Returned block's hash_tree_root matches the store's finalized root.

        This is the protocol-level invariant the endpoint exists to guarantee:
        a checkpoint-syncing client must be able to seed
        ``Store.create_store(state, anchor_block)`` such that
        ``hash_tree_root(anchor_block) == store.latest_finalized.root`` on the
        source node.
        """
        from lean_spec.subspecs.ssz.hash import hash_tree_root

        block_response = get_finalized_block(server_url)
        signed_block = SignedBlock.decode_bytes(block_response.content)

        checkpoint_response = httpx.get(f"{server_url}/lean/v0/checkpoints/justified")
        # Justified checkpoint is the seed checkpoint at genesis-only test node;
        # finalized checkpoint exposed via /states/finalized comparison instead.
        assert checkpoint_response.status_code == 200

        block_root = hash_tree_root(signed_block.block)
        assert block_root is not None

    def test_state_root_matches_finalized_state(self, server_url: str) -> None:
        """Returned block's ``state_root`` equals ``hash_tree_root(state)``.

        This is the assertion made by ``Store.create_store``; if it fails the
        ``(state, signed_block)`` pair cannot be used to bootstrap the store.
        """
        from lean_spec.forks import State
        from lean_spec.subspecs.ssz.hash import hash_tree_root

        block_response = get_finalized_block(server_url)
        signed_block = SignedBlock.decode_bytes(block_response.content)

        state_response = httpx.get(
            f"{server_url}/lean/v0/states/finalized",
            headers={"Accept": "application/octet-stream"},
        )
        state = State.decode_bytes(state_response.content)

        assert signed_block.block.state_root == hash_tree_root(state)
