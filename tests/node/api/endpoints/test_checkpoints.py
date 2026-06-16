"""Tests for the checkpoints endpoints."""

import httpx


def get_justified_checkpoint(server_url: str) -> httpx.Response:
    """Fetch justified checkpoint from the server."""
    return httpx.get(
        f"{server_url}/lean/v0/checkpoints/justified",
        headers={"Accept": "application/json"},
    )


class TestJustifiedCheckpoint:
    """Tests for the /lean/v0/checkpoints/justified endpoint."""

    def test_returns_200(self, server_url: str) -> None:
        """Justified checkpoint endpoint returns 200 status code."""
        response = get_justified_checkpoint(server_url)
        assert response.status_code == 200

    def test_content_type_is_json(self, server_url: str) -> None:
        """Justified checkpoint endpoint returns JSON content type."""
        response = get_justified_checkpoint(server_url)
        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type

    def test_justified_checkpoint_is_genesis(self, server_url: str) -> None:
        """At genesis the justified checkpoint is the genesis block at slot 0."""
        head = httpx.get(f"{server_url}/lean/v0/fork_choice").json()["head"]
        assert get_justified_checkpoint(server_url).json() == {"slot": 0, "root": head}
