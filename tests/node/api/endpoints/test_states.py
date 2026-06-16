"""Tests for the states endpoints."""

import httpx

from lean_spec.spec.forks.lstar import State


def get_finalized_state(server_url: str) -> httpx.Response:
    """Fetch finalized state from the server."""
    return httpx.get(
        f"{server_url}/lean/v0/states/finalized",
        headers={"Accept": "application/octet-stream"},
    )


class TestFinalizedState:
    """Tests for the /lean/v0/states/finalized endpoint."""

    def test_returns_200(self, server_url: str) -> None:
        """Finalized state endpoint returns 200 status code."""
        response = get_finalized_state(server_url)
        assert response.status_code == 200

    def test_content_type_is_octet_stream(self, server_url: str) -> None:
        """Finalized state endpoint returns octet-stream content type."""
        response = get_finalized_state(server_url)
        content_type = response.headers.get("content-type", "")
        assert "application/octet-stream" in content_type

    def test_finalized_state_is_genesis(self, server_url: str) -> None:
        """Finalized state decodes to the genesis state: slot 0 with three validators."""
        state = State.decode_bytes(get_finalized_state(server_url).content)
        assert int(state.slot) == 0
        assert len(state.validators) == 3
