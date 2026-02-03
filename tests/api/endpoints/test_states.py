"""Tests for the states endpoints."""

import httpx

from lean_spec.subspecs.containers import State

# =============================================================================
# HELPERS
# =============================================================================


def get_finalized_state(server_url: str) -> httpx.Response:
    """Fetch finalized state from the server."""
    return httpx.get(
        f"{server_url}/lean/v0/states/finalized",
        headers={"Accept": "application/octet-stream"},
    )


# =============================================================================
# TESTS
# =============================================================================


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

    def test_ssz_deserializes(self, server_url: str) -> None:
        """Finalized state SSZ bytes deserialize to a valid State object."""
        response = get_finalized_state(server_url)
        state = State.decode_bytes(response.content)
        assert state is not None

    def test_has_valid_slot(self, server_url: str) -> None:
        """Finalized state has a non-negative slot."""
        response = get_finalized_state(server_url)
        state = State.decode_bytes(response.content)
        assert int(state.slot) >= 0

    def test_has_validators(self, server_url: str) -> None:
        """Finalized state has at least one validator."""
        response = get_finalized_state(server_url)
        state = State.decode_bytes(response.content)
        assert len(state.validators) > 0
