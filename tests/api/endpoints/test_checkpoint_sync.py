"""Tests for the checkpoint sync endpoints (finalized state and justified checkpoint)."""

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


def get_justified_checkpoint(server_url: str) -> httpx.Response:
    """Fetch justified checkpoint from the server."""
    return httpx.get(
        f"{server_url}/lean/v0/checkpoints/justified",
        headers={"Accept": "application/json"},
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

    def test_has_slot(self, server_url: str) -> None:
        """Justified checkpoint response has a slot field."""
        response = get_justified_checkpoint(server_url)
        data = response.json()

        assert "slot" in data
        assert isinstance(data["slot"], int)
        assert data["slot"] >= 0

    def test_has_root(self, server_url: str) -> None:
        """Justified checkpoint response has a valid root field."""
        response = get_justified_checkpoint(server_url)
        data = response.json()

        assert "root" in data
        root = data["root"]

        # Root should be a 0x-prefixed hex string (32 bytes = 66 chars with prefix)
        assert isinstance(root, str)
        assert root.startswith("0x"), "Root must have 0x prefix"
        assert len(root) == 66

        # Should be valid hex
        int(root, 16)
