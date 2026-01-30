"""Tests for the finalized state endpoint with SSZ validation."""

import httpx

from lean_spec.subspecs.containers import State


def test_finalized_state_returns_200(server_url: str) -> None:
    """Finalized state endpoint returns 200 status code."""
    response = httpx.get(
        f"{server_url}/lean/v0/states/finalized",
        headers={"Accept": "application/octet-stream"},
    )
    assert response.status_code == 200


def test_finalized_state_content_type_is_octet_stream(server_url: str) -> None:
    """Finalized state endpoint returns octet-stream content type."""
    response = httpx.get(
        f"{server_url}/lean/v0/states/finalized",
        headers={"Accept": "application/octet-stream"},
    )
    content_type = response.headers.get("content-type", "")
    assert "application/octet-stream" in content_type


def test_finalized_state_ssz_deserializes(server_url: str) -> None:
    """Finalized state SSZ bytes deserialize to a valid State object."""
    response = httpx.get(
        f"{server_url}/lean/v0/states/finalized",
        headers={"Accept": "application/octet-stream"},
    )
    state = State.decode_bytes(response.content)
    assert state is not None


def test_finalized_state_has_valid_slot(server_url: str) -> None:
    """Finalized state has a non-negative slot."""
    response = httpx.get(
        f"{server_url}/lean/v0/states/finalized",
        headers={"Accept": "application/octet-stream"},
    )
    state = State.decode_bytes(response.content)
    assert int(state.slot) >= 0


def test_finalized_state_has_validators(server_url: str) -> None:
    """Finalized state has at least one validator."""
    response = httpx.get(
        f"{server_url}/lean/v0/states/finalized",
        headers={"Accept": "application/octet-stream"},
    )
    state = State.decode_bytes(response.content)
    assert len(state.validators) > 0
