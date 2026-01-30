"""Tests for the finalized state endpoint with deep SSZ validation."""

import httpx

from lean_spec.subspecs.containers import State


def test_finalized_state_returns_200(server_url: str) -> None:
    """Finalized state endpoint returns 200 status code."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    assert response.status_code == 200


def test_finalized_state_content_type_is_octet_stream(server_url: str) -> None:
    """Finalized state endpoint returns octet-stream content type."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    content_type = response.headers.get("content-type", "")
    assert "application/octet-stream" in content_type


def test_finalized_state_ssz_deserializes(server_url: str) -> None:
    """Finalized state SSZ bytes deserialize to a valid State object."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    ssz_bytes = response.content

    # This will raise if the bytes are not valid SSZ for State
    state = State.decode_bytes(ssz_bytes)

    # Basic structural validation
    assert state is not None


def test_finalized_state_has_valid_slot(server_url: str) -> None:
    """Finalized state has a non-negative slot."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    state = State.decode_bytes(response.content)

    assert int(state.slot) >= 0


def test_finalized_state_has_validators(server_url: str) -> None:
    """Finalized state has at least one validator."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    state = State.decode_bytes(response.content)

    assert len(state.validators) > 0


def test_finalized_state_has_valid_config(server_url: str) -> None:
    """Finalized state has a valid config with genesis time."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    state = State.decode_bytes(response.content)

    # Genesis time should be a positive timestamp
    assert int(state.config.genesis_time) >= 0


def test_finalized_state_has_valid_checkpoints(server_url: str) -> None:
    """Finalized state has valid justified and finalized checkpoints."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    state = State.decode_bytes(response.content)

    # Checkpoints should have valid slots
    assert int(state.latest_justified.slot) >= 0
    assert int(state.latest_finalized.slot) >= 0

    # Finalized slot should not exceed justified slot
    assert state.latest_finalized.slot <= state.latest_justified.slot


def test_finalized_state_has_valid_block_header(server_url: str) -> None:
    """Finalized state has a valid latest block header."""
    response = httpx.get(f"{server_url}/lean/v0/states/finalized")
    state = State.decode_bytes(response.content)

    # Block header should have valid slot and proposer index
    assert int(state.latest_block_header.slot) >= 0
    assert int(state.latest_block_header.proposer_index) >= 0
