"""Tests for the health endpoint."""

import httpx

from lean_spec.subspecs.api.endpoints import health


def get_health(server_url: str) -> httpx.Response:
    """Fetch health status from the server."""
    return httpx.get(
        f"{server_url}/lean/v0/health",
        headers={"Accept": "application/json"},
    )


def test_health_returns_200(server_url: str) -> None:
    """Health endpoint returns 200 status code."""
    response = get_health(server_url)
    assert response.status_code == 200


def test_health_content_type_is_json(server_url: str) -> None:
    """Health endpoint returns JSON content type."""
    response = get_health(server_url)
    assert "application/json" in response.headers.get("content-type", "")


def test_health_response_structure(server_url: str) -> None:
    """Health endpoint returns expected JSON structure."""
    response = get_health(server_url)
    data = response.json()

    assert "status" in data
    assert data["status"] == "ok"

    assert "slot" in data
    assert isinstance(data["slot"], int)

    assert "synced" in data
    assert isinstance(data["synced"], bool)
