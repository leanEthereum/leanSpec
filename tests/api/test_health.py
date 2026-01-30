"""Tests for the health endpoint."""

import httpx


def test_health_returns_200(server_url: str) -> None:
    """Health endpoint returns 200 status code."""
    response = httpx.get(f"{server_url}/lean/v0/health")
    assert response.status_code == 200


def test_health_content_type_is_json(server_url: str) -> None:
    """Health endpoint returns JSON content type."""
    response = httpx.get(f"{server_url}/lean/v0/health")
    content_type = response.headers.get("content-type", "")
    assert "application/json" in content_type


def test_health_response_structure(server_url: str) -> None:
    """Health endpoint returns expected JSON structure."""
    response = httpx.get(f"{server_url}/lean/v0/health")
    data = response.json()

    assert "status" in data
    assert data["status"] == "healthy"

    assert "service" in data
    assert data["service"] == "lean-rpc-api"
