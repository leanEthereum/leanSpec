"""Tests for unknown route handling."""

import httpx


def test_unknown_root_route_returns_404(server_url: str) -> None:
    """Unknown route at root level returns 404."""
    response = httpx.get(f"{server_url}/unknown")
    assert response.status_code == 404


def test_unknown_api_route_returns_404(server_url: str) -> None:
    """Unknown route under API namespace returns 404."""
    response = httpx.get(f"{server_url}/lean/v0/unknown")
    assert response.status_code == 404
