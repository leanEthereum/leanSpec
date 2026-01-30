"""Tests for the justified checkpoint endpoint."""

import httpx


def test_justified_checkpoint_returns_200(server_url: str) -> None:
    """Justified checkpoint endpoint returns 200 status code."""
    response = httpx.get(f"{server_url}/lean/v0/checkpoints/justified")
    assert response.status_code == 200


def test_justified_checkpoint_content_type_is_json(server_url: str) -> None:
    """Justified checkpoint endpoint returns JSON content type."""
    response = httpx.get(f"{server_url}/lean/v0/checkpoints/justified")
    content_type = response.headers.get("content-type", "")
    assert "application/json" in content_type


def test_justified_checkpoint_has_slot(server_url: str) -> None:
    """Justified checkpoint response has a slot field."""
    response = httpx.get(f"{server_url}/lean/v0/checkpoints/justified")
    data = response.json()

    assert "slot" in data
    assert isinstance(data["slot"], int)
    assert data["slot"] >= 0


def test_justified_checkpoint_has_root(server_url: str) -> None:
    """Justified checkpoint response has a valid root field."""
    response = httpx.get(f"{server_url}/lean/v0/checkpoints/justified")
    data = response.json()

    assert "root" in data
    root = data["root"]

    # Root should be a 0x-prefixed hex string (32 bytes = 66 chars with prefix)
    assert isinstance(root, str)
    assert root.startswith("0x"), "Root must have 0x prefix"
    assert len(root) == 66

    # Should be valid hex
    int(root, 16)
