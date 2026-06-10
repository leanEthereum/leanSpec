"""Tests for the fork choice endpoint."""

from __future__ import annotations

import httpx

ZERO_ROOT = "0x" + "00" * 32


def get_fork_choice(server_url: str) -> httpx.Response:
    """Fetch fork choice tree from the server."""
    return httpx.get(
        f"{server_url}/lean/v0/fork_choice",
        headers={"Accept": "application/json"},
    )


class TestForkChoice:
    """Tests for the /lean/v0/fork_choice endpoint."""

    def test_returns_200(self, server_url: str) -> None:
        """Fork choice endpoint returns 200 status code."""
        response = get_fork_choice(server_url)
        assert response.status_code == 200

    def test_content_type_is_json(self, server_url: str) -> None:
        """Fork choice endpoint returns JSON content type."""
        response = get_fork_choice(server_url)
        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type

    def test_fork_choice_response(self, server_url: str) -> None:
        """Fork choice response matches expected genesis-only tree structure."""
        response_body = get_fork_choice(server_url).json()
        genesis_root = response_body["head"]

        assert response_body == {
            "nodes": [
                {
                    "root": genesis_root,
                    "slot": 0,
                    "parent_root": ZERO_ROOT,
                    "proposer_index": 0,
                    "weight": 0,
                },
            ],
            "head": genesis_root,
            "justified": {"slot": 0, "root": genesis_root},
            "finalized": {"slot": 0, "root": genesis_root},
            "safe_target": genesis_root,
            "validator_count": 3,
        }
