"""Tests for the fork choice endpoint."""

import httpx


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

    def test_has_nodes(self, server_url: str) -> None:
        """Fork choice response has a nodes array."""
        data = get_fork_choice(server_url).json()

        assert "nodes" in data
        assert isinstance(data["nodes"], list)
        assert len(data["nodes"]) > 0

    def test_node_structure(self, server_url: str) -> None:
        """Each node has root, slot, parent_root, proposer_index, and weight."""
        data = get_fork_choice(server_url).json()
        node = data["nodes"][0]

        assert isinstance(node["root"], str)
        assert node["root"].startswith("0x")
        assert len(node["root"]) == 66

        assert isinstance(node["slot"], int)
        assert node["slot"] >= 0

        assert isinstance(node["parent_root"], str)
        assert node["parent_root"].startswith("0x")
        assert len(node["parent_root"]) == 66

        assert isinstance(node["proposer_index"], int)
        assert node["proposer_index"] >= 0

        assert isinstance(node["weight"], int)
        assert node["weight"] >= 0

    def test_has_head(self, server_url: str) -> None:
        """Fork choice response has a valid head root."""
        data = get_fork_choice(server_url).json()

        assert "head" in data
        assert isinstance(data["head"], str)
        assert data["head"].startswith("0x")
        assert len(data["head"]) == 66

    def test_has_justified_checkpoint(self, server_url: str) -> None:
        """Fork choice response has a justified checkpoint with slot and root."""
        data = get_fork_choice(server_url).json()

        assert "justified" in data
        justified = data["justified"]

        assert isinstance(justified["slot"], int)
        assert justified["slot"] >= 0

        assert isinstance(justified["root"], str)
        assert justified["root"].startswith("0x")
        assert len(justified["root"]) == 66

    def test_has_finalized_checkpoint(self, server_url: str) -> None:
        """Fork choice response has a finalized checkpoint with slot and root."""
        data = get_fork_choice(server_url).json()

        assert "finalized" in data
        finalized = data["finalized"]

        assert isinstance(finalized["slot"], int)
        assert finalized["slot"] >= 0

        assert isinstance(finalized["root"], str)
        assert finalized["root"].startswith("0x")
        assert len(finalized["root"]) == 66

    def test_has_safe_target(self, server_url: str) -> None:
        """Fork choice response has a valid safe_target root."""
        data = get_fork_choice(server_url).json()

        assert "safe_target" in data
        assert isinstance(data["safe_target"], str)
        assert data["safe_target"].startswith("0x")
        assert len(data["safe_target"]) == 66

    def test_has_validator_count(self, server_url: str) -> None:
        """Fork choice response has a non-negative validator count."""
        data = get_fork_choice(server_url).json()

        assert "validator_count" in data
        assert isinstance(data["validator_count"], int)
        assert data["validator_count"] >= 0

    def test_head_is_in_nodes(self, server_url: str) -> None:
        """The head root appears in the nodes list."""
        data = get_fork_choice(server_url).json()
        node_roots = {node["root"] for node in data["nodes"]}
        assert data["head"] in node_roots
