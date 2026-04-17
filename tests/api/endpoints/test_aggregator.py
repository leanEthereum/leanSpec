"""
Tests for the admin aggregator endpoint.

The conformance server is started with a controller seeded to disabled,
so tests exercise both the happy path and error cases.
"""

from __future__ import annotations

import httpx


class TestAggregatorStatus:
    """Tests for GET /lean/v0/admin/aggregator."""

    def test_returns_200(self, server_url: str) -> None:
        """GET returns 200 when the controller is wired."""
        response = httpx.get(f"{server_url}/lean/v0/admin/aggregator")
        assert response.status_code == 200

    def test_content_type_is_json(self, server_url: str) -> None:
        """GET returns JSON content type."""
        response = httpx.get(f"{server_url}/lean/v0/admin/aggregator")
        assert "application/json" in response.headers.get("content-type", "")

    def test_response_has_is_aggregator_field(self, server_url: str) -> None:
        """GET response contains the is_aggregator boolean field."""
        response = httpx.get(f"{server_url}/lean/v0/admin/aggregator")
        data = response.json()
        assert "is_aggregator" in data
        assert isinstance(data["is_aggregator"], bool)


class TestAggregatorToggle:
    """Tests for POST /lean/v0/admin/aggregator."""

    def test_toggle_returns_200(self, server_url: str) -> None:
        """POST with valid body returns 200."""
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        assert response.status_code == 200

    def test_toggle_content_type_is_json(self, server_url: str) -> None:
        """POST returns JSON content type."""
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        assert "application/json" in response.headers.get("content-type", "")

    def test_toggle_response_structure(self, server_url: str) -> None:
        """POST response contains is_aggregator and previous boolean fields."""
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        data = response.json()
        assert "is_aggregator" in data
        assert "previous" in data
        assert isinstance(data["is_aggregator"], bool)
        assert isinstance(data["previous"], bool)

    def test_toggle_reflects_requested_value(self, server_url: str) -> None:
        """POST response reflects the requested enabled value."""
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": False},
        )
        assert response.json()["is_aggregator"] is False

    def test_get_reflects_toggle(self, server_url: str) -> None:
        """A follow-up GET reflects the state set by a preceding POST."""
        httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        response = httpx.get(f"{server_url}/lean/v0/admin/aggregator")
        assert response.json()["is_aggregator"] is True


class TestAggregatorErrors:
    """Tests for error responses on /lean/v0/admin/aggregator."""

    def test_unsupported_method_returns_405(self, server_url: str) -> None:
        """DELETE against the admin aggregator route is not allowed."""
        response = httpx.delete(f"{server_url}/lean/v0/admin/aggregator")
        assert response.status_code == 405

    def test_toggle_rejects_missing_body(self, server_url: str) -> None:
        """POST with empty body returns 400."""
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400

    def test_toggle_rejects_missing_field(self, server_url: str) -> None:
        """POST without enabled field returns 400."""
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={},
        )
        assert response.status_code == 400

    def test_toggle_rejects_non_boolean(self, server_url: str) -> None:
        """POST with non-boolean enabled returns 400."""
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": "yes"},
        )
        assert response.status_code == 400
