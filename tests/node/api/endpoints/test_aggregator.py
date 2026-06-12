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

    def test_status_reports_disabled_after_disabling(self, server_url: str) -> None:
        """GET reports is_aggregator False after a POST disables the role."""
        httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": False},
        )
        response = httpx.get(f"{server_url}/lean/v0/admin/aggregator")
        assert response.json() == {"is_aggregator": False}

    def test_status_reports_enabled_after_enabling(self, server_url: str) -> None:
        """GET reports is_aggregator True after a POST enables the role."""
        httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        response = httpx.get(f"{server_url}/lean/v0/admin/aggregator")
        assert response.json() == {"is_aggregator": True}


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

    def test_toggle_enabling_from_disabled(self, server_url: str) -> None:
        """POST enabling from a disabled state returns the True state and False previous."""
        httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": False},
        )
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        assert response.json() == {"is_aggregator": True, "previous": False}

    def test_toggle_disabling_from_enabled(self, server_url: str) -> None:
        """POST disabling from an enabled state returns the False state and True previous."""
        httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": False},
        )
        assert response.json() == {"is_aggregator": False, "previous": True}

    def test_toggle_to_same_value_reports_unchanged_previous(self, server_url: str) -> None:
        """POST enabling an already-enabled role reports the unchanged True previous."""
        httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        response = httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        assert response.json() == {"is_aggregator": True, "previous": True}

    def test_get_reflects_toggle(self, server_url: str) -> None:
        """A follow-up GET reflects the state set by a preceding POST."""
        httpx.post(
            f"{server_url}/lean/v0/admin/aggregator",
            json={"enabled": True},
        )
        response = httpx.get(f"{server_url}/lean/v0/admin/aggregator")
        assert response.json() == {"is_aggregator": True}


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
