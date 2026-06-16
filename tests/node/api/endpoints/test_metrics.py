"""Tests for the metrics endpoint."""

from __future__ import annotations

import httpx


def get_metrics(server_url: str) -> httpx.Response:
    """Fetch the Prometheus metrics scrape from the server."""
    return httpx.get(f"{server_url}/metrics")


def test_metrics_returns_200(server_url: str) -> None:
    """Metrics endpoint returns 200 status code."""
    assert get_metrics(server_url).status_code == 200


def test_metrics_content_type_is_prometheus_text(server_url: str) -> None:
    """Metrics endpoint returns the Prometheus text exposition content type."""
    response = get_metrics(server_url)
    assert response.headers.get("content-type") == "text/plain; version=0.0.4; charset=utf-8"


def test_metrics_body_is_prometheus_exposition(server_url: str) -> None:
    """Metrics body is non-empty Prometheus exposition with HELP and TYPE lines."""
    body = get_metrics(server_url).text
    assert body != ""
    assert "# HELP " in body
    assert "# TYPE " in body
