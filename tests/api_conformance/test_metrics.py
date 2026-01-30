"""Tests for the metrics endpoint."""

import httpx


def test_metrics_returns_200(server_url: str) -> None:
    """Metrics endpoint returns 200 status code."""
    response = httpx.get(f"{server_url}/metrics")
    assert response.status_code == 200


def test_metrics_content_type_is_text(server_url: str) -> None:
    """Metrics endpoint returns text/plain content type."""
    response = httpx.get(f"{server_url}/metrics")
    content_type = response.headers.get("content-type", "")
    assert content_type.startswith("text/plain")


def test_metrics_contains_prometheus_format(server_url: str) -> None:
    """Metrics endpoint returns Prometheus-format metrics."""
    response = httpx.get(f"{server_url}/metrics")
    body = response.text

    # Prometheus format has lines like:
    # - metric_name value
    # - # HELP metric_name description
    # - # TYPE metric_name type

    # Check for at least one metric line (non-comment, non-empty)
    lines = body.strip().split("\n")
    metric_lines = [line for line in lines if line and not line.startswith("#")]

    assert len(metric_lines) > 0, "Expected at least one metric line"
