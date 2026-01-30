"""Pytest plugin for API conformance testing via the apitest CLI.

This plugin is used by the apitest CLI command to pass the --server-url
option to pytest. The option is registered here so pytest can parse it.

When running via `uv run pytest`, the conftest.py in tests/api_conformance
handles server startup and provides the server_url fixture directly.
"""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """
    Register the --server-url option with pytest.

    The apitest CLI passes this option to pytest.
    When running via regular pytest, the conftest.py handles this.
    """
    group = parser.getgroup("apitest", "leanSpec API conformance testing")
    group.addoption(
        "--server-url",
        action="store",
        default=None,
        help="Base URL of the API server to test",
    )
