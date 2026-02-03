"""CLI command for running API conformance tests against an external server."""

import sys
from pathlib import Path
from typing import Sequence

import click
import pytest


@click.command(
    context_settings={
        "ignore_unknown_options": True,
        "allow_extra_args": True,
    }
)
@click.argument("server_url")
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def apitest(
    ctx: click.Context,
    server_url: str,
    pytest_args: Sequence[str],
) -> None:
    """
    Run API conformance tests against an external server, i.e. a client implementation.

    SERVER_URL is the base URL of the API server (e.g., http://localhost:5052).

    For testing the local leanSpec implementation, use `uv run pytest tests/api`
    which automatically starts a local server.

    Examples:
        # Run against external server
        apitest http://localhost:5052

        # Run with verbose output
        apitest http://localhost:5052 -v

        # Run specific test
        apitest http://localhost:5052 -k test_health
    """
    config_path = Path(__file__).parent / "pytest_ini_files" / "pytest-apitest.ini"

    # Find project root
    project_root = Path.cwd()
    while project_root != project_root.parent:
        if (project_root / "pyproject.toml").exists():
            pyproject = project_root / "pyproject.toml"
            if "[tool.uv.workspace]" in pyproject.read_text():
                break
        project_root = project_root.parent

    # Build pytest arguments
    args = [
        "-c",
        str(config_path),
        f"--rootdir={project_root}",
        f"--server-url={server_url}",
        "tests/api",
    ]

    args.extend(pytest_args)
    args.extend(ctx.args)

    exit_code = pytest.main(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    apitest()
