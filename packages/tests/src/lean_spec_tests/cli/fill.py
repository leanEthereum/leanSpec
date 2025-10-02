"""CLI command for generating consensus test fixtures."""

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
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--output",
    "-o",
    default="fixtures",
    help="Output directory for generated fixtures",
)
@click.option(
    "--fork",
    required=True,
    help="Fork to generate fixtures for (e.g., devnet)",
)
@click.option(
    "--clean",
    is_flag=True,
    help="Clean output directory before generating",
)
@click.pass_context
def fill(
    ctx: click.Context,
    pytest_args: Sequence[str],
    output: str,
    fork: str,
    clean: bool,
) -> None:
    """
    Generate consensus test fixtures from test specifications.

    This command runs pytest with the filler plugin to generate JSON
    test fixtures instead of running tests.

    Example:
        fill tests/vote_processing --fork=devnet --clean -v
    """
    # Look for pytest-fill.ini in current directory (project root)
    config_path = Path.cwd() / "pytest-fill.ini"

    # Build pytest arguments
    args = [
        "-c",
        str(config_path),
        f"--output={output}",
        f"--fork={fork}",
    ]

    if clean:
        args.append("--clean")

    # Add all pytest args
    args.extend(pytest_args)

    # Add extra click context args
    args.extend(ctx.args)

    # Run pytest
    exit_code = pytest.main(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    fill()
