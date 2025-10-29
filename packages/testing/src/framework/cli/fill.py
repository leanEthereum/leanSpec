"""Unified CLI command for generating Ethereum test fixtures across all layers."""

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
    help="Fork to generate fixtures for (e.g., Devnet for consensus, Shanghai for execution)",
)
@click.option(
    "--layer",
    type=click.Choice(["consensus", "execution"], case_sensitive=False),
    default="consensus",
    help="Ethereum layer to generate fixtures for (default: consensus)",
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
    layer: str,
    clean: bool,
) -> None:
    """
    Generate Ethereum test fixtures from test specifications.

    This unified command works across both consensus and execution layers.
    The --layer flag determines which layer's forks and fixtures to use.

    Examples:
        # Generate consensus layer fixtures
        fill tests/spec_tests/devnet --fork=Devnet --layer=consensus --clean -v

        # Generate execution layer fixtures (future)
        fill tests/spec_tests/shanghai --fork=Shanghai --layer=execution --clean -v

        # Default layer is consensus
        fill tests/spec_tests/devnet --fork=Devnet --clean -v
    """
    config_path = Path(__file__).parent / "pytest_ini_files" / "pytest-fill.ini"
    # Find project root by looking for pyproject.toml with [tool.uv.workspace]
    project_root = Path.cwd()
    while project_root != project_root.parent:
        if (project_root / "pyproject.toml").exists():
            # Check if this is the workspace root
            pyproject = project_root / "pyproject.toml"
            if "[tool.uv.workspace]" in pyproject.read_text():
                break
        project_root = project_root.parent

    # Build pytest arguments
    args = [
        "-c",
        str(config_path),
        f"--rootdir={project_root}",
        f"--output={output}",
        f"--fork={fork}",
        f"--layer={layer}",
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
