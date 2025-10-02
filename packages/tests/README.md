# Lean Spec Tests

Consensus test authoring framework for Lean Ethereum specifications.

This package provides tools for generating consensus test fixtures, including:
- Pytest plugins for fixture generation
- Base fixture types and serialization
- CLI tools for test management

## Installation

This package is part of the lean-spec workspace and is automatically installed when you sync the parent project:

```bash
cd ../..
uv sync --all-extras
```

## Usage

Generate test fixtures using the `fill` command:

```bash
uv run fill --fork devnet
```

See the main project documentation for more details.
