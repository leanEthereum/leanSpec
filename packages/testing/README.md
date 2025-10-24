# Lean Ethereum Specification Testing Framework

Testing framework for generating and running Lean Ethereum specification tests.

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
uv run fill --clean --fork=devnet
```

See the main project documentation for more details.
