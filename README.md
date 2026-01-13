# Lean Ethereum Specifications

The Lean Ethereum protocol specifications and cryptographic subspecifications.

## Quick Start

### Prerequisites

#### Installing uv

[uv](https://github.com/astral-sh/uv) is a fast Python package manager that handles dependencies and Python versions.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
````

#### Installing Python 3.12+

This project requires Python 3.12 or later and should be installed via `uv`:

```bash
# Install Python 3.12, or latest stable version
uv python install 3.12
```

#### Installing Rust Nightly (Temporary)

> **Note:** This is a temporary requirement. In the future, the Rust bindings will be removed and all cryptographic primitives will be implemented directly in Python.

This project currently depends on `lean-multisig-py`, a Rust-based Python extension that requires Rust nightly to compile:

```bash
# Install rustup if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install and set nightly as default
rustup install nightly
rustup default nightly

# Verify installation
rustc --version  # Should show nightly version
```

### Setup

```bash
# Clone this repository
git clone https://github.com/leanEthereum/leanSpec leanSpec
cd leanSpec

# Install and sync project and dev dependencies, using `uv.lock` versions
uv sync

# Run tests to verify setup
uv run pytest
```

### Project Structure

```
├── src/
│   └── lean_spec/                      # Main specifications
│      ├── __init__.py
│      └── subspecs/                       # Sub-specifications
│          ├── poseidon2/
│          │   ├── __init__.py
│          │   ├── poseidon2.py
│          │   └── ...
│          ├── ...
│          └── ...
├── tests/                              # Test suite
|   ├── consensus/                      # Tests for consensus
|   |   └── devnet/                     # Tests for devnet
|   |       ├── fc/                     # Tests for fork-choice
|   |       └── state_transition/       # Tests for stf
│   └── lean_spec/                      # Tests for main specs
│       └── subspecs/                   # Tests for subspecs
├── docs/                               # Documentation
└── pyproject.toml                      # Project configuration
```

### Workspace Commands

```bash
# Install package and dev dependencies or re-sync workspace
uv sync
```

## Development Workflow

### Running Tests

```bash
# Run all tests from workspace root
uv run pytest

# Run tests in parallel, utilizing all available CPU cores
uv run pytest -n auto

# Run tests in parallel, specifying number of workers (e.g., 4)
uv run pytest -n 4

# Skip slow tests (marked with @pytest.mark.slow)
uv run pytest -m "not slow"

# Fill test vectors from pytest specs.
# Usage: uv run fill --clean --fork=devnet [--output=<dir>]
#   --clean  Overwrite existing fixtures
#   --fork   Target fork (default: devnet)
#   --output Optional directory for filled fixtures
uv run fill --clean --fork=devnet
```

### Code Quality

```bash
# Check code style and errors
uv run ruff check

# Auto-fix issues
uv run ruff check --fix

# Format code
uv run ruff format

# Type checking
uv run ty check
```

### Using Tox for Comprehensive Checks

You can use `tox` with `uvx`, which:
* Creates a temporary environment just for `tox`
* Doesn't require `uv sync` first
* Uses `tox-uv` for faster dependency installation

```bash
# Run specific environment, like "all quality checks" (lint, typecheck, spellcheck)
uvx tox -e all-checks

# Run all tox environments (all checks + tests + docs)
uvx tox
```

### Documentation

```bash
# Serve docs locally (with auto-reload)
uv run mkdocs serve

# Build docs
uv run mkdocs build
```

## Writing Specifications

### Example: Writing Tests

```python
# tests/test_new_types.py
import pytest
from pydantic import ValidationError
from lean_spec.types import Withdrawal  # Example Pydantic model


TEST_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"


# Parametrized test - test multiple inputs
@pytest.mark.parametrize("amount", [0, 1, 1000, 2**64 - 1])
def test_withdrawal_amount(amount):
    withdrawal = Withdrawal(
            index=0,
            validator_index=1,
            address=TEST_ADDRESS,
            amount=amount,
    )
    assert withdrawal.amount == amount  # Check if amount is set correctly



# Exception testing
def test_withdrawal_amount_above_uint64_max():
    with pytest.raises(ValidationError) as e:
        Withdrawal(
            index=0,
            validator_index=1,
            address=TEST_ADDRESS,
            amount=2**64,  # Exceeds uint64 max
        )
    assert " amount " in str(e.value)
```

## Guide to Python Tools

- **Pydantic models**: Think of these as strongly-typed data structures that validate inputs automatically
- **pytest**: Testing framework - just name test files `test_*.py` and functions `test_*`
- **uv**: Fast Python package manager - like npm/yarn but for Python
- **ruff**: Linter and formatter
- **ty**: Type checker
- **tox**: Automation tool for running tests across multiple environments (used via `uvx`)
- **mkdocs**: Documentation generator - write docs in Markdown, serve them locally

## Common Commands Reference

| Task                                          | Command                   |
|-----------------------------------------------|---------------------------|
| Install and sync project and dev dependencies | `uv sync`                 |
| Run tests                                     | `uv run pytest ...`       |
| Format code                                   | `uv run ruff format`      |
| Lint code                                     | `uv run ruff check`       |
| Fix lint errors                               | `uv run ruff check --fix` |
| Type check                                    | `uv run ty check`         |
| Build docs                                    | `uv run mkdocs build`     |
| Serve docs                                    | `uv run mkdocs serve`     |
| Run everything (checks + tests + docs)        | `uvx tox`                 |
| Run all quality checks (no tests/docs)        | `uvx tox -e all-checks`   |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for more guidelines.

## License

MIT License - see LICENSE file for details.
