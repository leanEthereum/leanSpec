# Lean Ethereum Specifications

The Lean Ethereum protocol specifications and cryptographic subspecifications.

> **🐳 Running with Docker?** Skip the setup and jump to [DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md) for containerized deployment examples.

## Quick Start

**New to leanSpec?** Choose your path:
- **Local development**: Follow the instructions below
- **Docker deployment**: See [DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md) for running as a consensus node

### Prerequisites

#### Installing uv

[uv](https://github.com/astral-sh/uv) is a fast Python package manager that handles dependencies and Python versions.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
````

#### Installing just

[`just`](https://just.systems/) is the task runner used for common developer
workflows in this repository.

```bash
# Recommended cross-platform install
uv tool install just-bin

# Alternatives
brew install just
apt install just
```

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

# See the available repo tasks
just

# Run tests to verify setup
just test
```

### Project Structure

```
├── src/
│   └── lean_spec/                      # Main specifications
│      ├── __init__.py
│      └── subspecs/                       # Sub-specifications
│          ├── poseidon1/
│          │   ├── __init__.py
│          │   ├── permutation.py
│          │   └── constants.py
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
# Run the default test suite
just test

# Run all tests from workspace root without just
uv run pytest

# Run tests in parallel, utilizing all available CPU cores
uv run pytest -n auto

# Run tests in parallel, specifying number of workers (e.g., 4)
uv run pytest -n 4

# Skip slow tests (marked with @pytest.mark.slow)
uv run pytest -m "not slow"

# Fill test vectors from pytest specs.
# Usage: uv run fill --clean --fork=Lstar [--scheme=<scheme>] [--output=<dir>]
#   --clean  Overwrite existing fixtures
#   --fork   Target fork (e.g., Lstar)
#   --scheme XMSS signature scheme: "test" (default, fast) or "prod" (prod config, slower)
#   --output Optional directory for filled fixtures
uv run fill --clean --fork=Lstar
uv run fill --clean --fork=Lstar --scheme=prod

# Run API conformance tests against an external client implementation
# Usage: uv run apitest <server-url> [pytest-args]
uv run apitest http://localhost:5052

# Same API conformance test through the task runner
just apitest http://localhost:5052
```

### Code Quality

```bash
# Run the full quality gate
just check

# Check code style and errors
just lint

# Auto-fix issues
just fix

# Format code
just format

# Type checking
just typecheck
```

### Using just for Common Tasks

Run `just` with no arguments to see the available recipes. `just` is the
primary command surface for contributors, while raw `uv run ...` commands remain
available when you want to invoke tools directly.

```bash
# List available tasks
just

# Run quality checks
just check

# Run tests
just test

# Build documentation
just docs

# Generate consensus fixtures
uv run fill --fork=Lstar --clean -n auto
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
- **just**: Task runner for repository workflows such as checks, tests, docs, and fixture generation
- **mkdocs**: Documentation generator - write docs in Markdown, serve them locally

## Common Commands Reference

| Task                                          | Command                                                |
|-----------------------------------------------|--------------------------------------------------------|
| Install and sync project and dev dependencies | `uv sync`                                              |
| List repo tasks                               | `just`                                                 |
| Run quality checks                            | `just check`                                           |
| Run tests                                     | `just test`                                            |
| Format code                                   | `just format`                                          |
| Fix lint and formatting                       | `just fix`                                             |
| Type check                                    | `just typecheck`                                       |
| Build docs                                    | `just docs`                                            |
| Serve docs                                    | `just docs-serve`                                      |
| Generate consensus fixtures                   | `uv run fill --fork=Lstar --clean -n auto`             |
| Test external client API conformance          | `just apitest http://localhost:5052`                   |
| Run consensus node                            | `uv run python -m lean_spec --genesis config.yaml`     |
| Build Docker test image                       | `docker build -t lean-spec:test .`                     |
| Build Docker node image                       | `docker build --target node -t lean-spec:node .`       |
| Run tests in Docker                           | `docker run --rm lean-spec:test`                       |
| Run node in Docker                            | `docker run --rm lean-spec:node --genesis /app/data/config.yaml` |
| Dev shell in Docker                           | `docker run --rm -it lean-spec:dev`                    |

## Docker

> **🚀 Quick Start**: New to Docker? See [DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md) for:
> - Step-by-step deployment examples
> - Running as a validator node
> - Checkpoint sync configuration
> - Troubleshooting common issues

### Building the Docker Image

```bash
# Build the test runtime image (default, for running tests)
docker build -t lean-spec:test .

# Build the node image (for running as a consensus node)
docker build --target node -t lean-spec:node .

# Build the development image (includes all dev tools)
docker build --target development -t lean-spec:dev .
```

### Running Tests with Docker

```bash
# Run tests (default command for 'test' target)
docker run --rm lean-spec:test

# Run tests in parallel
docker run --rm lean-spec:test uv run pytest -n auto

# Run the fill command directly
docker run --rm lean-spec:test uv run fill --clean --fork=Lstar
```

### Running a Consensus Node with Docker

Pass CLI arguments directly to the node:

```bash
# Basic node
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml

# With bootnode
docker run --rm \
  -v /path/to/genesis:/app/data:ro \
  -p 9000:9000 \
  lean-spec:node \
  --genesis /app/data/config.yaml \
  --bootnode /ip4/127.0.0.1/tcp/9000
```

See [DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md) for more examples including validator nodes, checkpoint sync, and troubleshooting.

## Documentation

- **[DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md)** - Complete Docker deployment guide with examples

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for more guidelines.

## License

MIT License - see LICENSE file for details.
