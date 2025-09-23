# Working with leanSpec

## Repository Overview

This is a Python repository for the Lean Ethereum Python specifications. It is set up as
a single `uv` project containing the main specifications and various cryptographic
subspecifications that the Lean Ethereum protocol relies on.

## Key Directories

- `src/lean_spec/` - Main specifications for the Lean Ethereum protocol
- `src/lean_spec/subspecs/` - Supporting subspecifications for cryptographic primitives
- `tests/` - Specification tests
- `docs/` - MkDocs documentation source

## Development Workflow

### Running Tests
```bash
# Sync all dependencies and install packages
uv sync --all-extras

# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=src/lean_spec --cov-report=html
```

### Code Quality Checks
```bash
# Format code
uv run ruff format src tests

# Check linting
uv run ruff check src tests

# Fix fixable linting errors
uv run ruff check --fix src tests

# Type checking
uv run mypy src tests

# Run all quality checks (lint, typecheck, spellcheck)
uv run tox -e all-checks

# Run everything (all checks + tests + docs)
uv run tox
```

### Common Tasks

1. **Adding to main specs**: Located in `src/lean_spec/`
2. **Adding to subspecs**: Located in `src/lean_spec/subspecs/`
   - Create a new subdirectory for each subspec (e.g., `src/lean_spec/subspecs/poseidon2/`)
   - Tests for subspecs should be in `tests/subspecs/{subspec}/`, mirroring the source structure

## Important Patterns

### Test Patterns
- Tests should be placed in `tests/` and follow the same structure as the source code.
- Use `pytest.fixture`, in `conftest.py` or test files, for reusable test setup.
- Use `pytest.mark.parametrize` to parametrize tests with multiple inputs
- Use `pytest.raises(...)` with specific exceptions to test error cases
- Use `@pytest.mark.slow` for long-running tests

## Code Style

- Line length: 79 characters
- Use type hints everywhere
- Follow Google docstring style
- No docstrings needed for `__init__` methods
- Imports are automatically sorted by `isort` and `ruff`

## Testing Philosophy

- Tests should be simple and clear
- Test file names must start with `test_`
- Test function names must start with `test_`
- Use descriptive test names that explain what's being tested

## Common Commands Reference

| Task                                   | Command                             |
|----------------------------------------|-------------------------------------|
| Install dependencies                   | `uv sync --all-extras`              |
| Run tests                              | `uv run pytest`                     |
| Format code                            | `uv run ruff format src tests`      |
| Lint code                              | `uv run ruff check src tests`       |
| Fix lint errors                        | `uv run ruff check --fix src tests` |
| Type check                             | `uv run mypy src tests`             |
| Build docs                             | `uv run mkdocs build`               |
| Serve docs                             | `uv run mkdocs serve`               |
| Run all quality checks (no tests/docs) | `uv run tox -e all-checks`          |
| Run everything (checks + tests + docs) | `uv run tox`                        |

## Important Notes

1. This repository uses Python 3.12+ features
2. All models should use Pydantic for automatic validation.
3. Keep things simple, readable, and clear. These are meant to be clear specifications.
4. The repository is `leanSpec` not `lean-spec`.

## SSZ Type Design Patterns

When creating SSZ types, follow these established patterns:

### Domain-Specific Types (Preferred)
- Use meaningful names that describe the purpose: `JustificationValidators`, `HistoricalBlockHashes`, `Attestations`
- Define domain-specific types close to where they're used (e.g., in `state.py` for state-specific types)
- Avoid generic names with numbers like `Bitlist68719476736` or `SignedVoteList4096`

### Type Inheritance Strategy
- **Primitive types** (uint, boolean, bytes): Use IS-A pattern (direct inheritance)
- **Collection types** (lists, vectors, bitfields): Use HAS-A pattern with SSZModel/Container base classes
- All SSZ types should have proper serialization (`encode_bytes`, `decode_bytes`, `serialize`, `deserialize`)

### Examples

**Good domain-specific types:**
```python
class JustificationValidators(BitlistBase):
    """Bitlist for tracking validator justifications."""
    LIMIT = 262144 * 262144  # For flattened validator justifications

class Attestations(SSZList):
    """List of signed votes (attestations) included in a block."""
    ELEMENT_TYPE = SignedVote
    LIMIT = 4096  # VALIDATOR_REGISTRY_LIMIT
```

**Avoid generic types:**
```python
# Don't do this:
class Bitlist68719476736(BitlistBase): ...
class SignedVoteList4096(SSZList): ...
```
