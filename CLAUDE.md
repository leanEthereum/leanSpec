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
- Define domain-specific types in modular structure (see Architecture section below)
- Avoid generic names with numbers like `Bitlist68719476736` or `SignedVoteList4096`

### SSZType vs SSZModel Design Decision

**SSZType (IS-A pattern)**: Use for types that *are* data
- Primitive scalars: `Uint64`, `Boolean`, `Bytes32`
- These inherit directly from their underlying Python types
- Example: `Uint64(42)` *is* the integer 42 with SSZ serialization

**SSZModel (HAS-A pattern)**: Use for types that *have* data
- Collections: `SSZList`, `SSZVector`, bitfields
- Containers: `State`, `Block`, etc.
- These use Pydantic models with a `data` field for contents
- Example: `MyList(data=[1, 2, 3])` *has* a list of data with SSZ serialization

**Key principle**: If the type conceptually *holds* or *contains* other data, use SSZModel for consistent validation and immutability.

### Modular Architecture

Containers should be organized into modules with clear separation:

```
src/lean_spec/subspecs/containers/
├── state/
│   ├── __init__.py      # Exports State and related types
│   ├── state.py         # Main State container class
│   └── types.py         # State-specific types: JustifiedSlots, HistoricalBlockHashes, etc.
├── block/
│   ├── __init__.py      # Exports Block classes
│   ├── block.py         # Main Block container classes
│   └── types.py         # Block-specific types: Attestations, etc.
└── ...
```

**Key principles:**
- **Base types** (BitlistBase, SSZList, etc.) stay in general scope (`src/lean_spec/types/`)
- **Spec-specific types** go in their respective modules (`state/types.py`, `block/types.py`)
- **Public API** exposed through `__init__.py` files for backward compatibility
- **Domain-specific types** defined close to where they're used

### Examples

**Good domain-specific types:**
```python
# In state/types.py
class JustificationValidators(BitlistBase):
    """Bitlist for tracking validator justifications."""
    LIMIT = 262144 * 262144  # For flattened validator justifications

# In block/types.py
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

### API Compatibility

When refactoring, maintain backward compatibility:
- Keep existing import paths working through `__init__.py` exports
- Preserve method signatures and behavior
