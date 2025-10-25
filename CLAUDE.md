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
uv sync --all-packages            # Install dependencies
uv run pytest                     # Run unit tests
uv run fill --fork=devnet --clean # Generate test vectors
# Note: execution layer support is planned for future, infrastructure is ready
# for now, `--layer=consensus` is default and the only value used.
```

### Code Quality
```bash
uv run ruff format src tests               # Format code
uv run ruff check --fix src tests packages # Lint and fix
uvx tox -e typecheck                       # Type check
uvx tox -e all-checks                      # All quality checks
uvx tox                                    # Everything (checks + tests + docs)
```

### Common Tasks
- **Main specs**: `src/lean_spec/`
- **Subspecs**: `src/lean_spec/subspecs/{subspec}/`
- **Unit tests**: `tests/lean_spec/` (mirrors source structure)
- **Consensus spec tests**: `tests/consensus/` (generates test vectors)
- **Execution spec tests**: `tests/execution/` (future - infrastructure ready)

## Code Style
- Line length: 100 characters, type hints everywhere
- Google docstring style (no docstrings for `__init__`)
- Test files/functions must start with `test_`

## Test Framework Structure

**Two types of tests:**

1. **Unit tests** (`tests/lean_spec/`) - Standard pytest tests for implementation
2. **Spec tests** (`tests/consensus/`) - Generate JSON test vectors via fillers
   - *Note: `tests/execution/` infrastructure is ready for future execution layer work*

**Test Filling Framework:**
- Layer-agnostic pytest plugin in `packages/testing/src/framework/pytest_plugins/filler.py`
- Layer-specific packages: `consensus_testing` (active) and `execution_testing` (future)
- Write consensus spec tests using `state_transition_test` or `fork_choice_test` fixtures
- These fixtures are type aliases that create test vectors when called
- Run `uv run fill --fork=Devnet --clean` to generate consensus fixtures
- Use `--layer=execution` flag when execution layer is implemented
- Output goes to `fixtures/{layer}/{format}/{test_path}/...`

**Example spec test:**
```python
def test_block(state_transition_test: StateTransitionTestFiller) -> None:
    state_transition_test(
        pre=genesis_state,
        blocks=[block],
        post=StateExpectation(slot=Slot(1))  # Only check what matters
    )
```

**How it works:**
1. Test function receives a fixture class (not instance) as parameter
2. Calling it creates a `FixtureWrapper` that runs `make_fixture()`
3. `make_fixture()` executes the spec code (state transitions, fork choice steps)
4. Validates output against expectations (`StateExpectation`, `StoreChecks`)
5. Serializes to JSON via Pydantic's `model_dump(mode="json")`
6. Writes fixtures at session end to `fixtures/{layer}/{format}/{test_path}/...`

**Layer-specific architecture:**
- `framework/` - Shared infrastructure (base classes, pytest plugin, CLI)
- `consensus_testing/` - Consensus layer fixtures, forks, builders
- `execution_testing/` - Execution layer fixtures, forks, builders
- Regular pytest runs (`uv run pytest`) ignore spec tests - they only run via `fill` command

**Serialization requirements:**
- All spec types (State, Block, Uint64, etc.) must be Pydantic models
- Custom types need `@field_serializer` or `model_serializer` for JSON output
- SSZ types typically serialize to hex strings (e.g., `"0x1234..."`)
- Fixture models inherit from layer-specific base classes:
  - Consensus: `BaseConsensusFixture` (in `consensus_testing/test_fixtures/base.py`)
  - Execution: `BaseExecutionFixture` (in `execution_testing/test_fixtures/base.py`)
  - Both use `CamelModel` for camelCase JSON output
- Test the serialization: `fixture.model_dump(mode="json")` must produce valid JSON

**Key fixture types:**
- `StateTransitionTest` - Tests state transitions with blocks
- `ForkChoiceTest` - Tests fork choice with steps (tick/block/attestation)
- Selective validation via `StateExpectation` and `StoreChecks` (only validates fields you specify)

## Important Notes

- Python 3.12+ required
- Use Pydantic models for validation
- Keep specs simple, readable, and clear
- Repository is `leanSpec` not `lean-spec`

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
- **Base types** (BaseBitlist, SSZList, etc.) stay in general scope (`src/lean_spec/types/`)
- **Spec-specific types** go in their respective modules (`state/types.py`, `block/types.py`)
- **Public API** exposed through `__init__.py` files for backward compatibility
- **Domain-specific types** defined close to where they're used

### Examples

**Good domain-specific types:**
```python
# In state/types.py
HISTORICAL_ROOTS_LIMIT = 262144

class JustificationValidators(BaseBitlist):
    """Bitlist for tracking validator justifications."""
    LIMIT = HISTORICAL_ROOTS_LIMIT * HISTORICAL_ROOTS_LIMIT

# In block/types.py
class Attestations(SSZList):
    """List of signed votes (attestations) included in a block."""
    ELEMENT_TYPE = SignedVote
    LIMIT = 4096  # VALIDATOR_REGISTRY_LIMIT
```

**Avoid generic types:**
```python
# Don't do this:
class Bitlist68719476736(BaseBitlist): ...
class SignedVoteList4096(SSZList): ...
```

### API Compatibility

When refactoring, maintain backward compatibility:
- Keep existing import paths working through `__init__.py` exports
- Preserve method signatures and behavior
