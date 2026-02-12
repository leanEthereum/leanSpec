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
uv sync                           # Install dependencies
uv run pytest                     # Run unit tests
uv run fill --fork=devnet --clean -n auto # Generate test vectors
# Note: execution layer support is planned for future, infrastructure is ready
# for now, `--layer=consensus` is default and the only value used.
```

### Code Quality

```bash
uv run ruff format       # Format code
uv run ruff check --fix  # Lint and fix
uvx tox -e typecheck     # Type check
uvx tox -e all-checks    # All quality checks
uvx tox                  # Everything (checks + tests + docs)
```

### Common Tasks

- **Main specs**: `src/lean_spec/`
- **Subspecs**: `src/lean_spec/subspecs/{subspec}/`
- **Unit tests**: `tests/lean_spec/` (mirrors source structure)
- **Consensus spec tests**: `tests/consensus/` (generates test vectors)
- **Execution spec tests**: `tests/execution/` (future - infrastructure ready)

## Code Style

- Line length: 100 characters, type hints everywhere
- Google docstring style
- Test files/functions must start with `test_`
- **No example code in docstrings**: Do not include `Example:` sections with code blocks in docstrings. Keep documentation concise and focused on explaining *what* and *why*, not *how to use*. Unit tests serve as usage examples.
- **No section separator comments**: Never use banner-style separator comments (`# ====...`, `# ----...`, or similar). They add visual clutter with no value. Use blank lines to separate logical sections. If a section needs a heading, a single `#` comment line is enough.

### Import Style

**All imports must be at the top of the file.** Never place imports inside functions, methods, or conditional blocks. This applies to both source code and tests. If a circular dependency exists, restructure the code to break the cycle rather than using a lazy import.

Bad:
```python
def process(data):
    from lean_spec.subspecs.ssz import hash_tree_root
    return hash_tree_root(data)
```

Good:
```python
from lean_spec.subspecs.ssz import hash_tree_root

def process(data):
    return hash_tree_root(data)
```

**Avoid confusing import renames.** When an external library exports a name that conflicts with a local type, prefer restructuring over renaming.

Bad:
```python
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey as CryptographyX25519PublicKey,
)
```

Good - import the module and use qualified access:
```python
from cryptography.hazmat.primitives.asymmetric import x25519

# Then use x25519.X25519PublicKey when needed
public_key = x25519.X25519PublicKey.from_public_bytes(data)
```

Good - move conflicting local types to a separate constants/types module:
```python
# In constants.py - no external dependencies that conflict
X25519PublicKey: TypeAlias = Bytes32

# In crypto.py - import from constants, use qualified access for external
from .constants import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import x25519
```

This keeps code readable and avoids mental overhead of tracking renamed imports.

### Module-Level Constants

Use docstrings (not comments) to document module-level constants. Place the docstring immediately after the assignment.

Bad:
```python
# Noise protocol name - used to initialize the handshake state
# This is the full protocol name per the Noise spec
PROTOCOL_NAME: bytes = b"Noise_XX_25519_ChaChaPoly_SHA256"
```

Good:
```python
PROTOCOL_NAME: bytes = b"Noise_XX_25519_ChaChaPoly_SHA256"
"""Noise protocol name per the Noise spec. Used to initialize the handshake state."""
```

This pattern:
- Is recognized by documentation tools (Sphinx, mkdocs)
- Shows up in IDE tooltips and autocomplete
- Keeps documentation close to the code it describes

### Documentation Rules (CRITICAL)

**NEVER use explicit function or method names in documentation.**

Names change. Documentation becomes stale. Use plain language instead.

Bad:
```python
# The shutdown task waits for stop() to be called, then signals
# all services to terminate. Once all services exit, TaskGroup completes.
```

Good:
```python
# A separate task monitors the shutdown signal.
# When triggered, it stops all services.
# Once services exit, execution completes.
```

**Write short, scannable sentences.**

Attention spans are short. Capture the reader precisely and concisely.

- One idea per line.
- Add blank lines between logical groups.
- Avoid long compound sentences.

Bad:
```python
# The state includes initial checkpoints, validator registry,
# and configuration derived from genesis time.
```

Good:
```python
# Includes initial checkpoints, validator registry, and config.
```

**Use bullet points or enumeration for lists.**

When listing multiple items, use structured formatting. Helps readers maintain focus.

Bad:
```python
"""
The verification checks structural validity, cryptographic correctness,
and state transition rules before accepting the block.
"""
```

Good:
```python
"""
The verification checks:

- Structural validity
- Cryptographic correctness
- State transition rules
"""
```

Or with numbered steps:
```python
"""
Processing proceeds in order:

1. Validate input format
2. Check signatures
3. Apply state transition
4. Update forkchoice
"""
```

Bad:
```python
"""
Wait for shutdown signal then stop services.

This task runs alongside the services. When shutdown is signaled,
it stops both services, allowing their run loops to exit gracefully.
"""
```

Good:
```python
"""
Wait for shutdown signal then stop services.

Runs alongside the services.
When shutdown is signaled, stops all services gracefully.
"""
```

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
- Run `uv run fill --fork=Devnet --clean -n auto` to generate consensus fixtures
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
- **Always run linter checks before finishing**: Run `uvx tox -e all-checks` at the end of any code changes to ensure all linting, formatting, type checking, and spell checking passes.
- **CRITICAL - NO BACKWARD COMPATIBILITY**: This is a STRICT requirement. NEVER add backward compatibility code under any circumstances. This means:
  - NO legacy constants (like `KEY_TYPE_ED25519 = KeyType.ED25519`)
  - NO wrapper functions that delegate to new classes
  - NO re-exports of deprecated APIs
  - NO deprecation shims or aliases
  - When refactoring from functions to classes, DELETE the old functions entirely
  - Update ALL call sites to use the new API directly
  - Old patterns must be REMOVED, not preserved alongside new ones

## SSZ Type Design Patterns

When creating SSZ types, follow these established patterns:

### Domain-Specific Types (Preferred)

- Use meaningful names that describe the purpose: `JustificationValidators`, `HistoricalBlockHashes`, `Attestations`
- Define domain-specific types in modular structure (see Architecture section below)
- Avoid generic names with numbers like `Bitlist68719476736` or `SignedAttestationList4096`

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
    """List of signed attestations included in a block."""
    ELEMENT_TYPE = SignedAttestation
    LIMIT = 4096  # VALIDATOR_REGISTRY_LIMIT
```

**Avoid generic types:**

```python
# Don't do this:
class Bitlist68719476736(BaseBitlist): ...
class SignedAttestationList4096(SSZList): ...
```

