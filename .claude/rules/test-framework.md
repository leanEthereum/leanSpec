---
paths:
  - "tests/**/*.py"
  - "packages/testing/**/*.py"
---

# Test Framework Structure

**Two types of tests:**

1. **Unit tests** (`tests/lean_spec/`) - Standard pytest tests for implementation
2. **Spec tests** (`tests/consensus/`) - Generate JSON test vectors via fillers
   - *Note: `tests/execution/` infrastructure is ready for future execution layer work*

**Test Filling Framework:**

- Layer-agnostic pytest plugin in `packages/testing/src/framework/pytest_plugins/filler.py`
- Layer-specific packages: `consensus_testing` (active) and `execution_testing` (future)
- Write consensus spec tests using `state_transition_test` or `fork_choice_test` fixtures
- These fixtures are type aliases that create test vectors when called
- Run `uv run fill --fork=Lstar --clean -n auto` to generate consensus fixtures
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

