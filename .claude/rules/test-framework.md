---
paths:
  - "tests/**/*.py"
  - "packages/testing/**/*.py"
---

# Test Framework Structure

**Two types of tests:**

1. **Unit tests** (`tests/`) - Standard pytest tests for implementation
2. **Spec tests** (`tests/consensus/`) - Generate JSON test vectors via fillers

**Test Filling Framework:**

- Pytest plugin in `packages/testing/src/consensus_testing/pytest_plugins/filler.py`
- Consensus fixture package: `consensus_testing`
- Write consensus spec tests using `state_transition_test` or `fork_choice_test` fixtures
- These fixtures are type aliases that create test vectors when called
- Run `uv run fill --fork=Lstar --clean -n auto` to generate consensus fixtures
- Output goes to `fixtures/consensus/{format}/{test_path}/...`

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

1. Test function receives a filler callable as parameter
2. Calling it builds a frozen input spec (a `BaseTestSpec` subclass) from the kwargs
3. `generate()` executes the spec code and returns a separate frozen fixture object
4. Validates output against expectations (`StateExpectation`, `StoreChecks`, `ExpectedRejection`)
5. Serializes to JSON via Pydantic's `model_dump(mode="json")`
6. Writes fixtures at session end to `fixtures/consensus/{format}/{test_path}/...`

**Package architecture:**

- Single package `consensus_testing/`: fixtures, forks, builders, the pytest
  plugin (`pytest_plugins/`), and CLI entry points (`cli/`)
- Regular pytest runs (`uv run pytest`) ignore spec tests - they only run via `fill` command

**Serialization requirements:**

- All spec types (State, Block, Uint64, etc.) must be Pydantic models
- Custom types need `@field_serializer` or `model_serializer` for JSON output
- SSZ types typically serialize to hex strings (e.g., `"0x1234..."`)
- Emitted fixtures inherit from `BaseConsensusFixture`, input specs from
  `BaseTestSpec` (both in `consensus_testing/test_fixtures/base.py`); both are
  frozen `CamelModel`s producing camelCase JSON output
- Test the serialization: `fixture.model_dump(mode="json")` must produce valid JSON

**Key fixture types:**

- `StateTransitionTest` - Tests state transitions with blocks
- `ForkChoiceTest` - Tests fork choice with steps (tick/block/attestation)
- Selective validation via `StateExpectation` and `StoreChecks` (only validates fields you specify)
- Negative paths via `ExpectedRejection` (reason + optional message substring)
