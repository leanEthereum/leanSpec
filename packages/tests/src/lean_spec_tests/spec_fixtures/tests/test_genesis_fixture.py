"""Tests for GenesisTest filler."""

from lean_spec_tests import genesis_test
from lean_spec_tests.spec_fixtures import GenesisTest

from lean_spec.types import Uint64


def test_genesis_basic() -> None:
    """Test basic genesis generation with minimal validators."""
    test = genesis_test(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    # The fixture is now filled - these are just sanity checks
    # (not strictly needed, but helpful for understanding)
    assert test.genesis_time == Uint64(1000000)
    assert test.num_validators == Uint64(4)
    assert test.expected_state is not None
    assert test.expected_state.slot.as_int() == 0
    assert test.expected_state.config.num_validators == Uint64(4)
    assert test.expected_state.config.genesis_time == Uint64(1000000)


def test_genesis_different_validator_counts() -> None:
    """Test genesis with various validator counts."""
    validator_counts = [Uint64(1), Uint64(4), Uint64(16), Uint64(64)]

    for count in validator_counts:
        test: GenesisTest = genesis_test(
            genesis_time=Uint64(0),
            num_validators=count,
        )
        assert test.expected_state is not None
        assert test.expected_state.config.num_validators == count


def test_genesis_initial_checkpoints() -> None:
    """Test that genesis state has proper initial checkpoints."""
    test: GenesisTest = genesis_test(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    state = test.expected_state
    assert state is not None

    # Genesis checkpoints should point to slot 0 with zero hash
    assert state.latest_justified.slot.as_int() == 0
    assert state.latest_finalized.slot.as_int() == 0
    assert state.latest_justified.root.hex() == "00" * 32
    assert state.latest_finalized.root.hex() == "00" * 32


def test_genesis_empty_history() -> None:
    """Test that genesis state starts with empty history."""
    test: GenesisTest = genesis_test(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    state = test.expected_state
    assert state is not None

    # History should be empty at genesis
    assert len(state.historical_block_hashes) == 0
    assert len(state.justified_slots) == 0
    assert len(state.justifications_roots) == 0
    assert len(state.justifications_validators) == 0


def test_genesis_serialization() -> None:
    """Test that genesis test can be serialized to JSON."""
    test: GenesisTest = genesis_test(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    # Use json_dict which properly applies camelCase
    json_dict = test.json_dict
    assert json_dict is not None
    assert "genesisTime" in json_dict  # CamelCase via CamelModel
    assert "numValidators" in json_dict
    assert json_dict["genesisTime"] == 1000000
    assert json_dict["numValidators"] == 4


def test_genesis_different_times() -> None:
    """Test genesis with different timestamps."""
    times = [Uint64(0), Uint64(1000000), Uint64(2**32), Uint64(2**63 - 1)]

    for genesis_time in times:
        test: GenesisTest = genesis_test(
            genesis_time=genesis_time,
            num_validators=Uint64(4),
        )
        assert test.genesis_time == genesis_time
        assert test.expected_state is not None
        assert test.expected_state.config.genesis_time == genesis_time


def test_genesis_determinism() -> None:
    """Test that genesis generation is deterministic."""
    test1: GenesisTest = genesis_test(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    test2: GenesisTest = genesis_test(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    # Both should produce identical states
    assert test1.expected_state is not None
    assert test2.expected_state is not None
    assert test1.expected_state.model_dump() == test2.expected_state.model_dump()
