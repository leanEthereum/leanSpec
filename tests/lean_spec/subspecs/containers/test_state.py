"""
Tests for the State container and its methods.
"""

from typing import Dict, List

import pytest

from lean_spec.subspecs.chain import DEVNET_CONFIG
from lean_spec.subspecs.containers import (
    BlockHeader,
    Checkpoint,
    Config,
    State,
)
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


@pytest.fixture
def sample_config() -> Config:
    """Provides a sample configuration with 10 validators."""
    return Config(num_validators=10, genesis_time=0)


@pytest.fixture
def sample_block_header() -> BlockHeader:
    """Provides a sample, empty block header for state initialization."""
    return BlockHeader(
        slot=0,
        proposer_index=0,
        parent_root=Bytes32(b"\x00" * 32),
        state_root=Bytes32(b"\x00" * 32),
        body_root=Bytes32(b"\x00" * 32),
    )


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Provides a sample, empty checkpoint for state initialization."""
    return Checkpoint(root=Bytes32(b"\x00" * 32), slot=0)


@pytest.fixture
def base_state(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> State:
    """Provides a base State object with default empty values."""
    return State(
        config=sample_config,
        slot=Uint64(0),
        latest_block_header=sample_block_header,
        latest_justified=sample_checkpoint,
        latest_finalized=sample_checkpoint,
        historical_block_hashes=[],
        justified_slots=[],
        justifications_roots=[],
        justifications_validators=[],
    )


def test_is_proposer(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> None:
    """
    Test the `is_proposer` method with various slots and validator indices
    to ensure the round-robin proposer selection logic is correct.
    """

    def create_state_at_slot(slot: int) -> State:
        """Helper function to create a state object at a specific slot."""
        return State(
            config=sample_config,
            slot=Uint64(slot),
            latest_block_header=sample_block_header,
            latest_justified=sample_checkpoint,
            latest_finalized=sample_checkpoint,
            historical_block_hashes=[],
            justified_slots=[],
            justifications_roots=[],
            justifications_validators=[],
        )

    # At slot 0, validator 0 should be the proposer (0 % 10 == 0)
    state_slot_0 = create_state_at_slot(0)
    assert state_slot_0.is_proposer(ValidatorIndex(0)) is True
    assert state_slot_0.is_proposer(ValidatorIndex(1)) is False

    # At slot 7, validator 7 should be the proposer (7 % 10 == 7)
    state_slot_7 = create_state_at_slot(7)
    assert state_slot_7.is_proposer(ValidatorIndex(7)) is True
    assert state_slot_7.is_proposer(ValidatorIndex(8)) is False

    # At slot 10, the selection wraps around to validator 0 (10 % 10 == 0)
    state_slot_10 = create_state_at_slot(10)
    assert state_slot_10.is_proposer(ValidatorIndex(0)) is True
    assert state_slot_10.is_proposer(ValidatorIndex(1)) is False

    # At slot 23, the selection wraps around to validator 3 (23 % 10 == 3)
    state_slot_23 = create_state_at_slot(23)
    assert state_slot_23.is_proposer(ValidatorIndex(3)) is True
    assert state_slot_23.is_proposer(ValidatorIndex(2)) is False


def test_get_justifications_empty(base_state: State) -> None:
    """
    Test `get_justifications` when the state contains no justification data.

    Verifies that the method correctly returns an empty dictionary when
    `justifications_roots` and `justifications_validators` are empty lists.
    """
    # Ensure the base state has empty justification lists
    assert not base_state.justifications_roots
    assert not base_state.justifications_validators

    # Call the method and assert it returns an empty dictionary
    justifications = base_state.get_justifications()
    assert justifications == {}


def test_get_justifications_single_root(base_state: State) -> None:
    """
    Test `get_justifications` with a single root and its associated votes.

    This test ensures the method can correctly parse and map one block root
    to its corresponding list of validator votes from the flattened structure.
    """
    # Define a single root being voted on
    root1 = Bytes32(b"\x01" * 32)

    # Create a sample list of votes for this root.
    #
    # The length must match the validator registry limit.
    votes1 = [False] * DEVNET_CONFIG.validator_registry_limit
    votes1[2] = True  # Validator 2 voted
    votes1[5] = True  # Validator 5 voted

    # Create a new state instance with the desired justification data.
    state_with_data = base_state.model_copy(
        update={
            "justifications_roots": [root1],
            "justifications_validators": votes1,
        }
    )

    # Call the method to reconstruct the justifications map
    justifications = state_with_data.get_justifications()

    # Define the expected output
    expected = {root1: votes1}

    # Verify the output matches the expected structure and data
    assert justifications == expected


def test_get_justifications_multiple_roots(base_state: State) -> None:
    """
    Test `get_justifications` with multiple roots to verify correct slicing.

    This is the primary test case that validates the core logic of the method.
    It checks that the flattened `justifications_validators` list is correctly
    sliced and that each segment of votes is accurately mapped to its
    corresponding root from `justifications_roots`.
    """
    # Define multiple unique roots that are being voted on
    root1 = Bytes32(b"\x01" * 32)
    root2 = Bytes32(b"\x02" * 32)
    root3 = Bytes32(b"\x03" * 32)

    # Define distinct vote patterns for each root.
    # Each list must have a length equal to `VALIDATOR_REGISTRY_LIMIT`.
    limit = DEVNET_CONFIG.validator_registry_limit
    votes1 = [False] * limit
    votes1[0] = True  # Validator 0 votes for root1

    votes2 = [False] * limit
    votes2[1] = True  # Validator 1 votes for root2
    votes2[2] = True  # Validator 2 votes for root2

    votes3 = [True] * limit  # All validators vote for root3

    # Create a new state instance with the desired justification data,
    # as the State model is frozen and cannot be mutated after creation.
    state_with_data = base_state.model_copy(
        update={
            "justifications_roots": [root1, root2, root3],
            "justifications_validators": votes1 + votes2 + votes3,
        }
    )

    # Call the method to reconstruct the justifications map
    justifications = state_with_data.get_justifications()

    # Define the expected dictionary with roots mapped to their respective votes
    expected = {
        root1: votes1,
        root2: votes2,
        root3: votes3,
    }

    # Verify that the reconstructed map is identical to the expected map
    assert justifications == expected
    # Also verify that the number of roots matches
    assert len(justifications) == 3


def test_set_justifications_empty(base_state: State) -> None:
    """
    Test `set_justifications` correctly clears the state with an empty map.
    """
    # Start with some data to ensure it gets cleared
    base_state.justifications_roots = [Bytes32(b"\x01" * 32)]
    base_state.justifications_validators = [True] * DEVNET_CONFIG.validator_registry_limit

    # Set with an empty map
    base_state.set_justifications({})

    # Verify that the state lists are now empty
    assert not base_state.justifications_roots
    assert not base_state.justifications_validators


def test_set_justifications_deterministic_order(base_state: State) -> None:
    """
    Test `set_justifications` always sorts roots for deterministic output.
    """
    root1 = Bytes32(b"\x01" * 32)
    root2 = Bytes32(b"\x02" * 32)
    limit = DEVNET_CONFIG.validator_registry_limit
    votes1 = [False] * limit
    votes2 = [True] * limit

    # Provide the dictionary in an unsorted order (root2 comes before root1)
    justifications = {root2: votes2, root1: votes1}
    base_state.set_justifications(justifications)

    # Verify that the roots in the state are sorted
    assert base_state.justifications_roots == [root1, root2]
    # Verify that the flattened validators list matches the sorted order
    assert base_state.justifications_validators == votes1 + votes2


def test_set_justifications_invalid_length(base_state: State) -> None:
    """
    Test `set_justifications` raises an AssertionError for incorrect vote lengths.
    """
    root1 = Bytes32(b"\x01" * 32)
    # Create a list of votes that is one short of the required length
    invalid_votes = [True] * (DEVNET_CONFIG.validator_registry_limit - 1)
    justifications = {root1: invalid_votes}

    # Verify that calling the setter with this data raises an assertion error
    with pytest.raises(AssertionError):
        base_state.set_justifications(justifications)


def _create_votes(indices: List[int]) -> List[bool]:
    """Creates a vote list with `True` at the specified indices."""
    votes = [False] * DEVNET_CONFIG.validator_registry_limit
    for i in indices:
        votes[i] = True
    return votes


@pytest.mark.parametrize(
    "justifications_map",
    [
        pytest.param({}, id="empty_justifications"),
        pytest.param({Bytes32(b"\x01" * 32): _create_votes([0])}, id="single_root"),
        pytest.param(
            {
                Bytes32(b"\x01" * 32): _create_votes([0]),
                Bytes32(b"\x02" * 32): _create_votes([1, 2]),
            },
            id="multiple_roots_sorted",
        ),
        pytest.param(
            {
                Bytes32(b"\x02" * 32): _create_votes([1, 2]),
                Bytes32(b"\x01" * 32): _create_votes([0]),
            },
            id="multiple_roots_unsorted",
        ),
        pytest.param(
            {
                Bytes32(b"\x03" * 32): [True] * DEVNET_CONFIG.validator_registry_limit,
                Bytes32(b"\x01" * 32): _create_votes([0]),
                Bytes32(b"\x02" * 32): _create_votes([1, 2]),
            },
            id="complex_unsorted",
        ),
    ],
)
def test_justifications_roundtrip(
    base_state: State, justifications_map: Dict[Bytes32, List[bool]]
) -> None:
    """
    Test that data remains consistent after a set -> get cycle.
    """
    # Use the standard setter to modify the state
    base_state.set_justifications(justifications_map)

    # Reconstruct the map using the getter
    reconstructed_map = base_state.get_justifications()

    # The expected result is the original map with sorted keys
    expected_map = dict(sorted(justifications_map.items()))

    # Assert that the reconstructed map is identical to the expected map
    assert reconstructed_map == expected_map
