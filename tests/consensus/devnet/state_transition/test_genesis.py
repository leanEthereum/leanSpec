"""
State Transition: Genesis State
=================================

Overview
--------
Tests for genesis state generation and initialization.
"""

import pytest
from consensus_testing import StateExpectation, StateTransitionTestFiller, generate_pre_state

from lean_spec.subspecs.containers.block import BlockBody
from lean_spec.subspecs.containers.block.types import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_genesis_default_configuration(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test genesis state with default configuration.

    Scenario
    --------
    Generate a genesis state with default parameters:
    - genesis_time = 0
    - 4 validators with zero pubkeys
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[],
        post=StateExpectation(
            slot=Slot(0),
            config_genesis_time=0,
            validator_count=4,
            latest_justified_slot=Slot(0),
            latest_justified_root=Bytes32.zero(),
            latest_finalized_slot=Slot(0),
            latest_finalized_root=Bytes32.zero(),
            latest_block_header_slot=Slot(0),
            latest_block_header_proposer_index=0,
            latest_block_header_parent_root=Bytes32.zero(),
            latest_block_header_state_root=Bytes32.zero(),
            latest_block_header_body_root=hash_tree_root(
                BlockBody(attestations=Attestations(data=[]))
            ),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_genesis_custom_time(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test genesis state with custom genesis time.

    Scenario
    --------
    Generate a genesis state with:
    - genesis_time = 1234567890
    - Default 4 validators

    Expected Behavior
    -----------------
    Genesis state should respect the custom genesis time while
    maintaining all other genesis properties.
    """
    genesis_time = Uint64(1234567890)

    state_transition_test(
        pre=generate_pre_state(genesis_time=genesis_time),
        blocks=[],
        post=StateExpectation(
            slot=Slot(0),
            config_genesis_time=int(genesis_time),
            validator_count=4,
            latest_justified_slot=Slot(0),
            latest_justified_root=Bytes32.zero(),
            latest_finalized_slot=Slot(0),
            latest_finalized_root=Bytes32.zero(),
            latest_block_header_slot=Slot(0),
            latest_block_header_proposer_index=0,
            latest_block_header_parent_root=Bytes32.zero(),
            latest_block_header_state_root=Bytes32.zero(),
            latest_block_header_body_root=hash_tree_root(
                BlockBody(attestations=Attestations(data=[]))
            ),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_genesis_custom_validator_set(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test genesis state with custom validator set.

    Scenario
    --------
    Generate a genesis state with:
    - 8 validators instead of default 4
    - Custom validator pubkeys

    Expected Behavior
    -----------------
    Genesis state should contain exactly 8 validators while
    maintaining all other genesis properties.
    """
    # Create 8 validators with unique pubkeys
    validators = Validators(data=[Validator(pubkey=Bytes52(bytes([i] * 52))) for i in range(8)])

    state_transition_test(
        pre=generate_pre_state(validators=validators),
        blocks=[],
        post=StateExpectation(
            slot=Slot(0),
            config_genesis_time=0,
            validator_count=8,
            latest_justified_slot=Slot(0),
            latest_justified_root=Bytes32.zero(),
            latest_finalized_slot=Slot(0),
            latest_finalized_root=Bytes32.zero(),
            latest_block_header_slot=Slot(0),
            latest_block_header_proposer_index=0,
            latest_block_header_parent_root=Bytes32.zero(),
            latest_block_header_state_root=Bytes32.zero(),
            latest_block_header_body_root=hash_tree_root(
                BlockBody(attestations=Attestations(data=[]))
            ),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )
