"""
State Transition: Genesis State
=================================

Overview
--------
Tests for genesis state generation and initialization.
"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)

from lean_spec.forks.lstar.containers.block import BlockBody
from lean_spec.forks.lstar.containers.block.types import AggregatedAttestations
from lean_spec.forks.lstar.containers.state import State
from lean_spec.forks.lstar.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.forks.lstar.containers.validator import Validator, Validators
from lean_spec.forks.lstar.spec import LstarSpec
from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Slot, Uint64, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def _generate_max_registry_pre_state() -> State:
    """Build genesis with the registry filled to capacity using placeholder pubkeys.

    XMSS key generation is intentionally skipped: every validator carries a
    zero pubkey. This is sound because the state-transition path used here
    counts attestation votes without verifying signatures, so the keys are
    never read.
    """
    zero_pubkey = Bytes52.zero()
    validators = Validators(
        data=[
            Validator(
                attestation_pubkey=zero_pubkey,
                proposal_pubkey=zero_pubkey,
                index=ValidatorIndex(i),
            )
            for i in range(int(VALIDATOR_REGISTRY_LIMIT))
        ]
    )
    return LstarSpec().generate_genesis(genesis_time=Uint64(0), validators=validators)


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
                BlockBody(attestations=AggregatedAttestations(data=[]))
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
                BlockBody(attestations=AggregatedAttestations(data=[]))
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
    state_transition_test(
        pre=generate_pre_state(num_validators=8),
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
                BlockBody(attestations=AggregatedAttestations(data=[]))
            ),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_genesis_maximum_validators_with_forced_threshold_attestation(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Genesis at the validator registry limit can still justify a checkpoint.

    Scenario
    --------
    Build a genesis state with 4096 validators (the registry limit), then
    process two blocks:

    - Block 1 at slot 1, proposer = validator 1 (1 % 4096).
    - Block 2 at slot 2, proposer = validator 2 by round-robin default,
      with attestations from validators 0..2730 -- exactly the 2731-of-4096
      supermajority threshold (3 * 2731 = 8193 >= 2 * 4096 = 8192).

    The 2731 votes are appended directly to block 2's body to bypass the
    builder's signing path; the placeholder validators have no real XMSS
    keys. The state transition still tallies the votes and applies the
    same supermajority rule as the production path.

    Expected post-state
    -------------------
    - Validator count: 4096
    - Slot: 2
    - Latest justified slot: 1 (block 1 reached the 2731/4096 threshold)
    - Latest finalized slot: 0 (no second justified checkpoint yet)
    - Latest block header slot: 2
    - Latest block header proposer: 2 (round-robin: 2 % 4096)
    """
    validator_count = int(VALIDATOR_REGISTRY_LIMIT)
    # Spec rule: 3 * count >= 2 * len(validators).
    # The minimum count is ceil(2 * N / 3); for 4096 validators this is 2731.
    supermajority_threshold = (2 * validator_count + 2) // 3

    state_transition_test(
        pre=_generate_max_registry_pre_state(),
        blocks=[
            BlockSpec(
                slot=Slot(1),
                label="block_1",
                proposer_index=ValidatorIndex(1),
            ),
            # Slot 2 leaves proposer_index implicit so the post-state assertion
            # verifies the framework's round-robin default at the registry limit.
            BlockSpec(
                slot=Slot(2),
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[ValidatorIndex(i) for i in range(supermajority_threshold)],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            validator_count=validator_count,
            latest_justified_slot=Slot(1),
            latest_justified_root_label="block_1",
            latest_finalized_slot=Slot(0),
            latest_block_header_slot=Slot(2),
            latest_block_header_proposer_index=2,
        ),
    )


def test_genesis_single_validator(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Genesis with exactly 1 validator; justification and finalization in 3 blocks.

    Scenario
    --------
    Single validator. Proposer for every slot (slot % 1 == 0, always).
    Supermajority threshold trivially met: 3*1=3 >= 2*1=2.

    - Block 1: empty (creates attestation target)
    - Block 2: V0 attests to slot 1 -> justifies slot 1
    - Block 3: V0 attests to slot 2 -> justifies slot 2, finalizes slot 1

    Expected post-state
    -------------------
    - Validator count: 1
    - Justified slot: 2
    - Finalized slot: 1
    - Proposer index: always 0
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=1, genesis_time=Uint64(0)),
        blocks=[
            # Block 1: creates the attestation target for block 2.
            BlockSpec(slot=Slot(1), label="block_1"),
            # Block 2: V0 attests to slot 1.
            # Threshold: 3*1=3 >= 2*1=2 -> justifies slot 1.
            # Finalization: range(0+1, 1) is empty -> finalizes source (slot 0).
            # But finalized was already 0, so no visible advance.
            BlockSpec(
                slot=Slot(2),
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[ValidatorIndex(0)],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            # Block 3: V0 attests to slot 2.
            # Justifies slot 2 (source=1, target=2).
            # Finalization: range(1+1, 2) is empty -> finalizes source = slot 1.
            # This is the visible advance: finalized goes from 0 to 1.
            BlockSpec(
                slot=Slot(3),
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[ValidatorIndex(0)],
                        slot=Slot(3),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(3),
            validator_count=1,
            latest_justified_slot=Slot(2),
            latest_finalized_slot=Slot(1),
            latest_block_header_proposer_index=0,
        ),
    )


def test_first_post_genesis_block_sets_checkpoint_anchor_roots(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state of the first block after genesis.

    Scenario
    --------
    1. Start from the default genesis state
    2. Process the first block at slot 1

    Expected Behavior
    -----------------
    1. The post-state slot is 1
    2. latest_justified.slot and latest_finalized.slot remain 0
    3. latest_justified.root and latest_finalized.root equal the parent root of block 1
    4. historical_block_hashes contains that root once
    5. justified_slots is empty
    """
    pre = generate_pre_state()
    anchor_state = LstarSpec().process_slots(pre, Slot(1))
    anchor_root = hash_tree_root(anchor_state.latest_block_header)

    state_transition_test(
        pre=pre,
        blocks=[
            BlockSpec(slot=Slot(1)),
        ],
        post=StateExpectation(
            slot=Slot(1),
            latest_justified_slot=Slot(0),
            latest_justified_root=anchor_root,
            latest_finalized_slot=Slot(0),
            latest_finalized_root=anchor_root,
            historical_block_hashes=HistoricalBlockHashes(data=[anchor_root]),
            justified_slots=JustifiedSlots(data=[]),
        ),
    )
