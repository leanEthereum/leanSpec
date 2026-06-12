"""State Transition: Genesis State"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import VALIDATOR_REGISTRY_LIMIT, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    BlockBody,
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    State,
    Validator,
    Validators,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32, Bytes52, Uint64

pytestmark = pytest.mark.valid_until("Lstar")


def _generate_max_registry_pre_state() -> State:
    """
    Build genesis with the registry filled to capacity using placeholder public_keys.

    XMSS key generation is intentionally skipped: every validator carries a
    zero public_key. This is sound because the state-transition path used here
    counts attestation votes without verifying signatures, so the keys are
    never read.
    """
    zero_public_key = Bytes52.zero()
    validators = Validators(
        data=[
            Validator(
                attestation_public_key=zero_public_key,
                proposal_public_key=zero_public_key,
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
    Genesis with default configuration starts unjustified and unfinalized.

    Given
    -----
    - genesis time is 0.
    - 4 validators with zero public keys.

    When
    ----
    - genesis is generated and no blocks are processed.

    Then
    ----
    - the state slot is 0.
    - justified slot is 0.
    - finalized slot is 0.
    - the justified and finalized roots are zero.
    - the pending-vote tracking is empty.
    """
    state_transition_test(
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
    Genesis records a custom genesis time and keeps all other defaults.

    Given
    -----
    - genesis time is 1234567890.
    - 4 validators.

    When
    ----
    - genesis is generated and no blocks are processed.

    Then
    ----
    - the configured genesis time is 1234567890.
    - the state slot is 0.
    - justified slot is 0.
    - finalized slot is 0.
    - the pending-vote tracking is empty.
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
    Genesis with a custom validator set holds exactly that many validators.

    Given
    -----
    - 8 validators instead of the default 4.

    When
    ----
    - genesis is generated and no blocks are processed.

    Then
    ----
    - the validator count is 8.
    - the state slot is 0.
    - justified slot is 0.
    - finalized slot is 0.
    - the pending-vote tracking is empty.
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


def test_genesis_registry_holds_exact_validator_entries(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Genesis carries the exact validator registry it was seeded with.

    Given
    -----
    - 3 validators with zeroed public keys.
    - V0, V1, V2 carry indices 0, 1, 2 in registry order.

    When
    ----
    - genesis is generated and no blocks are processed.

    Then
    ----
    - the registry holds those three entries in that order.
    """
    zero_public_key = Bytes52(b"\x00" * 52)
    seeded_validators = Validators(
        data=[
            Validator(
                attestation_public_key=zero_public_key,
                proposal_public_key=zero_public_key,
                index=ValidatorIndex(validator_position),
            )
            for validator_position in range(3)
        ]
    )

    state_transition_test(
        pre=LstarSpec().generate_genesis(
            genesis_time=Uint64(0),
            validators=seeded_validators,
        ),
        blocks=[],
        post=StateExpectation(validators=seeded_validators),
    )


def test_genesis_maximum_validators_with_forced_threshold_attestation(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Genesis at the validator registry limit can still justify a checkpoint.

    Given
    -----
    - 4096 validators, the registry limit.
    - a slot needs 2731 votes (2/3) to be justified.
    - 3 * 2731 = 8193 is at least 2 * 4096 = 8192.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - block_1 has proposer V1, from 1 modulo 4096.
    - block_2 leaves its proposer implicit, exercising the round-robin default.
    - block_2 includes V0 through V2730's votes for block_1.
    - the votes are appended directly to block_2 to bypass the signing path.
    - the placeholder validators have no real keys.

    When
    ----
    - the chain processes block_1 and block_2.

    Then
    ----
    - the validator count is 4096.
    - the state slot is 2.
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - block_2's proposer resolves to V2, from 2 modulo 4096.
    """
    validator_count = int(VALIDATOR_REGISTRY_LIMIT)
    supermajority_threshold = (2 * validator_count + 2) // 3

    state_transition_test(
        pre=_generate_max_registry_pre_state(),
        blocks=[
            BlockSpec(
                slot=Slot(1),
                label="block_1",
                proposer_index=ValidatorIndex(1),
            ),
            BlockSpec(
                slot=Slot(2),
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(i) for i in range(supermajority_threshold)
                        ],
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
    A single validator justifies and finalizes within three blocks.

    Given
    -----
    - 1 validator, which proposes every slot, since the slot modulo 1 is always 0.
    - a slot needs 1 vote (2/3) to be justified, since 3*1 = 3 is at least 2*1 = 2.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3)
    - block_1 carries no votes.
    - block_2 includes V0's vote for block_1.
    - block_2 justifies slot 1.
    - block_3 includes V0's vote for block_2.
    - block_3 justifies slot 2.
    - block_3 then finalizes slot 1.

    When
    ----
    - the chain processes block_1, block_2, and block_3.

    Then
    ----
    - the validator count is 1.
    - justified slot is 2.
    - finalized slot is 1.
    - every block proposer is V0.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=1, genesis_time=Uint64(0)),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[ValidatorIndex(0)],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(3),
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[ValidatorIndex(0)],
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
    The first block after genesis anchors the justified and finalized roots.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block_1(1)
    - the anchor root is the chain tip header at slot 1 before block_1.

    When
    ----
    - the chain processes block_1.

    Then
    ----
    - the state slot is 1.
    - justified slot is 0.
    - finalized slot is 0.
    - the justified root is the anchor root.
    - the finalized root is the anchor root.
    - the history holds the anchor root once.
    - the justified-slots bitfield is empty.
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
