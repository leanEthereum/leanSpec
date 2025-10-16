""" "Tests for the State container and its methods."""

from typing import Dict, Iterable, List

import pytest

from lean_spec.subspecs.chain import DEVNET_CONFIG
from lean_spec.subspecs.containers import (
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    SignedValidatorAttestation,
    State,
    ValidatorAttestation,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Validators,
)
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Boolean, Bytes32, Bytes4000, Uint64, ValidatorIndex


@pytest.fixture
def sample_config() -> Config:
    """
    Build a minimal Config for tests.

    Returns
    -------
    Config
        A configuration with 4096 validators and genesis_time set to 0.
    """
    # Create and return a simple configuration used across tests.
    return Config(
        num_validators=DEVNET_CONFIG.validator_registry_limit,
        genesis_time=Uint64(0),
    )


@pytest.fixture
def genesis_state(sample_config: Config) -> State:
    """
    Construct a canonical genesis State.

    Parameters
    ----------
    sample_config : Config
        The configuration fixture with validator count and genesis time.

    Returns
    -------
    State
        A fresh genesis state produced by the class factory.
    """
    # Call the canonical genesis factory with the sample configuration values.
    return State.generate_genesis(
        genesis_time=sample_config.genesis_time,
        num_validators=sample_config.num_validators,
    )


def _create_block(
    slot: int,
    parent_header: BlockHeader,
    votes: Iterable[ValidatorAttestation] | None = None,
) -> Block:
    """
    Helper: construct a valid `Block` for a given slot.

        Notes
        -----
        - Uses round-robin proposer selection with modulus 10 (aligned with the
            devnet configuration).
        - Sets state_root to zero; STF will compute and validate the real root.
        - Accepts an optional collection of validator attestations to embed in
            the body.

    Parameters
    ----------
    slot : int
        Slot number for the new block.
    parent_header : BlockHeader
        The header of the parent block to link against.
    votes : Iterable[ValidatorAttestation] | None
        Optional attestations to include.

    Returns
    -------
    Block
        The constructed block message with attestations embedded.
    """
    normalized_attestations = []
    if votes is not None:
        for attestation in votes:
            normalized_attestations.append(attestation)

    # Create a block body with the provided votes or an empty list.
    body = BlockBody(attestations=Attestations(data=normalized_attestations))
    # Construct the inner block message with correct parent_root linkage.
    block_message = Block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(slot % 10),  # Using sample_config num_validators
        parent_root=hash_tree_root(parent_header),
        state_root=Bytes32.zero(),  # Placeholder, to be filled in by STF
        body=body,
    )
    return block_message


def _create_votes(indices: List[int]) -> List[Boolean]:
    """
    Helper: build a validator vote bitlist of required size.

    Parameters
    ----------
    indices : list[int]
        Validator indices that should vote True.

    Returns
    -------
    list[Boolean]
        A bitlist of length VALIDATOR_REGISTRY_LIMIT with True at given indices.
    """
    # Start with an all-false bitlist at registry-limit length.
    votes = [Boolean(False)] * DEVNET_CONFIG.validator_registry_limit.as_int()
    # Flip the positions listed in indices to True.
    for i in indices:
        votes[i] = Boolean(True)
    # Return the completed bitlist.
    return votes


def _build_signed_attestation(
    validator: ValidatorIndex,
    slot: Slot,
    head: Checkpoint,
    source: Checkpoint,
    target: Checkpoint,
) -> SignedValidatorAttestation:
    """Create a signed attestation with a zeroed signature."""

    data = AttestationData(
        slot=slot,
        head=head,
        target=target,
        source=source,
    )
    message = ValidatorAttestation(
        validator_id=validator,
        data=data,
    )
    return SignedValidatorAttestation(
        message=message,
        signature=Bytes4000.zero(),
    )


@pytest.fixture
def sample_block_header() -> BlockHeader:
    """
    Produce a zeroed BlockHeader for initializing State.

    Returns
    -------
    BlockHeader
        A header with zero roots and slot 0.
    """
    # Construct and return a minimal header with zeroed fields.
    return BlockHeader(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body_root=Bytes32.zero(),
    )


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """
    Produce a zeroed Checkpoint for initializing State.

    Returns
    -------
    Checkpoint
        A checkpoint at slot 0 with zero root.
    """
    # Construct and return a minimal checkpoint.
    return Checkpoint.default()


@pytest.fixture
def base_state(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> State:
    """
    Provide a blank State instance for focused unit tests.

    Parameters
    ----------
    sample_config : Config
        Test configuration with 10 validators.
    sample_block_header : BlockHeader
        Zeroed header used as latest_block_header.
    sample_checkpoint : Checkpoint
        Zeroed checkpoint for justified/finalized.

    Returns
    -------
    State
        A State with empty history and justification lists.
    """
    # Build a State with the provided fixtures and no history/justifications.
    return State(
        config=sample_config,
        slot=Slot(0),
        latest_block_header=sample_block_header,
        latest_justified=sample_checkpoint,
        latest_finalized=sample_checkpoint,
        historical_block_hashes=HistoricalBlockHashes(data=[]),
        justified_slots=JustifiedSlots(data=[]),
        justifications_roots=JustificationRoots(data=[]),
        justifications_validators=JustificationValidators(data=[]),
        validators=Validators(data=[]),
    )


def test_get_justifications_empty(base_state: State) -> None:
    """
    get_justifications: empty input yields empty map.

    Steps
    -----
    - Confirm empty roots and validators lists.
    - Call accessor.
    - Expect {}.
    """
    # Sanity: State starts with no justifications data.
    assert not base_state.justifications_roots
    assert not base_state.justifications_validators

    # Reconstruct the map; expect an empty dict.
    justifications = base_state.get_justifications()
    assert justifications == {}


def test_get_justifications_single_root(base_state: State) -> None:
    """
    get_justifications: one root, one vote slice.

    Steps
    -----
    - Provide a single root.
    - Build a votes list of registry-limit length with a few True entries.
    - Expect the map to pair that root with the exact slice.
    """
    # Create a unique root under consideration.
    root1 = Bytes32(b"\x01" * 32)

    # Prepare a vote bitlist with required length; flip two positions to True.
    votes1 = [Boolean(False)] * base_state.config.num_validators.as_int()
    votes1[2] = Boolean(True)  # Validator 2 voted
    votes1[5] = Boolean(True)  # Validator 5 voted

    # Bake the synthetic justification data into a derived state.
    state_with_data = base_state.model_copy(
        update={
            "justifications_roots": JustificationRoots(data=[root1]),
            "justifications_validators": JustificationValidators(data=votes1),
        }
    )

    # Rebuild the map from the flattened state.
    justifications = state_with_data.get_justifications()

    # The only mapping should be root1 -> votes1.
    expected = {root1: votes1}
    assert justifications == expected


def test_get_justifications_multiple_roots(base_state: State) -> None:
    """
    get_justifications: multiple roots slice correctly.

    Steps
    -----
    - Define three roots and three distinct vote patterns.
    - Concatenate the three vote slices in order.
    - Expect the map to split and assign slices to matching roots.
    """
    # Three distinct roots to track.
    root1 = Bytes32(b"\x01" * 32)
    root2 = Bytes32(b"\x02" * 32)
    root3 = Bytes32(b"\x03" * 32)

    # Validator count for each vote slice.
    count = base_state.config.num_validators.as_int()

    # Build per-root vote slices.
    votes1 = [Boolean(False)] * count
    votes1[0] = Boolean(True)  # Only validator 0 in favor for root1

    votes2 = [Boolean(False)] * count
    votes2[1] = Boolean(True)  # Validators 1 and 2 in favor for root2
    votes2[2] = Boolean(True)

    votes3 = [Boolean(True)] * count  # Unanimous in favor for root3

    # Create a state that encodes the three roots and the concatenated votes.
    state_with_data = base_state.model_copy(
        update={
            "justifications_roots": JustificationRoots(data=[root1, root2, root3]),
            "justifications_validators": JustificationValidators(data=votes1 + votes2 + votes3),
        }
    )

    # Reconstruct the mapping from the flattened representation.
    justifications = state_with_data.get_justifications()

    # Validate that each root maps to its intended slice.
    expected = {root1: votes1, root2: votes2, root3: votes3}
    assert justifications == expected
    # Confirm we have exactly three entries.
    assert len(justifications) == 3


def test_with_justifications_empty(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> None:
    """
    with_justifications: writing an empty map clears lists.

    Steps
    -----
    - Seed a state with non-empty flattened justifications.
    - Write an empty map.
    - Expect new state to have empty roots and validators lists.
    - Ensure original state is unchanged.
    """
    # Build a state populated with a single root and a full votes bitlist.
    initial_state = State(
        config=sample_config,
        slot=Slot(0),
        latest_block_header=sample_block_header,
        latest_justified=sample_checkpoint,
        latest_finalized=sample_checkpoint,
        historical_block_hashes=HistoricalBlockHashes(data=[]),
        justified_slots=JustifiedSlots(data=[]),
        justifications_roots=JustificationRoots(data=[Bytes32(b"\x01" * 32)]),
        justifications_validators=JustificationValidators(
            data=[Boolean(True)] * sample_config.num_validators.as_int()
        ),
        validators=Validators(data=[]),
    )

    # Apply an empty justifications map to get a new state snapshot.
    new_state = initial_state.with_justifications({})

    # New state should have empty flattened fields.
    assert not new_state.justifications_roots
    assert not new_state.justifications_validators

    # Original state remains intact (functional update semantics).
    assert initial_state.justifications_roots
    assert initial_state.justifications_validators


def test_with_justifications_deterministic_order(base_state: State) -> None:
    """
    with_justifications: keys are sorted before flattening.

    Steps
    -----
    - Provide a map in unsorted key order.
    - Expect stored roots to be sorted ascending.
    - Expect flattened votes to follow the sorted order.
    """
    # Two roots to test ordering.
    root1 = Bytes32(b"\x01" * 32)
    root2 = Bytes32(b"\x02" * 32)

    # Build two vote slices of proper length.
    count = base_state.config.num_validators.as_int()
    votes1 = [Boolean(False)] * count
    votes2 = [Boolean(True)] * count

    # Intentionally supply the dict in unsorted key order.
    justifications = {root2: votes2, root1: votes1}

    # Flatten into a new state; method sorts keys deterministically.
    new_state = base_state.with_justifications(justifications)

    # The stored roots should be [root1, root2].
    assert list(new_state.justifications_roots) == [root1, root2]
    # The flattened validators list should follow the same order.
    assert list(new_state.justifications_validators) == votes1 + votes2
    # Original state remains empty.
    assert not base_state.justifications_roots


def test_with_justifications_invalid_length(base_state: State) -> None:
    """
    with_justifications: invalid vote slice length raises AssertionError.

    Steps
    -----
    - Build a votes list one element too short.
    - Call with_justifications and expect an assertion.
    """
    # Single root key for the map.
    root1 = Bytes32(b"\x01" * 32)

    # Construct an invalid votes bitlist: one short of required length.
    invalid_votes = [Boolean(True)] * (base_state.config.num_validators - Uint64(1)).as_int()
    justifications = {root1: invalid_votes}

    # The method asserts on incorrect lengths.
    with pytest.raises(AssertionError):
        base_state.with_justifications(justifications)


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
                Bytes32(b"\x03" * 32): [Boolean(True)]
                * DEVNET_CONFIG.validator_registry_limit.as_int(),
                Bytes32(b"\x01" * 32): _create_votes([0]),
                Bytes32(b"\x02" * 32): _create_votes([1, 2]),
            },
            id="complex_unsorted",
        ),
    ],
)
def test_justifications_roundtrip(
    base_state: State, justifications_map: Dict[Bytes32, List[Boolean]]
) -> None:
    """
    Roundtrip: with_justifications then get_justifications preserves data.

    Steps
    -----
    - Write a map into the state via with_justifications (keys sorted internally).
    - Read it back with get_justifications.
    - Compare against the original map sorted by key.
    """
    # Flatten the provided map into a new state snapshot.
    new_state = base_state.with_justifications(justifications_map)

    # Reconstruct the map from the flattened representation.
    reconstructed_map = new_state.get_justifications()

    # Compute the expected canonical form (sorted by key).
    expected_map = dict(sorted(justifications_map.items()))

    # Assert the roundtrip equality.
    assert reconstructed_map == expected_map


def test_generate_genesis(sample_config: Config) -> None:
    """
    generate_genesis: fields are correctly initialized.

    Steps
    -----
    - Create genesis state from config.
    - Validate config propagation, slot=0, and header body_root.
    - Ensure historical/justification lists start empty.
    """
    # Produce a genesis state from the sample config.
    state = State.generate_genesis(
        genesis_time=sample_config.genesis_time,
        num_validators=sample_config.num_validators,
    )

    # Config in state should match the input.
    assert state.config == sample_config
    # Slot should start at 0.
    assert state.slot == Slot(0)
    # Body root must commit to an empty body at genesis.
    expected_body = BlockBody(attestations=Attestations(data=[]))
    assert state.latest_block_header.body_root == hash_tree_root(expected_body)
    # History and justifications must be empty initially.
    assert not state.historical_block_hashes
    assert not state.justified_slots
    assert not state.justifications_roots
    assert not state.justifications_validators


def test_process_slot(genesis_state: State) -> None:
    """
    process_slot: first post-block slot caches pre-block state root.

    Steps
    -----
    - Confirm the latest header has zero state_root at genesis.
    - Call process_slot once; expect it to fill the state_root.
    - Call process_slot again; expect no further changes.
    """
    # At genesis, latest_block_header.state_root is zero.
    assert genesis_state.latest_block_header.state_root == Bytes32.zero()

    # Process one slot; this should backfill the header's state_root.
    state_after_slot = genesis_state.process_slot()

    # The filled root must be the hash of the pre-slot state.
    expected_root = hash_tree_root(genesis_state)
    assert state_after_slot.latest_block_header.state_root == expected_root

    # Re-processing the slot should be a no-op for the state_root.
    state_after_second_slot = state_after_slot.process_slot()
    assert state_after_second_slot.latest_block_header.state_root == expected_root


def test_process_slots(genesis_state: State) -> None:
    """
    process_slots: advances across multiple empty slots.

    Steps
    -----
    - Advance from slot 0 to 5 and verify the slot.
    - Verify the genesis state_root was cached during the first increment.
    - Assert that moving backwards raises an AssertionError.
    """
    # Choose a future slot target.
    target_slot = Slot(5)
    # Advance across empty slots to the target.
    new_state = genesis_state.process_slots(target_slot)

    # The state's slot should equal the target.
    assert new_state.slot == target_slot
    # The header state_root should reflect the genesis state's root.
    assert new_state.latest_block_header.state_root == hash_tree_root(genesis_state)

    # Rewinding is invalid; expect an assertion.
    with pytest.raises(AssertionError):
        new_state.process_slots(Slot(4))


def test_process_block_header_valid(genesis_state: State) -> None:
    """
    process_block_header: valid block updates header-linked fields.

    Steps
    -----
    - Move to slot 1 and build a valid block linked to the current header.
    - Process the header.
    - Verify: genesis becomes justified/finalized, history updated,
      justified_slots marked for slot 0, and latest header set for the new block.
    """
    # Step to slot 1 where we will insert the new block.
    state_at_slot_1 = genesis_state.process_slots(Slot(1))
    # Cache the root of the latest header, i.e., the parent we will vote on.
    genesis_header_root = hash_tree_root(state_at_slot_1.latest_block_header)

    # Build a valid block for slot 1 with proper parent linkage.
    block = _create_block(1, state_at_slot_1.latest_block_header)

    # Apply header processing to update state.
    new_state = state_at_slot_1.process_block_header(block)

    # The parent (genesis) becomes both finalized and justified.
    assert new_state.latest_finalized.root == genesis_header_root
    assert new_state.latest_justified.root == genesis_header_root
    # History should include the parent's root at index 0.
    assert list(new_state.historical_block_hashes) == [genesis_header_root]
    # Slot 0 should be marked justified.
    assert list(new_state.justified_slots) == [Boolean(True)]
    # Latest header now reflects the processed block's header content.
    assert new_state.latest_block_header.slot == block.slot
    assert new_state.latest_block_header.parent_root == block.parent_root
    # state_root remains zero until the next process_slot call.
    assert new_state.latest_block_header.state_root == Bytes32.zero()


@pytest.mark.parametrize(
    "bad_slot, bad_proposer, bad_parent_root, error_msg",
    [
        (2, 1, None, "Block slot mismatch"),
        (1, 2, None, "Incorrect block proposer"),
        (1, 1, Bytes32(b"\xde" * 32), "Block parent root mismatch"),
    ],
)
def test_process_block_header_invalid(
    genesis_state: State,
    bad_slot: int,
    bad_proposer: int,
    bad_parent_root: Bytes32 | None,
    error_msg: str,
) -> None:
    """
    process_block_header: invalid header fields raise assertions.

    Cases
    -----
    - Slot mismatch: block.slot != state.slot.
    - Wrong proposer: proposer_index != slot % num_validators.
    - Parent mismatch: parent_root != hash_tree_root(latest_header).
    """
    # Move to slot 1; this is the expected slot for the new block.
    state_at_slot_1 = genesis_state.process_slots(Slot(1))
    # Capture parent linkage details for the valid case baseline.
    parent_header = state_at_slot_1.latest_block_header
    parent_root = hash_tree_root(parent_header)

    # Build a block with possibly invalid slot, proposer, or parent root.
    block = Block(
        slot=Slot(bad_slot),
        proposer_index=ValidatorIndex(bad_proposer),
        parent_root=bad_parent_root or parent_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=Attestations(data=[])),
    )

    # Expect an AssertionError with the given message for each case.
    with pytest.raises(AssertionError, match=error_msg):
        state_at_slot_1.process_block_header(block)


def test_process_attestations_justification_and_finalization(
    genesis_state: State,
) -> None:
    """
    process_attestations: justify a target and finalize the source.

    Scenario
    --------
    - Build a short chain: genesis -> slot 1 -> slot 4.
    - Cast 7/10 votes (≥ 2/3) to justify slot 4 from genesis.
    - Because no other justifiable slot lies between 0 and 4, finalize genesis.
    """
    # Begin from genesis.
    state = genesis_state

    # Move to slot 1 to allow producing a block there.
    state_at_slot_1 = state.process_slots(Slot(1))
    # Create and process the block at slot 1.
    block1 = _create_block(1, state_at_slot_1.latest_block_header)
    state = state_at_slot_1.process_block(block1)

    # Move to slot 4 and produce/process a block.
    state_at_slot_4 = state.process_slots(Slot(4))
    block4 = _create_block(4, state_at_slot_4.latest_block_header)
    state = state_at_slot_4.process_block(block4)

    # Advance to slot 5 so the header at slot 4 caches its state root.
    state = state.process_slots(Slot(5))

    # Define source (genesis) and target (slot 4) checkpoints for voting.
    genesis_checkpoint = Checkpoint(
        root=state.historical_block_hashes[0],  # Canonical root for slot 0
        slot=Slot(0),
    )
    checkpoint4 = Checkpoint(
        root=hash_tree_root(state.latest_block_header),  # Root of the block at slot 4
        slot=Slot(4),
    )

    # Create 7 votes from distinct validators (indices 0..6) to reach ≥2/3.
    votes_for_4 = [
        _build_signed_attestation(
            validator=ValidatorIndex(i),
            slot=Slot(4),
            head=checkpoint4,
            source=genesis_checkpoint,
            target=checkpoint4,
        ).message
        for i in range(7)
    ]

    # Process attestations directly; returns a new state snapshot.
    new_state = state.process_attestations(votes_for_4)  # type: ignore

    # The target (slot 4) should now be justified.
    assert new_state.latest_justified == checkpoint4
    # The justified bit for slot 4 must be set.
    assert bool(new_state.justified_slots[4]) is True
    # Since no other justifiable slot exists between 0 and 4, genesis is finalized.
    assert new_state.latest_finalized == genesis_checkpoint
    # The per-root vote tracker for the justified target has been cleared.
    assert checkpoint4.root not in new_state.get_justifications()


def test_state_transition_full(genesis_state: State) -> None:
    """
    End-to-end: state_transition processes a full block correctly.

    Steps
    -----
    - Start at genesis.
    - Build a valid block for slot 1.
    - Compute expected post-state by calling process_block manually.
    - Set the block's state_root to the expected hash.
    - Run state_transition with valid signatures.
    - Assert resulting state equals the expected post-state.
    - Verify error cases for invalid signatures and bad state root.
    """
    # Begin with the genesis state.
    state = genesis_state

    # Move to slot 1 so we can propose a block.
    state_at_slot_1 = state.process_slots(Slot(1))
    # Build a valid block linked to the current latest header.
    block = _create_block(1, state_at_slot_1.latest_block_header)

    # Manually compute the post-state result of processing this block.
    expected_state = state_at_slot_1.process_block(block)
    # Embed the correct state root into the header to simulate a valid block.
    block_with_correct_root = block.model_copy(
        update={"state_root": hash_tree_root(expected_state)}
    )

    # Run STF and capture the output state.
    final_state = state.state_transition(
        block_with_correct_root,
        valid_signatures=True,
    )

    # The STF result must match the manually computed expected state.
    assert final_state == expected_state

    # Invalid signatures must cause the STF to assert.
    with pytest.raises(AssertionError, match="Block signatures must be valid"):
        state.state_transition(block_with_correct_root, valid_signatures=False)

    # A block that commits to a wrong state_root must also assert.
    block_with_bad_root = block.model_copy(update={"state_root": Bytes32.zero()})

    with pytest.raises(AssertionError, match="Invalid block state root"):
        state.state_transition(block_with_bad_root, valid_signatures=True)
