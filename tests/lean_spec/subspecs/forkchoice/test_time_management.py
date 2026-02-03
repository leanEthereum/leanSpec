"""Tests for time advancement, intervals, and slot management."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT
from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
    State,
    Validator,
)
from lean_spec.subspecs.containers.block import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID


@pytest.fixture
def sample_config() -> Config:
    """Sample configuration for testing."""
    return Config(genesis_time=Uint64(1000))


@pytest.fixture
def sample_store(sample_config: Config) -> Store:
    """Create a sample forkchoice store."""
    # Create a genesis block with empty body
    genesis_block = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(b"state" + b"\x00" * 27),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    genesis_hash = hash_tree_root(genesis_block)

    checkpoint = Checkpoint(root=genesis_hash, slot=Slot(0))

    # Create genesis state with 10 validators for testing
    validators = Validators(
        data=[Validator(pubkey=Bytes52.zero(), index=ValidatorIndex(i)) for i in range(10)]
    )
    state = State.generate_genesis(
        genesis_time=sample_config.genesis_time,
        validators=validators,
    )

    return Store(
        time=Uint64(100),
        config=sample_config,
        head=genesis_hash,
        safe_target=genesis_hash,
        latest_justified=checkpoint,
        latest_finalized=checkpoint,
        blocks={genesis_hash: genesis_block},
        states={genesis_hash: state},
        validator_id=TEST_VALIDATOR_ID,
    )


class TestGetForkchoiceStore:
    """Test Store.get_forkchoice_store() time initialization."""

    @settings(max_examples=100)
    @given(anchor_slot=st.integers(min_value=0, max_value=10000))
    def test_store_time_from_anchor_slot(self, anchor_slot: int) -> None:
        """get_forkchoice_store sets time = anchor_slot * INTERVALS_PER_SLOT."""
        # Must create its own state and block instead of using sample_store()
        # because sample_store() bypasses get_forkchoice_store() with hardcoded time.
        state = State.generate_genesis(
            genesis_time=Uint64(1000),
            validators=Validators(data=[]),
        )
        state_root = hash_tree_root(state)

        # Create anchor block with matching state root
        anchor_block = Block(
            slot=Slot(anchor_slot),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=state_root,
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )

        store = Store.get_forkchoice_store(
            anchor_state=state,
            anchor_block=anchor_block,
            validator_id=TEST_VALIDATOR_ID,
        )

        assert store.time == INTERVALS_PER_SLOT * Uint64(anchor_slot)


class TestOnTick:
    """Test Store on_tick functionality."""

    def test_on_tick_basic(self, sample_store: Store) -> None:
        """Test basic on_tick."""
        initial_time = sample_store.time
        target_time = sample_store.config.genesis_time + Uint64(200)  # Much later time

        sample_store = sample_store.on_tick(target_time, has_proposal=True)

        # Time should advance
        assert sample_store.time > initial_time

    def test_on_tick_no_proposal(self, sample_store: Store) -> None:
        """Test on_tick without proposal."""
        initial_time = sample_store.time
        target_time = sample_store.config.genesis_time + Uint64(100)

        sample_store = sample_store.on_tick(target_time, has_proposal=False)

        # Time should still advance
        assert sample_store.time >= initial_time

    def test_on_tick_already_current(self, sample_store: Store) -> None:
        """Test on_tick when already at target time."""
        initial_time = sample_store.time
        current_target = sample_store.config.genesis_time + initial_time

        # Try to advance to current time (should be no-op)
        sample_store = sample_store.on_tick(current_target, has_proposal=True)

        # Should not change significantly (time can only increase)
        # Tolerance increased for 5-interval per slot system
        assert sample_store.time - initial_time <= Uint64(30)

    def test_on_tick_small_increment(self, sample_store: Store) -> None:
        """Test on_tick with small time increment."""
        initial_time = sample_store.time
        target_time = sample_store.config.genesis_time + initial_time + Uint64(1)

        sample_store = sample_store.on_tick(target_time, has_proposal=False)

        # Should advance by small amount
        assert sample_store.time >= initial_time


class TestIntervalTicking:
    """Test interval-based time ticking."""

    def test_tick_interval_basic(self, sample_store: Store) -> None:
        """Test basic interval ticking."""
        initial_time = sample_store.time

        # Tick one interval forward
        sample_store = sample_store.tick_interval(has_proposal=False)

        # Time should advance by one interval
        assert sample_store.time == initial_time + Uint64(1)

    def test_tick_interval_with_proposal(self, sample_store: Store) -> None:
        """Test interval ticking with proposal."""
        initial_time = sample_store.time

        sample_store = sample_store.tick_interval(has_proposal=True)

        # Time should advance
        assert sample_store.time == initial_time + Uint64(1)

    def test_tick_interval_sequence(self, sample_store: Store) -> None:
        """Test sequence of interval ticks."""
        initial_time = sample_store.time

        # Tick multiple intervals
        for i in range(5):
            sample_store = sample_store.tick_interval(has_proposal=(i % 2 == 0))

        # Should have advanced by 5 intervals
        assert sample_store.time == initial_time + Uint64(5)

    def test_tick_interval_actions_by_phase(self, sample_store: Store) -> None:
        """Test different actions performed based on interval phase."""
        from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT

        # Reset store to known state
        initial_time = Uint64(0)
        object.__setattr__(sample_store, "time", initial_time)

        # Tick through a complete slot cycle
        for interval in range(INTERVALS_PER_SLOT):
            has_proposal = interval == 0  # Proposal only in first interval
            sample_store = sample_store.tick_interval(has_proposal=has_proposal)

            current_interval = sample_store.time % INTERVALS_PER_SLOT
            expected_interval = Uint64((interval + 1)) % INTERVALS_PER_SLOT
            assert current_interval == expected_interval


class TestAttestationProcessingTiming:
    """Test timing of attestation processing."""

    def test_accept_new_attestations_basic(self, sample_store: Store) -> None:
        """Test basic new attestation processing moves aggregated payloads."""
        # The method now processes aggregated payloads, not attestations directly
        # Just verify the method runs without error
        initial_known_payloads = len(sample_store.latest_known_aggregated_payloads)

        # Accept new attestations (which processes aggregated payloads)
        sample_store = sample_store.accept_new_attestations()

        # New payloads should move to known payloads
        assert len(sample_store.latest_new_aggregated_payloads) == 0
        assert len(sample_store.latest_known_aggregated_payloads) >= initial_known_payloads

    def test_accept_new_attestations_multiple(self, sample_store: Store) -> None:
        """Test accepting multiple new aggregated payloads."""
        # Aggregated payloads are now the source of attestations
        # The test is simplified to just test the migration logic
        sample_store = sample_store.accept_new_attestations()

        # All new payloads should move to known payloads
        assert len(sample_store.latest_new_aggregated_payloads) == 0

    def test_accept_new_attestations_empty(self, sample_store: Store) -> None:
        """Test accepting new attestations when there are none."""
        initial_known_payloads = len(sample_store.latest_known_aggregated_payloads)

        # Accept attestations when there are no new payloads
        sample_store = sample_store.accept_new_attestations()

        # Should be no-op
        assert len(sample_store.latest_new_aggregated_payloads) == 0
        assert len(sample_store.latest_known_aggregated_payloads) == initial_known_payloads


class TestProposalHeadTiming:
    """Test proposal head timing logic."""

    def test_get_proposal_head_basic(self, sample_store: Store) -> None:
        """Test getting proposal head for a slot."""
        # Add a block to make the test more realistic
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis_block)

        # Use immutable update to add block
        new_blocks = dict(sample_store.blocks)
        new_blocks[genesis_hash] = genesis_block
        sample_store = sample_store.model_copy(update={"blocks": new_blocks, "head": genesis_hash})

        # Get proposal head for slot 0
        store, head = sample_store.get_proposal_head(Slot(0))

        # Should return the store's head
        assert head == store.head

    def test_get_proposal_head_advances_time(self, sample_store: Store) -> None:
        """Test that get_proposal_head advances store time appropriately."""
        initial_time = sample_store.time

        # Get proposal head for a future slot
        future_slot = Slot(5)
        store, _ = sample_store.get_proposal_head(future_slot)

        # Time may have advanced (depending on slot timing)
        # This is mainly testing that the call doesn't fail
        assert store.time >= initial_time

    def test_get_proposal_head_processes_attestations(self, sample_store: Store) -> None:
        """Test that get_proposal_head processes pending aggregated payloads."""
        # Attestations are now tracked via aggregated payloads
        # Test simplified to verify the method runs correctly
        store, head = sample_store.get_proposal_head(Slot(1))

        # get_proposal_head should have called accept_new_attestations
        # which migrates new payloads to known payloads
        assert len(store.latest_new_aggregated_payloads) == 0


class TestTimeConstants:
    """Test time-related constants and their relationships."""

    def test_time_constants_consistency(self) -> None:
        """Test that time constants are consistent with each other."""
        from lean_spec.subspecs.chain.config import (
            INTERVALS_PER_SLOT,
            MILLISECONDS_PER_INTERVAL,
            MILLISECONDS_PER_SLOT,
            SECONDS_PER_SLOT,
        )

        # MILLISECONDS_PER_SLOT should equal INTERVALS_PER_SLOT * MILLISECONDS_PER_INTERVAL
        expected_milliseconds_per_slot = INTERVALS_PER_SLOT * MILLISECONDS_PER_INTERVAL
        assert MILLISECONDS_PER_SLOT == expected_milliseconds_per_slot

        # MILLISECONDS_PER_SLOT should equal SECONDS_PER_SLOT * 1000
        assert MILLISECONDS_PER_SLOT == SECONDS_PER_SLOT * Uint64(1000)

        # All should be positive
        assert INTERVALS_PER_SLOT > Uint64(0)
        assert MILLISECONDS_PER_INTERVAL > Uint64(0)
        assert MILLISECONDS_PER_SLOT > Uint64(0)
        assert SECONDS_PER_SLOT > Uint64(0)

    def test_interval_slot_relationship(self) -> None:
        """Test the relationship between intervals and slots."""
        from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT

        # Should have multiple intervals per slot
        assert INTERVALS_PER_SLOT >= Uint64(2)  # At least 2 intervals per slot

        # Test arithmetic with intervals
        total_intervals = Uint64(100)
        complete_slots = total_intervals // INTERVALS_PER_SLOT
        remaining_intervals = total_intervals % INTERVALS_PER_SLOT

        # Should be able to reconstruct total
        reconstructed = complete_slots * INTERVALS_PER_SLOT + remaining_intervals
        assert reconstructed == total_intervals
