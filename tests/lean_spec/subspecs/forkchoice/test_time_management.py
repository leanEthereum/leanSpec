"""Tests for time advancement, intervals, and slot management."""

import pytest  # type: ignore[import-not-found]

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex

from .conftest import build_signed_attestation


@pytest.fixture
def sample_config() -> Config:
    """Sample configuration for testing."""
    return Config(num_validators=Uint64(100), genesis_time=Uint64(1000))


@pytest.fixture
def sample_store(sample_config: Config) -> Store:
    """Create a sample forkchoice store."""
    checkpoint = Checkpoint(
        root=Bytes32(b"test_root" + b"\x00" * 23),
        slot=Slot(0),
    )

    return Store(
        time=Uint64(100),
        config=sample_config,
        head=Bytes32(b"head_root" + b"\x00" * 23),
        safe_target=Bytes32(b"safe_root" + b"\x00" * 23),
        latest_justified=checkpoint,
        latest_finalized=checkpoint,
    )


class TestTimeAdvancement:
    """Test Store time advancement functionality."""

    def test_advance_time_basic(self, sample_store: Store) -> None:
        """Test basic time advancement."""
        initial_time = sample_store.time
        # Much later time
        target_time = sample_store.config.genesis_time + Uint64(200)

        sample_store.advance_time(target_time, has_proposal=True)

        # Time should advance
        assert sample_store.time > initial_time

    def test_advance_time_no_proposal(self, sample_store: Store) -> None:
        """Test time advancement without proposal."""
        initial_time = sample_store.time
        target_time = sample_store.config.genesis_time + Uint64(100)

        sample_store.advance_time(target_time, has_proposal=False)

        # Time should still advance
        assert sample_store.time >= initial_time

    def test_advance_time_already_current(self, sample_store: Store) -> None:
        """Test advance_time when already at target time."""
        initial_time = sample_store.time
        current_target = sample_store.config.genesis_time + initial_time

        # Try to advance to current time (should be no-op)
        sample_store.advance_time(current_target, has_proposal=True)

        # Should not change significantly
        # Allow small tolerance due to interval rounding
        assert abs(sample_store.time.as_int() - initial_time.as_int()) <= 10

    def test_advance_time_small_increment(self, sample_store: Store) -> None:
        """Test advance_time with small time increment."""
        initial_time = sample_store.time
        target_time = sample_store.config.genesis_time + initial_time + Uint64(1)

        sample_store.advance_time(target_time, has_proposal=False)

        # Should advance by small amount
        assert sample_store.time >= initial_time


class TestIntervalTicking:
    """Test interval-based time ticking."""

    def test_tick_interval_basic(self, sample_store: Store) -> None:
        """Test basic interval ticking."""
        initial_time = sample_store.time

        # Tick one interval forward
        sample_store.tick_interval(has_proposal=False)

        # Time should advance by one interval
        assert sample_store.time == initial_time + Uint64(1)

    def test_tick_interval_with_proposal(self, sample_store: Store) -> None:
        """Test interval ticking with proposal."""
        initial_time = sample_store.time

        sample_store.tick_interval(has_proposal=True)

        # Time should advance
        assert sample_store.time == initial_time + Uint64(1)

    def test_tick_interval_sequence(self, sample_store: Store) -> None:
        """Test sequence of interval ticks."""
        initial_time = sample_store.time

        # Tick multiple intervals
        for i in range(5):
            sample_store.tick_interval(has_proposal=(i % 2 == 0))

        # Should have advanced by 5 intervals
        assert sample_store.time == initial_time + Uint64(5)

    def test_tick_interval_actions_by_phase(self, sample_store: Store) -> None:
        """Test different actions performed based on interval phase."""
        from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT

        # Reset store to known state
        initial_time = Uint64(0)
        object.__setattr__(sample_store, "time", initial_time)

        # Add some test votes for processing
        test_checkpoint = Checkpoint(
            root=Bytes32(b"test" + b"\x00" * 28),
            slot=Slot(1),
        )
        sample_store.latest_new_votes[ValidatorIndex(0)] = build_signed_attestation(
            ValidatorIndex(0),
            test_checkpoint,
        )

        # Tick through a complete slot cycle
        for interval in range(INTERVALS_PER_SLOT.as_int()):
            has_proposal = interval == 0  # Proposal only in first interval
            sample_store.tick_interval(has_proposal=has_proposal)

            current_interval = sample_store.time % INTERVALS_PER_SLOT
            expected_interval = Uint64((interval + 1) % INTERVALS_PER_SLOT.as_int())
            assert current_interval == expected_interval


class TestSlotTimeCalculations:
    """Test slot and time calculations."""

    def test_slot_to_time_conversion(self, sample_config: Config) -> None:
        """Test conversion from slot to time."""
        from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT

        genesis_time = sample_config.genesis_time

        # Slot 0 should be at genesis time
        slot_0_time = genesis_time + Uint64(0 * SECONDS_PER_SLOT.as_int())
        assert slot_0_time == genesis_time

        # Slot 1 should be at genesis + SECONDS_PER_SLOT
        slot_1_time = genesis_time + Uint64(1 * SECONDS_PER_SLOT.as_int())
        assert slot_1_time == genesis_time + SECONDS_PER_SLOT

        # Slot 10 should be at genesis + 10 * SECONDS_PER_SLOT
        slot_10_time = genesis_time + Uint64(10 * SECONDS_PER_SLOT.as_int())
        assert slot_10_time == genesis_time + Uint64(10) * SECONDS_PER_SLOT

    def test_time_to_slot_conversion(self, sample_config: Config) -> None:
        """Test conversion from time to slot."""
        from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT

        genesis_time = sample_config.genesis_time

        # Time at genesis should be slot 0
        time_at_genesis = genesis_time
        slot_0 = (time_at_genesis - genesis_time) // SECONDS_PER_SLOT
        assert slot_0 == Uint64(0)

        # Time after one slot duration should be slot 1
        time_after_one_slot = genesis_time + SECONDS_PER_SLOT
        slot_1 = (time_after_one_slot - genesis_time) // SECONDS_PER_SLOT
        assert slot_1 == Uint64(1)

        # Time after multiple slots
        time_after_five_slots = genesis_time + Uint64(5) * SECONDS_PER_SLOT
        slot_5 = (time_after_five_slots - genesis_time) // SECONDS_PER_SLOT
        assert slot_5 == Uint64(5)

    def test_interval_calculations(self) -> None:
        """Test interval calculations within slots."""
        from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT

        # Test interval arithmetic
        total_intervals = Uint64(10)
        slot_number = total_intervals // INTERVALS_PER_SLOT
        interval_in_slot = total_intervals % INTERVALS_PER_SLOT

        # 10 intervals with 4 intervals per slot = slot 2, interval 2
        assert slot_number == Uint64(2)
        assert interval_in_slot == Uint64(2)

        # Test boundary cases
        boundary_intervals = INTERVALS_PER_SLOT
        boundary_slot = boundary_intervals // INTERVALS_PER_SLOT
        boundary_interval = boundary_intervals % INTERVALS_PER_SLOT

        assert boundary_slot == Uint64(1)  # Start of next slot
        assert boundary_interval == Uint64(0)  # First interval of slot


class TestVoteProcessingTiming:
    """Test timing of vote processing."""

    def test_accept_new_votes_basic(self, sample_store: Store) -> None:
        """Test basic new vote processing."""
        # Add some new votes
        checkpoint = Checkpoint(
            root=Bytes32(b"test" + b"\x00" * 28),
            slot=Slot(1),
        )
        sample_store.latest_new_votes[ValidatorIndex(0)] = build_signed_attestation(
            ValidatorIndex(0),
            checkpoint,
        )

        initial_new_votes = len(sample_store.latest_new_votes)
        initial_known_votes = len(sample_store.latest_known_votes)

        # Accept new votes
        sample_store.accept_new_votes()

        # New votes should move to known votes
        assert len(sample_store.latest_new_votes) == 0
        assert len(sample_store.latest_known_votes) == initial_known_votes + initial_new_votes

    def test_accept_new_votes_multiple(self, sample_store: Store) -> None:
        """Test accepting multiple new votes."""
        # Add multiple new votes
        checkpoints = [
            Checkpoint(
                root=Bytes32(f"test{i}".encode() + b"\x00" * (32 - len(f"test{i}"))),
                slot=Slot(i),
            )
            for i in range(5)
        ]

        for i, checkpoint in enumerate(checkpoints):
            sample_store.latest_new_votes[ValidatorIndex(i)] = build_signed_attestation(
                ValidatorIndex(i),
                checkpoint,
            )

        # Accept all new votes
        sample_store.accept_new_votes()

        # All should move to known votes
        assert len(sample_store.latest_new_votes) == 0
        assert len(sample_store.latest_known_votes) == 5

        # Verify correct mapping
        for i, checkpoint in enumerate(checkpoints):
            stored = sample_store.latest_known_votes[ValidatorIndex(i)]
            assert stored.message.data.target == checkpoint

    def test_accept_new_votes_empty(self, sample_store: Store) -> None:
        """Test accepting new votes when there are none."""
        initial_known_votes = len(sample_store.latest_known_votes)

        # Accept votes when there are no new votes
        sample_store.accept_new_votes()

        # Should be no-op
        assert len(sample_store.latest_new_votes) == 0
        assert len(sample_store.latest_known_votes) == initial_known_votes


class TestProposalHeadTiming:
    """Test proposal head timing logic."""

    def test_get_proposal_head_basic(self, sample_store: Store) -> None:
        """Test getting proposal head for a slot."""
        # Add a block to make the test more realistic
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis_block)
        sample_store.blocks[genesis_hash] = genesis_block

        # Set store head to genesis
        object.__setattr__(sample_store, "head", genesis_hash)

        # Get proposal head for slot 0
        head = sample_store.get_proposal_head(Slot(0))

        # Should return current head
        assert head == sample_store.head

    def test_get_proposal_head_advances_time(
        self,
        sample_store: Store,
    ) -> None:
        """Test that get_proposal_head advances store time appropriately."""
        initial_time = sample_store.time

        # Get proposal head for a future slot
        future_slot = Slot(5)
        sample_store.get_proposal_head(future_slot)

        # Time may have advanced (depending on slot timing)
        # This is mainly testing that the call doesn't fail
        assert sample_store.time >= initial_time

    def test_get_proposal_head_processes_votes(
        self,
        sample_store: Store,
    ) -> None:
        """Test that get_proposal_head processes pending votes."""
        # Add some new votes
        checkpoint = Checkpoint(
            root=Bytes32(b"vote" + b"\x00" * 28),
            slot=Slot(1),
        )
        sample_store.latest_new_votes[ValidatorIndex(10)] = build_signed_attestation(
            ValidatorIndex(10),
            checkpoint,
        )

        # Get proposal head should process votes
        sample_store.get_proposal_head(Slot(1))

        # Votes should have been processed (moved to known votes)
        assert ValidatorIndex(10) not in sample_store.latest_new_votes
        assert ValidatorIndex(10) in sample_store.latest_known_votes
        stored = sample_store.latest_known_votes[ValidatorIndex(10)]
        assert stored.message.data.target == checkpoint


class TestTimeConstants:
    """Test time-related constants and their relationships."""

    def test_time_constants_consistency(self) -> None:
        """Test that time constants are consistent with each other."""
        from lean_spec.subspecs.chain.config import (
            INTERVALS_PER_SLOT,
            SECONDS_PER_INTERVAL,
            SECONDS_PER_SLOT,
        )

        # SECONDS_PER_SLOT should equal INTERVALS_PER_SLOT * SECONDS_PER_INTERVAL
        expected_seconds_per_slot = INTERVALS_PER_SLOT * SECONDS_PER_INTERVAL
        assert SECONDS_PER_SLOT == expected_seconds_per_slot

        # All should be positive
        assert INTERVALS_PER_SLOT > Uint64(0)
        assert SECONDS_PER_INTERVAL > Uint64(0)
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
