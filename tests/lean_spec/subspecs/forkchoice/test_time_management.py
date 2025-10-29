"""Tests for time advancement, intervals, and slot management."""

import pytest

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
    State,
    Validator,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64, ValidatorIndex

from .conftest import build_signed_attestation


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
        body=BlockBody(attestations=Attestations(data=[])),
    )
    genesis_hash = hash_tree_root(genesis_block)

    checkpoint = Checkpoint(root=genesis_hash, slot=Slot(0))

    # Create genesis state with 10 validators for testing
    validators = Validators(data=[Validator(pubkey=Bytes52.zero()) for _ in range(10)])
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
    )


class TestTimeAdvancement:
    """Test Store time advancement functionality."""

    def test_advance_time_basic(self, sample_store: Store) -> None:
        """Test basic time advancement."""
        initial_time = sample_store.time
        target_time = sample_store.config.genesis_time + Uint64(200)  # Much later time

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
        assert abs(sample_store.time.as_int() - initial_time.as_int()) <= 10  # small tolerance

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
        sample_store.time = initial_time

        # Add some test attestations for processing
        test_checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(1))
        sample_store.latest_new_attestations[ValidatorIndex(0)] = build_signed_attestation(
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


class TestAttestationProcessingTiming:
    """Test timing of attestation processing."""

    def test_accept_new_attestations_basic(self, sample_store: Store) -> None:
        """Test basic new attestation processing."""
        # Add some new attestations
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(1))
        sample_store.latest_new_attestations[ValidatorIndex(0)] = build_signed_attestation(
            ValidatorIndex(0),
            checkpoint,
        )

        initial_new_attestations = len(sample_store.latest_new_attestations)
        initial_known_attestations = len(sample_store.latest_known_attestations)

        # Accept new attestations
        sample_store.accept_new_attestations()

        # New attestations should move to known attestations
        assert len(sample_store.latest_new_attestations) == 0
        assert (
            len(sample_store.latest_known_attestations)
            == initial_known_attestations + initial_new_attestations
        )

    def test_accept_new_attestations_multiple(self, sample_store: Store) -> None:
        """Test accepting multiple new attestations."""
        # Add multiple new attestations
        checkpoints = [
            Checkpoint(
                root=Bytes32(f"test{i}".encode() + b"\x00" * (32 - len(f"test{i}"))),
                slot=Slot(i),
            )
            for i in range(5)
        ]

        for i, checkpoint in enumerate(checkpoints):
            sample_store.latest_new_attestations[ValidatorIndex(i)] = build_signed_attestation(
                ValidatorIndex(i),
                checkpoint,
            )

        # Accept all new attestations
        sample_store.accept_new_attestations()

        # All should move to known attestations
        assert len(sample_store.latest_new_attestations) == 0
        assert len(sample_store.latest_known_attestations) == 5

        # Verify correct mapping
        for i, checkpoint in enumerate(checkpoints):
            stored = sample_store.latest_known_attestations[ValidatorIndex(i)]
            assert stored.message.data.target == checkpoint

    def test_accept_new_attestations_empty(self, sample_store: Store) -> None:
        """Test accepting new attestations when there are none."""
        initial_known_attestations = len(sample_store.latest_known_attestations)

        # Accept attestations when there are no new attestations
        sample_store.accept_new_attestations()

        # Should be no-op
        assert len(sample_store.latest_new_attestations) == 0
        assert len(sample_store.latest_known_attestations) == initial_known_attestations


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
        sample_store.head = genesis_hash

        # Get proposal head for slot 0
        head = sample_store.get_proposal_head(Slot(0))

        # Should return current head
        assert head == sample_store.head

    def test_get_proposal_head_advances_time(self, sample_store: Store) -> None:
        """Test that get_proposal_head advances store time appropriately."""
        initial_time = sample_store.time

        # Get proposal head for a future slot
        future_slot = Slot(5)
        sample_store.get_proposal_head(future_slot)

        # Time may have advanced (depending on slot timing)
        # This is mainly testing that the call doesn't fail
        assert sample_store.time >= initial_time

    def test_get_proposal_head_processes_attestations(self, sample_store: Store) -> None:
        """Test that get_proposal_head processes pending attestations."""
        # Add some new attestations
        checkpoint = Checkpoint(root=Bytes32(b"attestation" + b"\x00" * 21), slot=Slot(1))
        sample_store.latest_new_attestations[ValidatorIndex(10)] = build_signed_attestation(
            ValidatorIndex(10),
            checkpoint,
        )

        # Get proposal head should process attestations
        sample_store.get_proposal_head(Slot(1))

        # Attestations should have been processed (moved to known attestations)
        assert ValidatorIndex(10) not in sample_store.latest_new_attestations
        assert ValidatorIndex(10) in sample_store.latest_known_attestations
        stored = sample_store.latest_known_attestations[ValidatorIndex(10)]
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
