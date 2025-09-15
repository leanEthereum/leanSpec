"""Tests for Store creation, initialization, and basic lifecycle operations."""

import pytest

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, StakerIndex, Uint64


@pytest.fixture
def sample_config() -> Config:
    """Sample configuration for testing."""
    return Config(num_validators=Uint64(100), genesis_time=Uint64(1000))


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Sample checkpoint for testing."""
    return Checkpoint(root=Bytes32(b"test_root" + b"\x00" * 23), slot=Slot(0))


@pytest.fixture
def sample_store(sample_config: Config, sample_checkpoint: Checkpoint) -> Store:
    """Create a sample forkchoice store."""
    return Store(
        time=Uint64(100),
        config=sample_config,
        head=Bytes32(b"head_root" + b"\x00" * 23),
        safe_target=Bytes32(b"safe_root" + b"\x00" * 23),
        latest_justified=sample_checkpoint,
        latest_finalized=sample_checkpoint,
    )


class TestStoreCreation:
    """Test Store creation and initialization."""

    def test_store_creation_basic(self, sample_store: Store) -> None:
        """Test basic Store creation with required fields."""
        assert sample_store.time == Uint64(100)
        assert sample_store.config.num_validators == Uint64(100)
        assert sample_store.head == Bytes32(b"head_root" + b"\x00" * 23)
        assert sample_store.safe_target == Bytes32(b"safe_root" + b"\x00" * 23)
        assert isinstance(sample_store.latest_justified, Checkpoint)
        assert isinstance(sample_store.latest_finalized, Checkpoint)

    def test_store_initialization_with_data(self) -> None:
        """Test Store initialization with blocks and states."""
        config = Config(num_validators=Uint64(10), genesis_time=Uint64(2000))
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(5))

        # Sample block
        block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"state" + b"\x00" * 27),
            body=BlockBody(attestations=[]),
        )
        block_hash = hash_tree_root(block)

        store = Store(
            time=Uint64(200),
            config=config,
            head=block_hash,
            safe_target=block_hash,
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks={block_hash: block},
            states={},
            latest_known_votes={StakerIndex(0): checkpoint},
            latest_new_votes={StakerIndex(1): checkpoint},
        )

        assert store.time == Uint64(200)
        assert store.config == config
        assert store.head == block_hash
        assert store.safe_target == block_hash
        assert block_hash in store.blocks
        assert store.blocks[block_hash] == block
        assert StakerIndex(0) in store.latest_known_votes
        assert StakerIndex(1) in store.latest_new_votes

    def test_store_factory_method(self) -> None:
        """Test Store.get_forkchoice_store factory method."""
        from lean_spec.subspecs.containers import State

        config = Config(num_validators=Uint64(10), genesis_time=Uint64(1000))
        checkpoint = Checkpoint(root=Bytes32(b"genesis" + b"\x00" * 25), slot=Slot(0))

        # Create block header for testing
        from lean_spec.subspecs.containers.block import BlockHeader

        block_header = BlockHeader(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"state" + b"\x00" * 27),
            body_root=Bytes32(b"body" + b"\x00" * 28),
        )

        # Create a minimal state for testing
        state = State(
            config=config,
            slot=Slot(0),
            stakers=[],
            latest_block_header=block_header,
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            historical_block_hashes=[],
            justified_slots=[],
            justifications_roots=[],
            justifications_validators=[],
        )

        # Create anchor block
        anchor_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=hash_tree_root(state),  # Must match state
            body=BlockBody(attestations=[]),
        )

        # Create store using factory method
        store = Store.get_forkchoice_store(state, anchor_block)

        # Verify initialization
        anchor_root = hash_tree_root(anchor_block)
        assert store.config == state.config
        assert store.head == anchor_root
        assert store.safe_target == anchor_root
        assert store.latest_justified == state.latest_justified
        assert store.latest_finalized == state.latest_finalized
        assert anchor_root in store.blocks
        assert anchor_root in store.states


class TestStoreDefaultValues:
    """Test Store default field values."""

    def test_store_empty_collections_by_default(self) -> None:
        """Test that Store initializes empty collections by default."""
        config = Config(num_validators=Uint64(5), genesis_time=Uint64(500))
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(0))

        store = Store(
            time=Uint64(50),
            config=config,
            head=Bytes32(b"head" + b"\x00" * 28),
            safe_target=Bytes32(b"safe" + b"\x00" * 28),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
        )

        # Should have empty collections by default
        assert len(store.blocks) == 0
        assert len(store.states) == 0
        assert len(store.latest_known_votes) == 0
        assert len(store.latest_new_votes) == 0

    def test_store_immutability(self, sample_store: Store) -> None:
        """Test that Store fields are immutable (frozen)."""
        original_time = sample_store.time

        # Should not be able to modify Store fields directly
        with pytest.raises((AttributeError, ValueError)):  # Pydantic frozen model
            sample_store.time = Uint64(999)  # type: ignore[misc]

        # Store should remain unchanged
        assert sample_store.time == original_time


class TestStoreValidation:
    """Test Store field validation."""

    def test_store_validation_required_fields(self) -> None:
        """Test that Store validates required fields."""
        config = Config(num_validators=Uint64(5), genesis_time=Uint64(500))
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(0))

        # Should create successfully with all required fields
        store = Store(
            time=Uint64(100),
            config=config,
            head=Bytes32(b"head" + b"\x00" * 28),
            safe_target=Bytes32(b"safe" + b"\x00" * 28),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
        )

        assert isinstance(store.time, Uint64)
        assert isinstance(store.config, Config)
        assert isinstance(store.head, Bytes32)
        assert isinstance(store.safe_target, Bytes32)
        assert isinstance(store.latest_justified, Checkpoint)
        assert isinstance(store.latest_finalized, Checkpoint)

    def test_store_type_validation(self) -> None:
        """Test Store validates field types."""
        config = Config(num_validators=Uint64(5), genesis_time=Uint64(500))
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(0))

        # Test with wrong type for time - should work due to Pydantic coercion
        # but verify it gets converted to the right type
        store = Store(
            time=100,  # int instead of Uint64
            config=config,
            head=Bytes32(b"head" + b"\x00" * 28),
            safe_target=Bytes32(b"safe" + b"\x00" * 28),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
        )

        # Should be coerced to Uint64
        assert isinstance(store.time, Uint64)
        assert store.time == Uint64(100)


class TestStoreComparison:
    """Test Store equality and comparison."""

    def test_store_equality(self, sample_config: Config, sample_checkpoint: Checkpoint) -> None:
        """Test Store equality comparison."""
        store1 = Store(
            time=Uint64(100),
            config=sample_config,
            head=Bytes32(b"head" + b"\x00" * 28),
            safe_target=Bytes32(b"safe" + b"\x00" * 28),
            latest_justified=sample_checkpoint,
            latest_finalized=sample_checkpoint,
        )

        store2 = Store(
            time=Uint64(100),
            config=sample_config,
            head=Bytes32(b"head" + b"\x00" * 28),
            safe_target=Bytes32(b"safe" + b"\x00" * 28),
            latest_justified=sample_checkpoint,
            latest_finalized=sample_checkpoint,
        )

        store3 = Store(
            time=Uint64(200),  # Different time
            config=sample_config,
            head=Bytes32(b"head" + b"\x00" * 28),
            safe_target=Bytes32(b"safe" + b"\x00" * 28),
            latest_justified=sample_checkpoint,
            latest_finalized=sample_checkpoint,
        )

        assert store1 == store2  # Same values
        assert store1 != store3  # Different time


class TestStoreStringRepresentation:
    """Test Store string representation."""

    def test_store_repr(self, sample_store: Store) -> None:
        """Test Store string representation includes key fields."""
        repr_str = repr(sample_store)

        assert "Store" in repr_str
        assert "time=" in repr_str
        assert "head=" in repr_str

    def test_store_str(self, sample_store: Store) -> None:
        """Test Store string conversion."""
        str_repr = str(sample_store)

        # Should be readable representation
        assert len(str_repr) > 0
        assert "Store" in str_repr or "time" in str_repr
