"""Tests for SQLite database implementation."""

from __future__ import annotations

from collections.abc import Generator

import pytest

from lean_spec.subspecs.containers import Block, BlockBody, Checkpoint, State
from lean_spec.subspecs.containers.attestation import AttestationData
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.storage import SQLiteDatabase
from lean_spec.types import Bytes32


@pytest.fixture
def db() -> Generator[SQLiteDatabase, None, None]:
    """Create an in-memory SQLite database for testing."""
    database = SQLiteDatabase(":memory:")
    yield database
    database.close()


class TestBlockOperations:
    """Tests for block storage operations."""

    def test_put_and_get_block(self, db: SQLiteDatabase, genesis_block: Block) -> None:
        """Block can be stored and retrieved by root."""
        root = hash_tree_root(genesis_block)
        db.put_block(genesis_block, root)

        retrieved = db.get_block(root)
        assert retrieved is not None
        assert retrieved.slot == genesis_block.slot
        assert retrieved.proposer_index == genesis_block.proposer_index
        assert retrieved.state_root == genesis_block.state_root

    def test_get_nonexistent_block(self, db: SQLiteDatabase) -> None:
        """Getting a nonexistent block returns None."""
        fake_root = Bytes32(b"\x01" * 32)
        assert db.get_block(fake_root) is None

    def test_has_block(self, db: SQLiteDatabase, genesis_block: Block) -> None:
        """has_block returns correct existence status."""
        root = hash_tree_root(genesis_block)

        assert not db.has_block(root)
        db.put_block(genesis_block, root)
        assert db.has_block(root)

    def test_put_block_overwrites(self, db: SQLiteDatabase, genesis_state: State) -> None:
        """Putting a block with same root overwrites previous."""
        block1 = Block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )
        root = hash_tree_root(block1)

        db.put_block(block1, root)
        db.put_block(block1, root)  # Same block again

        # Should not raise, just overwrite
        assert db.has_block(root)


class TestStateOperations:
    """Tests for state storage operations."""

    def test_put_and_get_state(self, db: SQLiteDatabase, genesis_state: State) -> None:
        """State can be stored and retrieved by root."""
        root = hash_tree_root(genesis_state)
        db.put_state(genesis_state, root)

        retrieved = db.get_state(root)
        assert retrieved is not None
        assert retrieved.slot == genesis_state.slot
        assert len(retrieved.validators) == len(genesis_state.validators)

    def test_get_nonexistent_state(self, db: SQLiteDatabase) -> None:
        """Getting a nonexistent state returns None."""
        fake_root = Bytes32(b"\x02" * 32)
        assert db.get_state(fake_root) is None

    def test_has_state(self, db: SQLiteDatabase, genesis_state: State) -> None:
        """has_state returns correct existence status."""
        root = hash_tree_root(genesis_state)

        assert not db.has_state(root)
        db.put_state(genesis_state, root)
        assert db.has_state(root)


class TestCheckpointOperations:
    """Tests for checkpoint storage operations."""

    def test_put_and_get_justified_checkpoint(self, db: SQLiteDatabase) -> None:
        """Justified checkpoint can be stored and retrieved."""
        checkpoint = Checkpoint(root=Bytes32(b"\x03" * 32), slot=Slot(10))
        db.put_justified_checkpoint(checkpoint)

        retrieved = db.get_justified_checkpoint()
        assert retrieved is not None
        assert retrieved.root == checkpoint.root
        assert retrieved.slot == checkpoint.slot

    def test_put_and_get_finalized_checkpoint(self, db: SQLiteDatabase) -> None:
        """Finalized checkpoint can be stored and retrieved."""
        checkpoint = Checkpoint(root=Bytes32(b"\x04" * 32), slot=Slot(5))
        db.put_finalized_checkpoint(checkpoint)

        retrieved = db.get_finalized_checkpoint()
        assert retrieved is not None
        assert retrieved.root == checkpoint.root
        assert retrieved.slot == checkpoint.slot

    def test_get_nonexistent_checkpoints(self, db: SQLiteDatabase) -> None:
        """Getting nonexistent checkpoints returns None."""
        assert db.get_justified_checkpoint() is None
        assert db.get_finalized_checkpoint() is None


class TestAttestationOperations:
    """Tests for attestation storage operations."""

    @pytest.fixture
    def attestation_data(self) -> AttestationData:
        """Create attestation data for testing."""
        return AttestationData(
            slot=Slot(5),
            head=Checkpoint(root=Bytes32(b"\x05" * 32), slot=Slot(5)),
            target=Checkpoint(root=Bytes32(b"\x06" * 32), slot=Slot(4)),
            source=Checkpoint(root=Bytes32(b"\x07" * 32), slot=Slot(3)),
        )

    def test_put_and_get_latest_attestation(
        self, db: SQLiteDatabase, attestation_data: AttestationData
    ) -> None:
        """Attestation can be stored and retrieved by validator index."""
        validator_index = ValidatorIndex(42)
        db.put_latest_attestation(validator_index, attestation_data)

        retrieved = db.get_latest_attestation(validator_index)
        assert retrieved is not None
        assert retrieved.slot == attestation_data.slot

    def test_get_nonexistent_attestation(self, db: SQLiteDatabase) -> None:
        """Getting a nonexistent attestation returns None."""
        assert db.get_latest_attestation(ValidatorIndex(999)) is None

    def test_get_all_latest_attestations(
        self, db: SQLiteDatabase, attestation_data: AttestationData
    ) -> None:
        """All attestations can be retrieved at once."""
        db.put_latest_attestation(ValidatorIndex(1), attestation_data)
        db.put_latest_attestation(ValidatorIndex(2), attestation_data)
        db.put_latest_attestation(ValidatorIndex(3), attestation_data)

        all_attestations = db.get_all_latest_attestations()
        assert len(all_attestations) == 3
        assert ValidatorIndex(1) in all_attestations
        assert ValidatorIndex(2) in all_attestations
        assert ValidatorIndex(3) in all_attestations


class TestHeadTracking:
    """Tests for head root tracking."""

    def test_put_and_get_head_root(self, db: SQLiteDatabase) -> None:
        """Head root can be stored and retrieved."""
        head_root = Bytes32(b"\x08" * 32)
        db.put_head_root(head_root)

        retrieved = db.get_head_root()
        assert retrieved == head_root

    def test_get_nonexistent_head_root(self, db: SQLiteDatabase) -> None:
        """Getting nonexistent head root returns None."""
        assert db.get_head_root() is None

    def test_head_root_updates(self, db: SQLiteDatabase) -> None:
        """Head root can be updated."""
        root1 = Bytes32(b"\x09" * 32)
        root2 = Bytes32(b"\x0a" * 32)

        db.put_head_root(root1)
        assert db.get_head_root() == root1

        db.put_head_root(root2)
        assert db.get_head_root() == root2


class TestSlotIndex:
    """Tests for slot-to-root indexing."""

    def test_put_and_get_block_root_by_slot(self, db: SQLiteDatabase) -> None:
        """Block root can be stored and retrieved by slot."""
        slot = Slot(100)
        root = Bytes32(b"\x0b" * 32)
        db.put_block_root_by_slot(slot, root)

        retrieved = db.get_block_root_by_slot(slot)
        assert retrieved == root

    def test_get_nonexistent_slot(self, db: SQLiteDatabase) -> None:
        """Getting nonexistent slot returns None."""
        assert db.get_block_root_by_slot(Slot(999)) is None


class TestLifecycle:
    """Tests for database lifecycle management."""

    def test_context_manager(self) -> None:
        """Database works as context manager."""
        with SQLiteDatabase(":memory:") as db:
            root = Bytes32(b"\x0c" * 32)
            db.put_head_root(root)
            assert db.get_head_root() == root

    def test_close_is_idempotent(self, db: SQLiteDatabase) -> None:
        """Closing database multiple times does not raise."""
        db.close()
        db.close()  # Should not raise
