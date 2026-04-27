"""Tests for SQLite database implementation."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from lean_spec.forks.lstar import State
from lean_spec.forks.lstar.containers import Block, BlockBody, Checkpoint
from lean_spec.forks.lstar.containers.attestation import AttestationData
from lean_spec.forks.lstar.containers.block.types import AggregatedAttestations
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.storage import (
    SQLiteDatabase,
    StorageCorruptionError,
    StorageReadError,
    StorageWriteError,
)
from lean_spec.types import Bytes32, Uint64


@pytest.fixture
def db() -> Generator[SQLiteDatabase, None, None]:
    """Create an in-memory SQLite database for testing."""
    database = SQLiteDatabase(":memory:", State)
    yield database
    database.close()


class TestBlockOperations:
    """Tests for block storage operations."""

    def test_put_and_get_block(self, db: SQLiteDatabase, genesis_block: Block) -> None:
        """Block can be stored and retrieved by root."""
        root = hash_tree_root(genesis_block)
        db.put_block(genesis_block, root)
        db.commit()

        assert db.get_block(root) == genesis_block

    def test_get_nonexistent_block(self, db: SQLiteDatabase) -> None:
        """Getting a nonexistent block returns None."""
        fake_root = Bytes32(b"\x01" * 32)
        assert db.get_block(fake_root) is None

    def test_has_block(self, db: SQLiteDatabase, genesis_block: Block) -> None:
        """has_block returns correct existence status."""
        root = hash_tree_root(genesis_block)

        assert not db.has_block(root)
        db.put_block(genesis_block, root)
        db.commit()
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
        db.commit()

        assert db.has_block(root)


class TestStateOperations:
    """Tests for state storage operations."""

    def test_put_and_get_state(self, db: SQLiteDatabase, genesis_state: State) -> None:
        """State can be stored and retrieved by block root."""
        root = hash_tree_root(genesis_state)
        db.put_state(genesis_state, root)
        db.commit()

        assert db.get_state(root) == genesis_state

    def test_get_nonexistent_state(self, db: SQLiteDatabase) -> None:
        """Getting a nonexistent state returns None."""
        fake_root = Bytes32(b"\x02" * 32)
        assert db.get_state(fake_root) is None

    def test_has_state(self, db: SQLiteDatabase, genesis_state: State) -> None:
        """has_state returns correct existence status."""
        root = hash_tree_root(genesis_state)

        assert not db.has_state(root)
        db.put_state(genesis_state, root)
        db.commit()
        assert db.has_state(root)


class TestCheckpointOperations:
    """Tests for checkpoint storage operations."""

    def test_put_and_get_justified_checkpoint(self, db: SQLiteDatabase) -> None:
        """Justified checkpoint can be stored and retrieved."""
        checkpoint = Checkpoint(root=Bytes32(b"\x03" * 32), slot=Slot(10))
        db.put_justified_checkpoint(checkpoint)
        db.commit()

        assert db.get_justified_checkpoint() == checkpoint

    def test_put_and_get_finalized_checkpoint(self, db: SQLiteDatabase) -> None:
        """Finalized checkpoint can be stored and retrieved."""
        checkpoint = Checkpoint(root=Bytes32(b"\x04" * 32), slot=Slot(5))
        db.put_finalized_checkpoint(checkpoint)
        db.commit()

        assert db.get_finalized_checkpoint() == checkpoint

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
        db.commit()

        assert db.get_latest_attestation(validator_index) == attestation_data

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
        db.commit()

        assert db.get_all_latest_attestations() == {
            ValidatorIndex(1): attestation_data,
            ValidatorIndex(2): attestation_data,
            ValidatorIndex(3): attestation_data,
        }


class TestHeadTracking:
    """Tests for head root tracking."""

    def test_put_and_get_head_root(self, db: SQLiteDatabase) -> None:
        """Head root can be stored and retrieved."""
        head_root = Bytes32(b"\x08" * 32)
        db.put_head_root(head_root)
        db.commit()

        assert db.get_head_root() == head_root

    def test_get_nonexistent_head_root(self, db: SQLiteDatabase) -> None:
        """Getting nonexistent head root returns None."""
        assert db.get_head_root() is None

    def test_head_root_updates(self, db: SQLiteDatabase) -> None:
        """Head root can be updated."""
        root1 = Bytes32(b"\x09" * 32)
        root2 = Bytes32(b"\x0a" * 32)

        db.put_head_root(root1)
        db.commit()
        assert db.get_head_root() == root1

        db.put_head_root(root2)
        db.commit()
        assert db.get_head_root() == root2


class TestSlotIndex:
    """Tests for slot-to-root indexing."""

    def test_put_and_get_block_root_by_slot(self, db: SQLiteDatabase) -> None:
        """Block root can be stored and retrieved by slot."""
        slot = Slot(100)
        root = Bytes32(b"\x0b" * 32)
        db.put_block_root_by_slot(slot, root)
        db.commit()

        assert db.get_block_root_by_slot(slot) == root

    def test_get_nonexistent_slot(self, db: SQLiteDatabase) -> None:
        """Getting nonexistent slot returns None."""
        assert db.get_block_root_by_slot(Slot(999)) is None

    def test_slot_index_reorg(self, db: SQLiteDatabase) -> None:
        """Slot index reflects the latest canonical chain after reorg."""
        slot = Slot(5)
        root_a = Bytes32(b"\x0b" * 32)
        root_b = Bytes32(b"\x0c" * 32)

        db.put_block_root_by_slot(slot, root_a)
        db.commit()
        assert db.get_block_root_by_slot(slot) == root_a

        # Reorg: overwrite with different root at same slot
        db.put_block_root_by_slot(slot, root_b)
        db.commit()
        assert db.get_block_root_by_slot(slot) == root_b


class TestStateRootIndex:
    """Tests for state root to block root index."""

    def test_put_and_get_block_root_by_state_root(self, db: SQLiteDatabase) -> None:
        """Block root can be stored and retrieved by state root."""
        state_root = Bytes32(b"\x0d" * 32)
        block_root = Bytes32(b"\x0e" * 32)

        db.put_block_root_by_state_root(state_root, block_root)
        db.commit()

        assert db.get_block_root_by_state_root(state_root) == block_root

    def test_get_nonexistent_state_root(self, db: SQLiteDatabase) -> None:
        """Getting nonexistent state root returns None."""
        assert db.get_block_root_by_state_root(Bytes32(b"\xff" * 32)) is None


class TestGenesisTime:
    """Tests for genesis time storage."""

    def test_put_and_get_genesis_time(self, db: SQLiteDatabase) -> None:
        """Genesis time can be stored and retrieved."""
        genesis_time = Uint64(1606824023)
        db.put_genesis_time(genesis_time)
        db.commit()

        assert db.get_genesis_time() == genesis_time

    def test_get_nonexistent_genesis_time(self, db: SQLiteDatabase) -> None:
        """Getting nonexistent genesis time returns None."""
        assert db.get_genesis_time() is None

    def test_genesis_time_zero(self, db: SQLiteDatabase) -> None:
        """Genesis time of zero round-trips correctly."""
        db.put_genesis_time(Uint64(0))
        db.commit()

        assert db.get_genesis_time() == Uint64(0)


class TestBatchWrite:
    """Tests for atomic batch write operations."""

    def test_batch_write_commits_all(self, db: SQLiteDatabase) -> None:
        """All writes within batch are visible after commit."""
        root1 = Bytes32(b"\x10" * 32)
        root2 = Bytes32(b"\x11" * 32)

        with db.batch_write():
            db.put_head_root(root1)
            db.put_block_root_by_slot(Slot(1), root2)

        assert db.get_head_root() == root1
        assert db.get_block_root_by_slot(Slot(1)) == root2

    def test_batch_write_rolls_back_on_exception(self, db: SQLiteDatabase) -> None:
        """Writes are rolled back when an exception occurs within batch."""
        root = Bytes32(b"\x12" * 32)
        db.put_head_root(root)
        db.commit()

        with pytest.raises(ValueError, match="intentional"):
            with db.batch_write():
                db.put_head_root(Bytes32(b"\x13" * 32))
                raise ValueError("intentional")

        # Original value preserved after rollback.
        assert db.get_head_root() == root

    def test_batch_write_reads_see_uncommitted_writes(self, db: SQLiteDatabase) -> None:
        """Reads within batch see writes made in the same transaction."""
        root = Bytes32(b"\x14" * 32)

        with db.batch_write():
            db.put_head_root(root)

            # SQLite read-your-writes: uncommitted data is visible
            # within the same connection.
            assert db.get_head_root() == root

    def test_batch_write_with_block_and_state(
        self, db: SQLiteDatabase, genesis_block: Block, genesis_state: State
    ) -> None:
        """Batch write atomically persists block and state together."""
        block_root = hash_tree_root(genesis_block)

        with db.batch_write():
            db.put_block(genesis_block, block_root)
            db.put_state(genesis_state, block_root)
            db.put_head_root(block_root)

        assert db.get_block(block_root) == genesis_block
        assert db.get_state(block_root) == genesis_state
        assert db.get_head_root() == block_root

    def test_batch_write_rolls_back_storage_write_error(self, db: SQLiteDatabase) -> None:
        """StorageWriteError within batch triggers rollback."""
        root = Bytes32(b"\x15" * 32)
        db.put_head_root(root)
        db.commit()

        with pytest.raises(StorageWriteError):
            with db.batch_write():
                db.put_head_root(Bytes32(b"\x16" * 32))
                raise StorageWriteError("simulated failure")

        assert db.get_head_root() == root


class TestRestartRecovery:
    """Tests for database restart and recovery using real SQLite files."""

    def test_persist_and_reload_genesis(self, genesis_block: Block, genesis_state: State) -> None:
        """Full cycle: write genesis, close DB, reopen, verify data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            block_root = hash_tree_root(genesis_block)
            justified = Checkpoint(root=block_root, slot=Slot(0))
            finalized = Checkpoint(root=block_root, slot=Slot(0))
            genesis_time = Uint64(1000)

            # Write genesis data and close.
            with SQLiteDatabase(db_path, State) as db:
                with db.batch_write():
                    db.put_block(genesis_block, block_root)
                    db.put_state(genesis_state, block_root)
                    db.put_head_root(block_root)
                    db.put_justified_checkpoint(justified)
                    db.put_finalized_checkpoint(finalized)
                    db.put_block_root_by_slot(genesis_block.slot, block_root)
                    db.put_genesis_time(genesis_time)

            # Reopen and verify all data survived.
            with SQLiteDatabase(db_path, State) as db:
                assert db.get_head_root() == block_root
                assert db.get_block(block_root) == genesis_block
                assert db.get_state(block_root) == genesis_state
                assert db.get_justified_checkpoint() == justified
                assert db.get_finalized_checkpoint() == finalized
                assert db.get_block_root_by_slot(genesis_block.slot) == block_root
                assert db.get_genesis_time() == genesis_time


class TestErrorPaths:
    """Tests for error handling and corruption detection."""

    def test_corrupt_block_data_raises_corruption_error(self, db: SQLiteDatabase) -> None:
        """Reading corrupt block data raises StorageCorruptionError."""
        root = Bytes32(b"\x20" * 32)

        # Write garbage bytes directly into the blocks table.
        cursor = db._conn.cursor()
        cursor.execute(
            "INSERT INTO blocks (root, slot, data) VALUES (?, ?, ?)",
            (bytes(root), 0, b"not valid ssz"),
        )
        db._conn.commit()

        with pytest.raises(StorageCorruptionError, match="Corrupt block"):
            db.get_block(root)

    def test_corrupt_state_data_raises_corruption_error(self, db: SQLiteDatabase) -> None:
        """Reading corrupt state data raises StorageCorruptionError."""
        root = Bytes32(b"\x21" * 32)

        cursor = db._conn.cursor()
        cursor.execute(
            "INSERT INTO states (root, slot, data) VALUES (?, ?, ?)",
            (bytes(root), 0, b"not valid ssz"),
        )
        db._conn.commit()

        with pytest.raises(StorageCorruptionError, match="Corrupt state"):
            db.get_state(root)

    def test_corrupt_checkpoint_data_raises_corruption_error(self, db: SQLiteDatabase) -> None:
        """Reading corrupt checkpoint data raises StorageCorruptionError."""
        cursor = db._conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO checkpoints (key, data) VALUES (?, ?)",
            ("justified", b"not valid ssz"),
        )
        db._conn.commit()

        with pytest.raises(StorageCorruptionError, match="Corrupt justified"):
            db.get_justified_checkpoint()

    def test_corrupt_attestation_data_raises_corruption_error(self, db: SQLiteDatabase) -> None:
        """Reading corrupt attestation data raises StorageCorruptionError."""
        cursor = db._conn.cursor()
        cursor.execute(
            "INSERT INTO attestations (validator_index, data) VALUES (?, ?)",
            (42, b"not valid ssz"),
        )
        db._conn.commit()

        with pytest.raises(StorageCorruptionError, match="Corrupt attestation"):
            db.get_latest_attestation(ValidatorIndex(42))

    def test_read_after_close_raises(self, db: SQLiteDatabase) -> None:
        """Operations on a closed database raise StorageReadError."""
        db.close()

        with pytest.raises(StorageReadError):
            db.get_head_root()


class TestMultiBlockChain:
    """Tests for storing a chain of multiple blocks."""

    def test_store_and_retrieve_chain(self, db: SQLiteDatabase, genesis_state: State) -> None:
        """Store a chain of 3 blocks with slot indices, verify all retrievable."""
        blocks: list[tuple[Block, Bytes32]] = []

        for i in range(3):
            parent_root = blocks[-1][1] if blocks else Bytes32.zero()
            block = Block(
                slot=Slot(i),
                proposer_index=ValidatorIndex(0),
                parent_root=parent_root,
                state_root=hash_tree_root(genesis_state),
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
            )
            root = hash_tree_root(block)
            blocks.append((block, root))

        with db.batch_write():
            for block, root in blocks:
                db.put_block(block, root)
                db.put_block_root_by_slot(block.slot, root)

            # Head points to latest block.
            db.put_head_root(blocks[-1][1])

        # All blocks retrievable.
        for block, root in blocks:
            assert db.get_block(root) == block

        # Slot index returns correct roots.
        for block, root in blocks:
            assert db.get_block_root_by_slot(block.slot) == root

        # Head root points to latest.
        assert db.get_head_root() == blocks[-1][1]


class TestPruning:
    """Tests for database pruning operations."""

    def test_prune_removes_blocks_and_states_below_threshold(
        self, db: SQLiteDatabase, genesis_state: State
    ) -> None:
        """Prune removes entries below the given slot."""
        blocks: list[tuple[Block, Bytes32]] = []

        for i in range(5):
            block = Block(
                slot=Slot(i),
                proposer_index=ValidatorIndex(0),
                parent_root=blocks[-1][1] if blocks else Bytes32.zero(),
                state_root=hash_tree_root(genesis_state),
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
            )
            root = hash_tree_root(block)
            blocks.append((block, root))

        with db.batch_write():
            for block, root in blocks:
                db.put_block(block, root)
                db.put_block_root_by_slot(block.slot, root)

        # Prune everything below slot 3.
        with db.batch_write():
            pruned = db.prune_before_slot(Slot(3), keep_roots=frozenset())

        # 3 blocks + 3 slot_index entries pruned.
        assert pruned == 6

        # Slots 0-2 gone.
        for i in range(3):
            assert db.get_block(blocks[i][1]) is None
            assert db.get_block_root_by_slot(Slot(i)) is None

        # Slots 3-4 preserved.
        for i in range(3, 5):
            assert db.get_block(blocks[i][1]) == blocks[i][0]

    def test_prune_preserves_kept_roots(self, db: SQLiteDatabase, genesis_state: State) -> None:
        """Prune preserves blocks/states whose roots are in keep_roots."""
        blocks: list[tuple[Block, Bytes32]] = []

        for i in range(3):
            block = Block(
                slot=Slot(i),
                proposer_index=ValidatorIndex(0),
                parent_root=blocks[-1][1] if blocks else Bytes32.zero(),
                state_root=hash_tree_root(genesis_state),
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
            )
            root = hash_tree_root(block)
            blocks.append((block, root))

        with db.batch_write():
            for block, root in blocks:
                db.put_block(block, root)
                db.put_state(genesis_state, root)

        # Prune below slot 3, but keep slot-0 block (the "finalized" block).
        keep = frozenset({blocks[0][1]})
        with db.batch_write():
            db.prune_before_slot(Slot(3), keep_roots=keep)

        # Slot 0 preserved because it's in keep_roots.
        assert db.get_block(blocks[0][1]) == blocks[0][0]
        assert db.get_state(blocks[0][1]) == genesis_state

        # Slots 1-2 pruned.
        assert db.get_block(blocks[1][1]) is None
        assert db.get_block(blocks[2][1]) is None

    def test_prune_preserves_blocks_at_or_above_threshold(
        self, db: SQLiteDatabase, genesis_state: State
    ) -> None:
        """Prune only affects blocks strictly below the threshold slot."""
        block = Block(
            slot=Slot(5),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )
        root = hash_tree_root(block)

        with db.batch_write():
            db.put_block(block, root)

        # Prune below slot 5 — block at slot 5 should survive.
        with db.batch_write():
            pruned = db.prune_before_slot(Slot(5), keep_roots=frozenset())

        assert pruned == 0
        assert db.get_block(root) == block

    def test_prune_empty_database_is_noop(self, db: SQLiteDatabase) -> None:
        """Pruning an empty database returns zero and does not error."""
        with db.batch_write():
            assert db.prune_before_slot(Slot(100), keep_roots=frozenset()) == 0


class TestLifecycle:
    """Tests for database lifecycle management."""

    def test_context_manager(self) -> None:
        """Database works as context manager."""
        with SQLiteDatabase(":memory:", State) as db:
            root = Bytes32(b"\x0c" * 32)
            db.put_head_root(root)
            db.commit()
            assert db.get_head_root() == root

    def test_close_is_idempotent(self, db: SQLiteDatabase) -> None:
        """Closing database multiple times does not raise."""
        db.close()
        db.close()  # Should not raise
