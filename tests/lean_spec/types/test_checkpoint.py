"""Tests for the Checkpoint container."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Checkpoint, Slot
from lean_spec.types.exceptions import SSZSerializationError


class TestCheckpointConstruction:
    """Field validation rules enforced by the strict Pydantic base."""

    def test_extra_field_is_rejected(self) -> None:
        """Construction with an unknown field raises a Pydantic validation error."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0), epoch=Slot(0))  # type: ignore[call-arg]

    def test_missing_root_is_rejected(self) -> None:
        """Omitting the root raises a Pydantic validation error."""
        with pytest.raises(ValidationError, match="root"):
            Checkpoint(slot=Slot(0))  # type: ignore[call-arg]

    def test_missing_slot_is_rejected(self) -> None:
        """Omitting the slot raises a Pydantic validation error."""
        with pytest.raises(ValidationError, match="slot"):
            Checkpoint(root=Bytes32(b"\x00" * 32))  # type: ignore[call-arg]

    def test_wrong_root_type_is_rejected(self) -> None:
        """A plain string for the root cannot be coerced under strict mode."""
        with pytest.raises(ValidationError):
            Checkpoint(root="not-bytes", slot=Slot(0))  # type: ignore[arg-type]

    def test_wrong_slot_type_is_rejected(self) -> None:
        """A plain float for the slot cannot be coerced under strict mode."""
        with pytest.raises(ValidationError):
            Checkpoint(root=Bytes32(b"\x00" * 32), slot=1.5)  # type: ignore[arg-type]


class TestCheckpointEquality:
    """Structural equality and hashability across the two named fields."""

    def test_same_root_and_slot_are_equal(self) -> None:
        """Two checkpoints with identical fields compare equal."""
        assert Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11)) == Checkpoint(
            root=Bytes32(b"\xab" * 32), slot=Slot(11)
        )

    def test_different_root_breaks_equality(self) -> None:
        """A differing root makes two otherwise identical checkpoints unequal."""
        assert Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11)) != Checkpoint(
            root=Bytes32(b"\xcd" * 32), slot=Slot(11)
        )

    def test_different_slot_breaks_equality(self) -> None:
        """A differing slot makes two otherwise identical checkpoints unequal."""
        assert Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11)) != Checkpoint(
            root=Bytes32(b"\xab" * 32), slot=Slot(12)
        )

    def test_hash_matches_equality(self) -> None:
        """Equal checkpoints share a hash so they collapse inside a set."""
        cp_one = Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11))
        cp_two = Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11))
        assert {cp_one, cp_two} == {cp_one}


class TestCheckpointImmutability:
    """Frozen-model semantics forbid post-construction mutation."""

    def test_assigning_root_raises(self) -> None:
        """Assigning a new root on a constructed checkpoint raises."""
        cp = Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0))
        with pytest.raises(ValidationError, match="frozen"):
            cp.root = Bytes32(b"\xff" * 32)  # type: ignore[misc]

    def test_assigning_slot_raises(self) -> None:
        """Assigning a new slot on a constructed checkpoint raises."""
        cp = Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0))
        with pytest.raises(ValidationError, match="frozen"):
            cp.slot = Slot(99)  # type: ignore[misc]


class TestCheckpointSSZShape:
    """Fixed-size container metadata exposed by the SSZ machinery."""

    def test_is_fixed_size(self) -> None:
        """The container reports fixed-size because both fields are fixed-size."""
        assert Checkpoint.is_fixed_size() is True

    def test_byte_length_is_root_plus_slot(self) -> None:
        """The fixed encoded width is 32 bytes for the root plus 8 bytes for the slot."""
        assert Checkpoint.get_byte_length() == 40


class TestCheckpointSerialization:
    """SSZ wire-format encoding and decoding for the container."""

    def test_encodes_root_then_little_endian_slot(self) -> None:
        """Encoding lays out the root verbatim followed by the slot in little-endian uint64."""
        # Fixture state: root is 00..1f, slot is 1.
        # Trailing 8 bytes are 01 00 00 00 00 00 00 00.
        encoded = Checkpoint(root=Bytes32(bytes(range(32))), slot=Slot(1)).encode_bytes()
        assert encoded == bytes(range(32)) + b"\x01\x00\x00\x00\x00\x00\x00\x00"

    def test_roundtrip_preserves_value(self) -> None:
        """Encoding then decoding recovers the original checkpoint exactly."""
        original = Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(0xDEADBEEF))
        assert Checkpoint.decode_bytes(original.encode_bytes()) == original

    def test_roundtrip_at_max_slot(self) -> None:
        """A checkpoint at slot 2**64 - 1 survives a full encode and decode cycle."""
        original = Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(2**64 - 1))
        assert Checkpoint.decode_bytes(original.encode_bytes()) == original

    def test_decode_rejects_short_input(self) -> None:
        """A 39-byte input is one byte short of the slot field and is rejected."""
        with pytest.raises(SSZSerializationError) as exc_info:
            Checkpoint.decode_bytes(b"\x00" * 39)
        assert str(exc_info.value) == "Slot: expected 8 bytes, got 7"

    def test_decode_rejects_trailing_bytes(self) -> None:
        """A 41-byte input carries one trailing byte past the canonical encoding."""
        with pytest.raises(SSZSerializationError) as exc_info:
            Checkpoint.decode_bytes(b"\x00" * 41)
        assert str(exc_info.value) == "Checkpoint: 1 trailing byte(s) after decode"


class TestCheckpointHashTreeRoot:
    """Merkleization stability and sensitivity for the consensus-critical root."""

    def test_known_value_zero_checkpoint(self) -> None:
        """The all-zero checkpoint hashes to the SSZ root pinned for cross-client parity."""
        zero = Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0))
        assert hash_tree_root(zero) == Bytes32(
            bytes.fromhex("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")
        )

    def test_known_value_fixed_checkpoint(self) -> None:
        """A checkpoint with root 0xaa*32 and slot 7 hashes to a pinned spec-vector root."""
        cp = Checkpoint(root=Bytes32(b"\xaa" * 32), slot=Slot(7))
        assert hash_tree_root(cp) == Bytes32(
            bytes.fromhex("619c4743406fa29ff2ef812a64b72f6a9595c5e8d335dcbe74726a6cb34a6357")
        )

    def test_equal_checkpoints_share_root(self) -> None:
        """Two equal checkpoints produce the same Merkle root."""
        cp_one = Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11))
        cp_two = Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11))
        assert hash_tree_root(cp_one) == hash_tree_root(cp_two)

    def test_different_root_changes_hash(self) -> None:
        """Changing only the root field changes the Merkle root."""
        cp_one = Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11))
        cp_two = Checkpoint(root=Bytes32(b"\xcd" * 32), slot=Slot(11))
        assert hash_tree_root(cp_one) != hash_tree_root(cp_two)

    def test_different_slot_changes_hash(self) -> None:
        """Changing only the slot field changes the Merkle root."""
        cp_one = Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(11))
        cp_two = Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(12))
        assert hash_tree_root(cp_one) != hash_tree_root(cp_two)


class TestCheckpointAdvanceTo:
    """Forward-only progression rules for justified and finalized checkpoints."""

    @pytest.mark.parametrize(
        ("current_slot", "candidate_slot", "winner"),
        [
            # Strictly higher candidate slot wins.
            (3, 4, "candidate"),
            # Strictly lower candidate slot loses.
            (4, 3, "current"),
            # Tie at any slot keeps the receiver, regardless of root.
            (7, 7, "current"),
        ],
    )
    def test_picks_receiver_unless_candidate_is_strictly_higher(
        self, current_slot: int, candidate_slot: int, winner: str
    ) -> None:
        """The candidate replaces the receiver only when its slot is strictly greater."""
        current = Checkpoint(root=Bytes32(b"\xa0" * 32), slot=Slot(current_slot))
        candidate = Checkpoint(root=Bytes32(b"\xb0" * 32), slot=Slot(candidate_slot))
        expected = candidate if winner == "candidate" else current
        assert current.advance_to(candidate) == expected

    def test_tie_is_symmetric_to_the_caller(self) -> None:
        """On a slot tie the receiver of the call wins, swapping callers swaps the result."""
        cp_a = Checkpoint(root=Bytes32(b"\xa0" * 32), slot=Slot(7))
        cp_b = Checkpoint(root=Bytes32(b"\xb0" * 32), slot=Slot(7))
        assert cp_a.advance_to(cp_b) == cp_a
        assert cp_b.advance_to(cp_a) == cp_b

    def test_self_advance_returns_receiver(self) -> None:
        """Advancing a checkpoint against itself returns the receiver unchanged."""
        cp = Checkpoint(root=Bytes32(b"\xa0" * 32), slot=Slot(2))
        assert cp.advance_to(cp) == cp

    def test_zero_slot_receiver_yields_to_any_higher_candidate(self) -> None:
        """A genesis-slot checkpoint is replaced by any candidate at a higher slot."""
        current = Checkpoint(root=Bytes32(b"\xa0" * 32), slot=Slot(0))
        candidate = Checkpoint(root=Bytes32(b"\xb0" * 32), slot=Slot(1))
        assert current.advance_to(candidate) == candidate

    def test_max_slot_receiver_never_yields(self) -> None:
        """A checkpoint pinned at the uint64 maximum can never be advanced further."""
        current = Checkpoint(root=Bytes32(b"\xa0" * 32), slot=Slot(2**64 - 1))
        candidate = Checkpoint(root=Bytes32(b"\xb0" * 32), slot=Slot(2**64 - 2))
        assert current.advance_to(candidate) == current
