"""Tests for Ethereum 2.0 ENR types (Eth2Data, AttestationSubnets, SyncCommitteeSubnets)."""

import pytest
from pydantic import ValidationError

from lean_spec.subspecs.networking.enr import Eth2Data
from lean_spec.subspecs.networking.enr.eth2 import (
    FAR_FUTURE_EPOCH,
    AttestationSubnets,
    SyncCommitteeSubnets,
)
from lean_spec.types import Uint64
from lean_spec.types.byte_arrays import Bytes4


class TestEth2Data:
    """Tests for Eth2Data structure."""

    def test_create_eth2_data(self) -> None:
        """Eth2Data can be created with valid parameters."""
        data = Eth2Data(
            fork_digest=Bytes4(b"\x12\x34\x56\x78"),
            next_fork_version=Bytes4(b"\x02\x00\x00\x00"),
            next_fork_epoch=Uint64(194048),
        )
        assert data.fork_digest == Bytes4(b"\x12\x34\x56\x78")
        assert data.next_fork_epoch == Uint64(194048)

    def test_no_scheduled_fork_factory(self) -> None:
        """no_scheduled_fork factory creates correct data."""
        digest = Bytes4(b"\xab\xcd\xef\x01")
        version = Bytes4(b"\x01\x00\x00\x00")
        data = Eth2Data.no_scheduled_fork(digest, version)

        assert data.fork_digest == digest
        assert data.next_fork_version == version
        assert data.next_fork_epoch == FAR_FUTURE_EPOCH

    def test_eth2_data_immutable(self) -> None:
        """Eth2Data is immutable (frozen)."""
        data = Eth2Data(
            fork_digest=Bytes4(b"\x12\x34\x56\x78"),
            next_fork_version=Bytes4(b"\x02\x00\x00\x00"),
            next_fork_epoch=Uint64(0),
        )
        with pytest.raises(ValidationError):
            data.fork_digest = Bytes4(b"\x00\x00\x00\x00")

    def test_far_future_epoch_value(self) -> None:
        """FAR_FUTURE_EPOCH is max uint64."""
        assert FAR_FUTURE_EPOCH == Uint64(2**64 - 1)


class TestAttestationSubnets:
    """Tests for AttestationSubnets bitvector."""

    def test_empty_subscriptions(self) -> None:
        """none() creates empty subscriptions."""
        subnets = AttestationSubnets.none()
        assert subnets.subscription_count() == 0
        assert subnets.subscribed_subnets() == []

    def test_all_subscriptions(self) -> None:
        """all() creates full subscriptions."""
        subnets = AttestationSubnets.all()
        assert subnets.subscription_count() == 64
        assert len(subnets.subscribed_subnets()) == 64

    def test_specific_subscriptions(self) -> None:
        """from_subnet_ids() creates specific subscriptions."""
        subnets = AttestationSubnets.from_subnet_ids([0, 5, 63])

        assert subnets.is_subscribed(0)
        assert subnets.is_subscribed(5)
        assert subnets.is_subscribed(63)
        assert not subnets.is_subscribed(1)
        assert not subnets.is_subscribed(62)
        assert subnets.subscription_count() == 3

    def test_subscribed_subnets_list(self) -> None:
        """subscribed_subnets() returns correct list."""
        subnets = AttestationSubnets.from_subnet_ids([10, 20, 30])
        result = subnets.subscribed_subnets()

        assert result == [10, 20, 30]

    def test_invalid_subnet_id_in_from_subnet_ids(self) -> None:
        """from_subnet_ids() raises for invalid subnet IDs."""
        with pytest.raises(ValueError):
            AttestationSubnets.from_subnet_ids([64])

        with pytest.raises(ValueError):
            AttestationSubnets.from_subnet_ids([-1])

    def test_invalid_subnet_id_in_is_subscribed(self) -> None:
        """is_subscribed() raises for invalid subnet IDs."""
        subnets = AttestationSubnets.none()

        with pytest.raises(ValueError):
            subnets.is_subscribed(64)

        with pytest.raises(ValueError):
            subnets.is_subscribed(-1)

    def test_from_subnet_ids_empty_list(self) -> None:
        """from_subnet_ids with empty list creates no subscriptions."""
        subnets = AttestationSubnets.from_subnet_ids([])
        assert subnets.subscription_count() == 0
        assert subnets.subscribed_subnets() == []

    def test_from_subnet_ids_with_duplicates(self) -> None:
        """from_subnet_ids handles duplicates correctly."""
        subnets = AttestationSubnets.from_subnet_ids([5, 5, 5, 10])
        assert subnets.subscription_count() == 2
        assert subnets.subscribed_subnets() == [5, 10]

    def test_encode_bytes_empty(self) -> None:
        """Empty subscriptions serialize to 8 zero bytes."""
        subnets = AttestationSubnets.none()
        assert subnets.encode_bytes() == b"\x00" * 8

    def test_encode_bytes_all(self) -> None:
        """All subscriptions serialize to 8 0xff bytes."""
        subnets = AttestationSubnets.all()
        assert subnets.encode_bytes() == b"\xff" * 8

    def test_decode_bytes_roundtrip(self) -> None:
        """Encode then decode produces equivalent result."""
        original = AttestationSubnets.from_subnet_ids([0, 5, 63])
        encoded = original.encode_bytes()
        decoded = AttestationSubnets.decode_bytes(encoded)
        assert decoded.subscribed_subnets() == original.subscribed_subnets()

    def test_length_constant(self) -> None:
        """LENGTH constant is 64."""
        assert AttestationSubnets.LENGTH == 64


class TestSyncCommitteeSubnets:
    """Tests for SyncCommitteeSubnets bitvector."""

    def test_none_creates_empty_subscriptions(self) -> None:
        """none() creates empty subscriptions."""
        subnets = SyncCommitteeSubnets.none()
        for i in range(4):
            assert not subnets.is_subscribed(i)

    def test_all_creates_full_subscriptions(self) -> None:
        """all() creates full subscriptions."""
        subnets = SyncCommitteeSubnets.all()
        for i in range(4):
            assert subnets.is_subscribed(i)

    def test_is_subscribed_with_valid_ids(self) -> None:
        """is_subscribed() works for valid subnet IDs 0-3."""
        subnets = SyncCommitteeSubnets.all()
        assert subnets.is_subscribed(0)
        assert subnets.is_subscribed(1)
        assert subnets.is_subscribed(2)
        assert subnets.is_subscribed(3)

    def test_is_subscribed_raises_for_invalid_high_id(self) -> None:
        """is_subscribed() raises for subnet ID >= 4."""
        subnets = SyncCommitteeSubnets.none()
        with pytest.raises(ValueError, match="must be 0-3"):
            subnets.is_subscribed(4)

    def test_is_subscribed_raises_for_negative_id(self) -> None:
        """is_subscribed() raises for negative subnet ID."""
        subnets = SyncCommitteeSubnets.none()
        with pytest.raises(ValueError, match="must be 0-3"):
            subnets.is_subscribed(-1)

    def test_from_subnet_ids_specific(self) -> None:
        """from_subnet_ids() creates specific subscriptions."""
        subnets = SyncCommitteeSubnets.from_subnet_ids([0, 2])
        assert subnets.is_subscribed(0)
        assert not subnets.is_subscribed(1)
        assert subnets.is_subscribed(2)
        assert not subnets.is_subscribed(3)

    def test_from_subnet_ids_empty_list(self) -> None:
        """from_subnet_ids with empty list creates no subscriptions."""
        subnets = SyncCommitteeSubnets.from_subnet_ids([])
        assert subnets.subscription_count() == 0

    def test_from_subnet_ids_with_duplicates(self) -> None:
        """from_subnet_ids handles duplicates correctly."""
        subnets = SyncCommitteeSubnets.from_subnet_ids([1, 1, 1, 3])
        assert subnets.subscription_count() == 2
        assert subnets.subscribed_subnets() == [1, 3]

    def test_from_subnet_ids_invalid(self) -> None:
        """from_subnet_ids() raises for invalid subnet IDs."""
        with pytest.raises(ValueError, match="must be 0-3"):
            SyncCommitteeSubnets.from_subnet_ids([4])

        with pytest.raises(ValueError, match="must be 0-3"):
            SyncCommitteeSubnets.from_subnet_ids([-1])

    def test_subscribed_subnets(self) -> None:
        """subscribed_subnets() returns correct list."""
        subnets = SyncCommitteeSubnets.from_subnet_ids([1, 3])
        assert subnets.subscribed_subnets() == [1, 3]

    def test_subscription_count(self) -> None:
        """subscription_count() returns correct count."""
        subnets = SyncCommitteeSubnets.from_subnet_ids([0, 2, 3])
        assert subnets.subscription_count() == 3

    def test_encode_bytes_empty(self) -> None:
        """Empty subscriptions serialize to 1 zero byte."""
        subnets = SyncCommitteeSubnets.none()
        assert subnets.encode_bytes() == b"\x00"

    def test_encode_bytes_all(self) -> None:
        """All subscriptions serialize to 0x0f (lower 4 bits set)."""
        subnets = SyncCommitteeSubnets.all()
        assert subnets.encode_bytes() == b"\x0f"

    def test_decode_bytes_roundtrip(self) -> None:
        """Encode then decode produces equivalent result."""
        original = SyncCommitteeSubnets.from_subnet_ids([0, 2])
        encoded = original.encode_bytes()
        decoded = SyncCommitteeSubnets.decode_bytes(encoded)
        assert decoded.subscribed_subnets() == original.subscribed_subnets()

    def test_length_constant(self) -> None:
        """LENGTH constant is 4."""
        assert SyncCommitteeSubnets.LENGTH == 4
