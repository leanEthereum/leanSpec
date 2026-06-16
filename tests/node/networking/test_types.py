"""Tests for the networking shared types and domain newtypes."""

from __future__ import annotations

import pytest

from lean_spec.node.networking.types import (
    ConnectionState,
    Direction,
    DomainType,
    ForkDigest,
    Multiaddr,
    NodeId,
    Port,
    ProtocolId,
    SeqNumber,
    Version,
)
from lean_spec.spec.ssz import Bytes4, Bytes32, SSZValueError, Uint16, Uint64


class TestConnectionState:
    """Tests for ConnectionState enum."""

    def test_state_values(self) -> None:
        """ConnectionState has the 4 expected states."""
        assert ConnectionState.DISCONNECTED == 1
        assert ConnectionState.CONNECTING == 2
        assert ConnectionState.CONNECTED == 3
        assert ConnectionState.DISCONNECTING == 4


class TestDirection:
    """Tests for Direction enum."""

    def test_direction_values(self) -> None:
        """Direction has inbound and outbound."""
        assert Direction.INBOUND == 1
        assert Direction.OUTBOUND == 2


class TestDomainType:
    """Tests for DomainType."""

    def test_is_four_byte_array(self) -> None:
        """DomainType wraps exactly four bytes and is a Bytes4."""
        domain_type = DomainType(b"\x01\x00\x00\x00")
        assert isinstance(domain_type, Bytes4)
        assert bytes(domain_type) == b"\x01\x00\x00\x00"

    def test_wrong_length_rejected(self) -> None:
        """A byte count other than four is rejected with the full length message."""
        with pytest.raises(SSZValueError) as exception_info:
            DomainType(b"\x00" * 5)
        assert str(exception_info.value) == "DomainType requires exactly 4 bytes, got 5"

    def test_encode_decode_roundtrip(self) -> None:
        """SSZ encoding then decoding reproduces the original value."""
        domain_type = DomainType(b"\x01\x00\x00\x00")
        assert DomainType.decode_bytes(domain_type.encode_bytes()) == domain_type


class TestNodeId:
    """Tests for NodeId."""

    def test_is_thirty_two_byte_array(self) -> None:
        """NodeId wraps exactly thirty-two bytes and is a Bytes32."""
        node_id = NodeId(b"\xab" * 32)
        assert isinstance(node_id, Bytes32)
        assert bytes(node_id) == b"\xab" * 32

    def test_wrong_length_rejected(self) -> None:
        """A byte count other than thirty-two is rejected with the full length message."""
        with pytest.raises(SSZValueError) as exception_info:
            NodeId(b"\x00" * 31)
        assert str(exception_info.value) == "NodeId requires exactly 32 bytes, got 31"

    def test_encode_decode_roundtrip(self) -> None:
        """SSZ encoding then decoding reproduces the original value."""
        node_id = NodeId(b"\xab" * 32)
        assert NodeId.decode_bytes(node_id.encode_bytes()) == node_id


class TestForkDigest:
    """Tests for ForkDigest."""

    def test_is_four_byte_array(self) -> None:
        """ForkDigest wraps exactly four bytes and is a Bytes4."""
        fork_digest = ForkDigest(b"\x12\x34\x56\x78")
        assert isinstance(fork_digest, Bytes4)
        assert bytes(fork_digest) == b"\x12\x34\x56\x78"

    def test_wrong_length_rejected(self) -> None:
        """A byte count other than four is rejected with the full length message."""
        with pytest.raises(SSZValueError) as exception_info:
            ForkDigest(b"\x00" * 3)
        assert str(exception_info.value) == "ForkDigest requires exactly 4 bytes, got 3"

    def test_hash_distinguishes_from_other_bytes4_newtype(self) -> None:
        """Equal bytes in a sibling four-byte newtype hash differently from a ForkDigest."""
        assert hash(ForkDigest(b"\x12\x34\x56\x78")) != hash(Version(b"\x12\x34\x56\x78"))


class TestVersion:
    """Tests for Version."""

    def test_is_four_byte_array(self) -> None:
        """Version wraps exactly four bytes and is a Bytes4."""
        version = Version(b"\x01\x00\x00\x00")
        assert isinstance(version, Bytes4)
        assert bytes(version) == b"\x01\x00\x00\x00"

    def test_wrong_length_rejected(self) -> None:
        """A byte count other than four is rejected with the full length message."""
        with pytest.raises(SSZValueError) as exception_info:
            Version(b"\x00" * 8)
        assert str(exception_info.value) == "Version requires exactly 4 bytes, got 8"

    def test_repr_names_the_newtype(self) -> None:
        """The official representation labels the value with its own type name."""
        assert repr(Version(b"\x01\x00\x00\x00")) == "Version(01000000)"


class TestSeqNumber:
    """Tests for SeqNumber."""

    def test_is_unsigned_sixty_four_bit_integer(self) -> None:
        """SeqNumber is a Uint64 carrying its integer value."""
        sequence_number = SeqNumber(42)
        assert isinstance(sequence_number, Uint64)
        assert int(sequence_number) == 42

    def test_maximum_value_accepted(self) -> None:
        """The largest representable sixty-four-bit value is accepted."""
        assert int(SeqNumber(2**64 - 1)) == 18446744073709551615

    def test_above_maximum_rejected(self) -> None:
        """A value past the sixty-four-bit ceiling is rejected with the full range message."""
        with pytest.raises(SSZValueError) as exception_info:
            SeqNumber(2**64)
        assert (
            str(exception_info.value)
            == "18446744073709551616 out of range for SeqNumber [0, 18446744073709551615]"
        )

    def test_equality_rejects_a_different_uint_newtype(self) -> None:
        """Comparing against another unsigned integer type raises with the full operand message."""
        with pytest.raises(TypeError) as exception_info:
            bool(SeqNumber(7) == Port(7))
        assert (
            str(exception_info.value)
            == "Unsupported operand type(s) for ==: 'SeqNumber' and 'Port'"
        )


class TestPort:
    """Tests for Port."""

    def test_is_unsigned_sixteen_bit_integer(self) -> None:
        """Port is a Uint16 carrying its integer value."""
        port = Port(9000)
        assert isinstance(port, Uint16)
        assert int(port) == 9000

    def test_maximum_value_accepted(self) -> None:
        """The largest representable sixteen-bit port number is accepted."""
        assert int(Port(65535)) == 65535

    def test_above_maximum_rejected(self) -> None:
        """A port past the sixteen-bit ceiling is rejected with the full range message."""
        with pytest.raises(SSZValueError) as exception_info:
            Port(65536)
        assert str(exception_info.value) == "65536 out of range for Port [0, 65535]"

    def test_equality_rejects_the_plain_uint16_base(self) -> None:
        """Comparing against the unwrapped base integer raises with the full operand message."""
        with pytest.raises(TypeError) as exception_info:
            bool(Port(9000) == Uint16(9000))
        assert (
            str(exception_info.value) == "Unsupported operand type(s) for ==: 'Port' and 'Uint16'"
        )


class TestProtocolId:
    """Tests for ProtocolId."""

    def test_is_a_string(self) -> None:
        """ProtocolId is a plain string carrying the libp2p protocol path."""
        protocol_id = ProtocolId("/eth2/beacon_chain/req/status/1/ssz_snappy")
        assert isinstance(protocol_id, str)
        assert protocol_id == "/eth2/beacon_chain/req/status/1/ssz_snappy"

    def test_carries_no_instance_dictionary(self) -> None:
        """The slotted definition forbids attaching arbitrary attributes."""
        with pytest.raises(AttributeError):
            ProtocolId("/x").extra_field = "value"  # type: ignore[attr-defined]


class TestMultiaddr:
    """Tests for Multiaddr."""

    def test_is_a_string(self) -> None:
        """Multiaddr is a plain string carrying the multiaddress."""
        multiaddr = Multiaddr("/ip4/192.168.1.1/udp/9000/quic-v1")
        assert isinstance(multiaddr, str)
        assert multiaddr == "/ip4/192.168.1.1/udp/9000/quic-v1"

    def test_carries_no_instance_dictionary(self) -> None:
        """The slotted definition forbids attaching arbitrary attributes."""
        with pytest.raises(AttributeError):
            Multiaddr("/ip4/1.2.3.4").extra_field = "value"  # type: ignore[attr-defined]
