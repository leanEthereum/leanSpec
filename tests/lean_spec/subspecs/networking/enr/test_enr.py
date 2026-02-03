"""Tests for the Ethereum Node Record (ENR) module (EIP-778).

This module tests ENR parsing, validation, and property accessors using the
official EIP-778 test vector and additional edge cases.

References:
- EIP-778: https://eips.ethereum.org/EIPS/eip-778
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking.enr import ENR, keys
from lean_spec.subspecs.networking.enr.enr import ENR_PREFIX
from lean_spec.types import Bytes64, Uint64

# =============================================================================
# Official EIP-778 Test Vector
# =============================================================================
# From: https://eips.ethereum.org/EIPS/eip-778
#
# Node ID: a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7
# Sequence: 1
# IPv4: 127.0.0.1
# UDP port: 30303
# Identity scheme: "v4"
# Compressed secp256k1 public key:
#     03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138
OFFICIAL_ENR_STRING = (
    "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjz"
    "CBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQ"
    "PKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"
)

OFFICIAL_NODE_ID = "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
OFFICIAL_SEQ = 1
OFFICIAL_IPV4 = "127.0.0.1"
OFFICIAL_UDP_PORT = 30303
OFFICIAL_IDENTITY_SCHEME = "v4"
OFFICIAL_SECP256K1_PUBKEY = bytes.fromhex(
    "03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138"
)
OFFICIAL_SIGNATURE = bytes.fromhex(
    "7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b"
    "76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c"
)


class TestOfficialEIP778Vector:
    """Tests using the official EIP-778 test vector."""

    def test_parse_official_enr_string(self) -> None:
        """Official ENR string parses successfully."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr is not None

    def test_official_enr_sequence_number(self) -> None:
        """Official ENR has sequence number 1."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.seq == Uint64(OFFICIAL_SEQ)

    def test_official_enr_identity_scheme(self) -> None:
        """Official ENR uses "v4" identity scheme."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.identity_scheme == OFFICIAL_IDENTITY_SCHEME

    def test_official_enr_ipv4_address(self) -> None:
        """Official ENR has IPv4 address 127.0.0.1."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.ip4 == OFFICIAL_IPV4

    def test_official_enr_udp_port(self) -> None:
        """Official ENR has UDP port 30303."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.udp_port == OFFICIAL_UDP_PORT

    def test_official_enr_public_key(self) -> None:
        """Official ENR has 33-byte compressed secp256k1 public key."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.public_key is not None
        assert len(enr.public_key) == 33
        assert enr.public_key == OFFICIAL_SECP256K1_PUBKEY

    def test_official_enr_signature_length(self) -> None:
        """Official ENR has 64-byte signature."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert len(enr.signature) == 64

    def test_official_enr_signature_value(self) -> None:
        """Official ENR signature matches expected value."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.signature == OFFICIAL_SIGNATURE

    def test_official_enr_is_valid(self) -> None:
        """Official ENR passes structural validation."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.is_valid()

    def test_official_enr_no_tcp_port(self) -> None:
        """Official ENR does not have TCP port."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.tcp_port is None

    def test_official_enr_no_ipv6(self) -> None:
        """Official ENR does not have IPv6 address."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.ip6 is None

    def test_official_enr_no_multiaddr(self) -> None:
        """Official ENR has no multiaddr (no TCP port)."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.multiaddr() is None

    def test_official_enr_node_id(self) -> None:
        """Official ENR node ID matches keccak256(uncompressed_pubkey).

        Per EIP-778 "v4" identity scheme:
            "To derive a node address, take the keccak256 hash of the
             uncompressed public key."

        The hash is computed over the 64-byte x||y coordinates,
        excluding the 0x04 uncompressed point prefix.
        """
        from Crypto.Hash import keccak
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        enr = ENR.from_string(OFFICIAL_ENR_STRING)

        # Get the compressed 33-byte secp256k1 public key
        compressed_pubkey = enr.public_key
        assert compressed_pubkey is not None
        assert compressed_pubkey == OFFICIAL_SECP256K1_PUBKEY

        # Uncompress to 65 bytes (0x04 || x || y)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), compressed_pubkey)
        uncompressed = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        assert len(uncompressed) == 65
        assert uncompressed[0] == 0x04  # Uncompressed point prefix

        # Compute keccak256 of 64-byte x||y (excluding 0x04 prefix)
        k = keccak.new(digest_bits=256)
        k.update(uncompressed[1:])
        computed_node_id = k.hexdigest()

        assert computed_node_id == OFFICIAL_NODE_ID


class TestTextFormatValidation:
    """Tests for ENR text format parsing and validation."""

    def test_prefix_required(self) -> None:
        """ENR must start with 'enr:' prefix."""
        # Remove prefix from valid ENR
        invalid = OFFICIAL_ENR_STRING[len(ENR_PREFIX) :]
        with pytest.raises(ValueError, match=r"must start with 'enr:'"):
            ENR.from_string(invalid)

    def test_wrong_prefix_rejected(self) -> None:
        """ENR with wrong prefix is rejected."""
        invalid = "eth:" + OFFICIAL_ENR_STRING[len(ENR_PREFIX) :]
        with pytest.raises(ValueError, match=r"must start with 'enr:'"):
            ENR.from_string(invalid)

    def test_empty_string_rejected(self) -> None:
        """Empty string is rejected."""
        with pytest.raises(ValueError, match=r"must start with 'enr:'"):
            ENR.from_string("")

    def test_prefix_only_rejected(self) -> None:
        """Prefix only without data is rejected."""
        with pytest.raises(ValueError):
            ENR.from_string("enr:")

    def test_invalid_base64_rejected(self) -> None:
        """Invalid base64 encoding is rejected."""
        invalid = "enr:!!!invalid-base64!!!"
        with pytest.raises(ValueError, match=r"Invalid base64"):
            ENR.from_string(invalid)

    def test_base64url_without_padding(self) -> None:
        """Base64url without padding is handled correctly."""
        # The official ENR string has no padding and should parse fine
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr is not None

    def test_case_sensitive_prefix(self) -> None:
        """Prefix is case-sensitive (ENR: is invalid)."""
        invalid = "ENR:" + OFFICIAL_ENR_STRING[len(ENR_PREFIX) :]
        with pytest.raises(ValueError, match=r"must start with 'enr:'"):
            ENR.from_string(invalid)


class TestRLPStructureValidation:
    """Tests for RLP structure validation during parsing."""

    def test_minimum_fields_required(self) -> None:
        """ENR must have at least signature and seq."""
        # Create RLP for just signature (missing seq)
        import base64

        from lean_spec.types.rlp import encode_rlp

        # RLP list with only signature
        rlp_data = encode_rlp([b"\x00" * 64])
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        with pytest.raises(ValueError, match=r"at least signature and seq"):
            ENR.from_string(f"enr:{b64_content}")

    def test_odd_number_of_kv_pairs_rejected(self) -> None:
        """ENR key/value pairs must be even count."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        # [signature, seq, key1] - odd number after signature/seq
        rlp_data = encode_rlp([b"\x00" * 64, b"\x01", b"id"])
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        with pytest.raises(ValueError, match=r"key/value pairs must be even"):
            ENR.from_string(f"enr:{b64_content}")

    def test_empty_rlp_rejected(self) -> None:
        """Empty RLP data is rejected."""
        import base64

        b64_content = base64.urlsafe_b64encode(b"").decode("utf-8").rstrip("=")

        with pytest.raises(ValueError, match=r"Invalid RLP"):
            ENR.from_string(f"enr:{b64_content}")

    def test_malformed_rlp_rejected(self) -> None:
        """Malformed RLP is rejected."""
        import base64

        # Invalid RLP: truncated list
        malformed = bytes([0xC5, 0x01, 0x02])  # Claims 5 bytes but only has 2
        b64_content = base64.urlsafe_b64encode(malformed).decode("utf-8").rstrip("=")

        with pytest.raises(ValueError, match=r"Invalid RLP"):
            ENR.from_string(f"enr:{b64_content}")

    def test_valid_minimal_enr(self) -> None:
        """Minimal valid ENR with only required fields parses."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        # [signature(64), seq(1), "id", "v4", "secp256k1", pubkey(33)]
        rlp_data = encode_rlp(
            [
                b"\x00" * 64,  # signature
                b"\x01",  # seq = 1
                b"id",
                b"v4",
                b"secp256k1",
                b"\x02" + b"\x00" * 32,  # compressed pubkey
            ]
        )
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        enr = ENR.from_string(f"enr:{b64_content}")
        assert enr.seq == Uint64(1)
        assert enr.identity_scheme == "v4"


class TestPropertyAccessors:
    """Tests for ENR property accessors."""

    def test_identity_scheme_returns_v4(self) -> None:
        """identity_scheme property returns 'v4' for valid ENR."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert enr.identity_scheme == "v4"

    def test_identity_scheme_returns_none_when_missing(self) -> None:
        """identity_scheme returns None when 'id' key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert enr.identity_scheme is None

    def test_public_key_returns_33_bytes(self) -> None:
        """public_key returns 33-byte compressed secp256k1 key."""
        expected_key = b"\x03" + b"\xab" * 32
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: expected_key},
        )
        public_key = enr.public_key
        assert public_key is not None
        assert public_key == expected_key
        assert len(public_key) == 33

    def test_public_key_returns_none_when_missing(self) -> None:
        """public_key returns None when secp256k1 key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.public_key is None

    def test_ip4_formats_address_correctly(self) -> None:
        """ip4 property formats IPv4 address as dotted string."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.SECP256K1: b"\x02" + b"\x00" * 32,
                keys.IP: b"\x7f\x00\x00\x01",  # 127.0.0.1
            },
        )
        assert enr.ip4 == "127.0.0.1"

    def test_ip4_various_addresses(self) -> None:
        """ip4 formats various IPv4 addresses correctly."""
        test_cases = [
            (b"\x00\x00\x00\x00", "0.0.0.0"),
            (b"\xff\xff\xff\xff", "255.255.255.255"),
            (b"\xc0\xa8\x01\x01", "192.168.1.1"),
            (b"\x0a\x00\x00\x01", "10.0.0.1"),
        ]
        for ip_bytes, expected in test_cases:
            enr = ENR(
                signature=Bytes64(b"\x00" * 64),
                seq=Uint64(1),
                pairs={keys.ID: b"v4", keys.IP: ip_bytes},
            )
            assert enr.ip4 == expected

    def test_ip4_returns_none_when_missing(self) -> None:
        """ip4 returns None when 'ip' key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.ip4 is None

    def test_ip4_returns_none_for_wrong_length(self) -> None:
        """ip4 returns None when IP bytes are not 4 bytes."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP: b"\x7f\x00\x00"},  # Only 3 bytes
        )
        assert enr.ip4 is None

    def test_ip6_formats_address_correctly(self) -> None:
        """ip6 property formats IPv6 address as colon-separated hex."""
        # ::1 (loopback)
        ipv6_bytes = b"\x00" * 15 + b"\x01"
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP6: ipv6_bytes},
        )
        assert enr.ip6 == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_ip6_returns_none_when_missing(self) -> None:
        """ip6 returns None when 'ip6' key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.ip6 is None

    def test_ip6_returns_none_for_wrong_length(self) -> None:
        """ip6 returns None when IP bytes are not 16 bytes."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP6: b"\x00" * 8},  # Only 8 bytes
        )
        assert enr.ip6 is None

    def test_udp_port_extracts_correctly(self) -> None:
        """udp_port extracts port number from big-endian bytes."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.UDP: (30303).to_bytes(2, "big")},
        )
        assert enr.udp_port == 30303

    def test_udp_port_various_values(self) -> None:
        """udp_port handles various port values."""
        test_cases = [
            (b"\x00\x01", 1),
            (b"\xff\xff", 65535),
            (b"\x23\x28", 9000),
            (b"\x76\x5f", 30303),
        ]
        for port_bytes, expected in test_cases:
            enr = ENR(
                signature=Bytes64(b"\x00" * 64),
                seq=Uint64(1),
                pairs={keys.ID: b"v4", keys.UDP: port_bytes},
            )
            assert enr.udp_port == expected

    def test_udp_port_returns_none_when_missing(self) -> None:
        """udp_port returns None when 'udp' key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.udp_port is None

    def test_tcp_port_extracts_correctly(self) -> None:
        """tcp_port extracts port number from big-endian bytes."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.TCP: (9000).to_bytes(2, "big")},
        )
        assert enr.tcp_port == 9000

    def test_tcp_port_returns_none_when_missing(self) -> None:
        """tcp_port returns None when 'tcp' key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.tcp_port is None


class TestValidationMethods:
    """Tests for ENR validation methods."""

    def test_is_valid_returns_true_for_complete_v4_enr(self) -> None:
        """is_valid() returns True for complete v4 ENR."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert enr.is_valid()

    def test_is_valid_returns_false_for_missing_public_key(self) -> None:
        """is_valid() returns False when secp256k1 key is missing."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert not enr.is_valid()

    def test_is_valid_returns_false_for_wrong_identity_scheme(self) -> None:
        """is_valid() returns False for non-v4 identity scheme."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v5", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert not enr.is_valid()

    def test_is_valid_returns_false_for_missing_identity_scheme(self) -> None:
        """is_valid() returns False when 'id' key is missing."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert not enr.is_valid()

    def test_is_valid_returns_false_for_wrong_pubkey_length(self) -> None:
        """is_valid() returns False for public key != 33 bytes."""
        # 32 bytes (uncompressed prefix missing)
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x00" * 32},
        )
        assert not enr.is_valid()

        # 65 bytes (uncompressed format)
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x04" + b"\x00" * 64},
        )
        assert not enr.is_valid()

    def test_construction_fails_for_wrong_signature_length(self) -> None:
        """ENR construction fails when signature is not exactly 64 bytes."""
        import pytest

        from lean_spec.types import SSZValueError

        # 63 bytes should fail - Bytes64 enforces exactly 64 bytes
        with pytest.raises(SSZValueError, match="requires exactly 64 bytes"):
            ENR(
                signature=Bytes64(b"\x00" * 63),
                seq=Uint64(1),
                pairs={keys.ID: b"v4", keys.SECP256K1: b"\x02" + b"\x00" * 32},
            )


class TestMultiaddrGeneration:
    """Tests for multiaddr() method."""

    def test_multiaddr_with_ipv4_and_tcp(self) -> None:
        """multiaddr() generates correct format with IPv4 and TCP."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.IP: b"\xc0\xa8\x01\x01",  # 192.168.1.1
                keys.TCP: (9000).to_bytes(2, "big"),
            },
        )
        assert enr.multiaddr() == "/ip4/192.168.1.1/tcp/9000"

    def test_multiaddr_with_ipv6_and_tcp(self) -> None:
        """multiaddr() generates correct format with IPv6 and TCP."""
        ipv6_bytes = b"\x00" * 15 + b"\x01"  # ::1
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.IP6: ipv6_bytes,
                keys.TCP: (9000).to_bytes(2, "big"),
            },
        )
        assert enr.multiaddr() == "/ip6/0000:0000:0000:0000:0000:0000:0000:0001/tcp/9000"

    def test_multiaddr_returns_none_without_tcp(self) -> None:
        """multiaddr() returns None when TCP port is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.IP: b"\xc0\xa8\x01\x01",
                keys.UDP: (30303).to_bytes(2, "big"),  # UDP, not TCP
            },
        )
        assert enr.multiaddr() is None

    def test_multiaddr_returns_none_without_ip(self) -> None:
        """multiaddr() returns None when no IP address is present."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.TCP: (9000).to_bytes(2, "big")},
        )
        assert enr.multiaddr() is None

    def test_multiaddr_prefers_ipv4_over_ipv6(self) -> None:
        """multiaddr() uses IPv4 when both IPv4 and IPv6 are present."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.IP: b"\xc0\xa8\x01\x01",  # 192.168.1.1
                keys.IP6: b"\x00" * 15 + b"\x01",  # ::1
                keys.TCP: (9000).to_bytes(2, "big"),
            },
        )
        assert enr.multiaddr() == "/ip4/192.168.1.1/tcp/9000"


class TestStringRepresentation:
    """Tests for ENR string representation."""

    def test_str_includes_seq(self) -> None:
        """__str__() includes sequence number."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(42),
            pairs={keys.ID: b"v4"},
        )
        result = str(enr)
        assert "seq=42" in result

    def test_str_includes_ip(self) -> None:
        """__str__() includes IP address when present."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP: b"\xc0\xa8\x01\x01"},
        )
        result = str(enr)
        assert "192.168.1.1" in result

    def test_str_includes_tcp_port(self) -> None:
        """__str__() includes TCP port when present."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.TCP: (9000).to_bytes(2, "big")},
        )
        result = str(enr)
        assert "tcp=9000" in result

    def test_str_includes_udp_port(self) -> None:
        """__str__() includes UDP port when present."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.UDP: (30303).to_bytes(2, "big")},
        )
        result = str(enr)
        assert "udp=30303" in result

    def test_str_minimal_enr(self) -> None:
        """__str__() works for minimal ENR."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={},
        )
        result = str(enr)
        assert result.startswith("ENR(")
        assert result.endswith(")")
        assert "seq=1" in result


class TestKeyAccessMethods:
    """Tests for get() and has() methods."""

    def test_get_existing_key(self) -> None:
        """get() returns value for existing key."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.get(keys.ID) == b"v4"

    def test_get_missing_key(self) -> None:
        """get() returns None for missing key."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.get(keys.IP) is None

    def test_has_existing_key(self) -> None:
        """has() returns True for existing key."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP: b"\x7f\x00\x00\x01"},
        )
        assert enr.has(keys.ID)
        assert enr.has(keys.IP)

    def test_has_missing_key(self) -> None:
        """has() returns False for missing key."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert not enr.has(keys.IP)
        assert not enr.has(keys.TCP)
        assert not enr.has(keys.ETH2)


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_enr_with_only_required_fields(self) -> None:
        """ENR with minimum required fields is valid."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        rlp_data = encode_rlp(
            [
                b"\x00" * 64,  # signature
                b"\x01",  # seq
                b"id",
                b"v4",
                b"secp256k1",
                b"\x02" + b"\x00" * 32,
            ]
        )
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        enr = ENR.from_string(f"enr:{b64_content}")
        assert enr.is_valid()
        assert enr.ip4 is None
        assert enr.tcp_port is None
        assert enr.udp_port is None

    def test_enr_with_ipv6_only(self) -> None:
        """ENR with IPv6 but no IPv4 parses correctly."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        ipv6_bytes = bytes.fromhex("20010db8000000000000000000000001")  # 2001:db8::1
        rlp_data = encode_rlp(
            [
                b"\x00" * 64,
                b"\x01",
                b"id",
                b"v4",
                b"ip6",
                ipv6_bytes,
                b"secp256k1",
                b"\x02" + b"\x00" * 32,
                b"tcp",
                (9000).to_bytes(2, "big"),
            ]
        )
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        enr = ENR.from_string(f"enr:{b64_content}")
        assert enr.ip4 is None
        assert enr.ip6 is not None
        assert enr.tcp_port == 9000
        # multiaddr should use IPv6
        multiaddr = enr.multiaddr()
        assert multiaddr is not None
        assert "/ip6/" in multiaddr

    def test_enr_with_both_tcp_and_udp(self) -> None:
        """ENR with both TCP and UDP ports parses correctly."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        rlp_data = encode_rlp(
            [
                b"\x00" * 64,
                b"\x01",
                b"id",
                b"v4",
                b"ip",
                b"\xc0\xa8\x01\x01",
                b"secp256k1",
                b"\x02" + b"\x00" * 32,
                b"tcp",
                (9000).to_bytes(2, "big"),
                b"udp",
                (30303).to_bytes(2, "big"),
            ]
        )
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        enr = ENR.from_string(f"enr:{b64_content}")
        assert enr.tcp_port == 9000
        assert enr.udp_port == 30303
        assert enr.multiaddr() == "/ip4/192.168.1.1/tcp/9000"

    def test_sequence_number_zero(self) -> None:
        """ENR with sequence number 0 is valid."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        rlp_data = encode_rlp(
            [
                b"\x00" * 64,
                b"",  # Empty bytes = 0
                b"id",
                b"v4",
                b"secp256k1",
                b"\x02" + b"\x00" * 32,
            ]
        )
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        enr = ENR.from_string(f"enr:{b64_content}")
        assert enr.seq == Uint64(0)

    def test_large_sequence_number(self) -> None:
        """ENR with large sequence number parses correctly."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        large_seq = (2**32).to_bytes(5, "big")
        rlp_data = encode_rlp(
            [
                b"\x00" * 64,
                large_seq,
                b"id",
                b"v4",
                b"secp256k1",
                b"\x02" + b"\x00" * 32,
            ]
        )
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        enr = ENR.from_string(f"enr:{b64_content}")
        assert enr.seq == Uint64(2**32)


class TestENRConstants:
    """Tests for ENR constants."""

    def test_max_size_constant(self) -> None:
        """MAX_SIZE is 300 bytes per EIP-778."""
        assert ENR.MAX_SIZE == 300

    def test_scheme_constant(self) -> None:
        """SCHEME is 'v4' for current identity scheme."""
        assert ENR.SCHEME == "v4"

    def test_prefix_constant(self) -> None:
        """ENR_PREFIX is 'enr:' for text encoding."""
        assert ENR_PREFIX == "enr:"


class TestEth2DataProperty:
    """Tests for eth2_data property parsing."""

    def test_eth2_data_parses_from_enr(self) -> None:
        """eth2_data property parses 16-byte eth2 key."""
        from lean_spec.types.byte_arrays import Bytes4

        # 4 bytes fork_digest + 4 bytes next_fork_version + 8 bytes next_fork_epoch
        eth2_bytes = b"\x12\x34\x56\x78" + b"\x02\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00\x00\x01"
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.ETH2: eth2_bytes},
        )

        eth2 = enr.eth2_data
        assert eth2 is not None
        assert eth2.fork_digest == Bytes4(b"\x12\x34\x56\x78")
        assert eth2.next_fork_version == Bytes4(b"\x02\x00\x00\x00")
        # Epoch is little-endian
        assert eth2.next_fork_epoch == Uint64(1 << 56)

    def test_eth2_data_returns_none_when_missing(self) -> None:
        """eth2_data returns None when eth2 key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.eth2_data is None

    def test_eth2_data_returns_none_for_short_data(self) -> None:
        """eth2_data returns None when eth2 key is too short."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.ETH2: b"\x12\x34\x56\x78"},  # Only 4 bytes
        )
        assert enr.eth2_data is None


class TestAttestationSubnetsProperty:
    """Tests for attestation_subnets property parsing."""

    def test_attestation_subnets_parses_from_enr(self) -> None:
        """attestation_subnets property parses 8-byte attnets key."""
        # All bits set (64 bits = 8 bytes of 0xFF)
        attnets_bytes = b"\xff" * 8
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.ATTNETS: attnets_bytes},
        )

        attnets = enr.attestation_subnets
        assert attnets is not None
        assert attnets.subscription_count() == 64

    def test_attestation_subnets_returns_none_when_missing(self) -> None:
        """attestation_subnets returns None when attnets key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.attestation_subnets is None

    def test_attestation_subnets_returns_none_for_wrong_length(self) -> None:
        """attestation_subnets returns None when attnets key is not 8 bytes."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.ATTNETS: b"\xff\xff\xff\xff"},  # Only 4 bytes
        )
        assert enr.attestation_subnets is None


class TestSyncCommitteeSubnetsProperty:
    """Tests for sync_committee_subnets property parsing."""

    def test_sync_committee_subnets_parses_from_enr(self) -> None:
        """sync_committee_subnets property parses 1-byte syncnets key."""
        # All 4 bits set (lower nibble of 0x0F)
        syncnets_bytes = b"\x0f"
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SYNCNETS: syncnets_bytes},
        )

        syncnets = enr.sync_committee_subnets
        assert syncnets is not None
        for i in range(4):
            assert syncnets.is_subscribed(i)

    def test_sync_committee_subnets_returns_none_when_missing(self) -> None:
        """sync_committee_subnets returns None when syncnets key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.sync_committee_subnets is None

    def test_sync_committee_subnets_returns_none_for_wrong_length(self) -> None:
        """sync_committee_subnets returns None when syncnets key is not 1 byte."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SYNCNETS: b"\x0f\x00"},  # 2 bytes
        )
        assert enr.sync_committee_subnets is None


class TestForkCompatibility:
    """Tests for is_compatible_with() method."""

    def test_compatible_with_same_fork_digest(self) -> None:
        """ENRs with same fork digest are compatible."""
        eth2_bytes = b"\x12\x34\x56\x78" + b"\x02\x00\x00\x00" + b"\x00" * 8

        enr1 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.ETH2: eth2_bytes},
        )
        enr2 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(2),
            pairs={keys.ID: b"v4", keys.ETH2: eth2_bytes},
        )

        assert enr1.is_compatible_with(enr2)

    def test_incompatible_with_different_fork_digest(self) -> None:
        """ENRs with different fork digests are incompatible."""
        eth2_bytes1 = b"\x12\x34\x56\x78" + b"\x02\x00\x00\x00" + b"\x00" * 8
        eth2_bytes2 = b"\xab\xcd\xef\x01" + b"\x02\x00\x00\x00" + b"\x00" * 8

        enr1 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.ETH2: eth2_bytes1},
        )
        enr2 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(2),
            pairs={keys.ID: b"v4", keys.ETH2: eth2_bytes2},
        )

        assert not enr1.is_compatible_with(enr2)

    def test_incompatible_when_self_missing_eth2(self) -> None:
        """ENR is incompatible when self lacks eth2 key."""
        eth2_bytes = b"\x12\x34\x56\x78" + b"\x02\x00\x00\x00" + b"\x00" * 8

        enr1 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},  # No eth2
        )
        enr2 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(2),
            pairs={keys.ID: b"v4", keys.ETH2: eth2_bytes},
        )

        assert not enr1.is_compatible_with(enr2)

    def test_incompatible_when_other_missing_eth2(self) -> None:
        """ENR is incompatible when other lacks eth2 key."""
        eth2_bytes = b"\x12\x34\x56\x78" + b"\x02\x00\x00\x00" + b"\x00" * 8

        enr1 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.ETH2: eth2_bytes},
        )
        enr2 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(2),
            pairs={keys.ID: b"v4"},  # No eth2
        )

        assert not enr1.is_compatible_with(enr2)

    def test_incompatible_when_both_missing_eth2(self) -> None:
        """ENRs are incompatible when both lack eth2 key."""
        enr1 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        enr2 = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(2),
            pairs={keys.ID: b"v4"},
        )

        assert not enr1.is_compatible_with(enr2)


class TestMaxSizeEnforcement:
    """Tests for MAX_SIZE (300 bytes) enforcement."""

    def test_enr_exactly_300_bytes_succeeds(self) -> None:
        """ENR with exactly 300 bytes RLP parses successfully."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        # Build an ENR that is exactly 300 bytes
        # Start with minimal structure and add padding in a value
        signature = b"\x00" * 64
        seq = b"\x01"
        # Calculate how much padding we need in value
        # RLP overhead: ~4 bytes header + items
        # We need to carefully construct this

        # Start with basic structure and measure
        basic = encode_rlp([signature, seq, b"id", b"v4", b"secp256k1", b"\x02" + b"\x00" * 32])
        padding_needed = 300 - len(basic)

        # Add padding via a custom key with enough value bytes
        # The key "z" + value needs to fit in remaining space
        # Account for RLP overhead (key length byte + value length bytes)
        if padding_needed > 3:
            value_len = padding_needed - 3  # Approximate, may need adjustment
            padded = encode_rlp(
                [
                    signature,
                    seq,
                    b"id",
                    b"v4",
                    b"secp256k1",
                    b"\x02" + b"\x00" * 32,
                    b"zz",
                    b"\x00" * value_len,
                ]
            )
            # Adjust if needed
            while len(padded) < 300:
                value_len += 1
                padded = encode_rlp(
                    [
                        signature,
                        seq,
                        b"id",
                        b"v4",
                        b"secp256k1",
                        b"\x02" + b"\x00" * 32,
                        b"zz",
                        b"\x00" * value_len,
                    ]
                )
            while len(padded) > 300:
                value_len -= 1
                padded = encode_rlp(
                    [
                        signature,
                        seq,
                        b"id",
                        b"v4",
                        b"secp256k1",
                        b"\x02" + b"\x00" * 32,
                        b"zz",
                        b"\x00" * value_len,
                    ]
                )

            assert len(padded) == 300
            b64 = base64.urlsafe_b64encode(padded).decode().rstrip("=")
            enr = ENR.from_string(f"enr:{b64}")
            assert enr is not None

    def test_enr_301_bytes_rejected(self) -> None:
        """ENR with 301 bytes RLP is rejected."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        # Build an ENR that is exactly 301 bytes
        signature = b"\x00" * 64
        seq = b"\x01"

        basic = encode_rlp([signature, seq, b"id", b"v4", b"secp256k1", b"\x02" + b"\x00" * 32])
        padding_needed = 301 - len(basic)

        if padding_needed > 3:
            value_len = padding_needed - 3
            padded = encode_rlp(
                [
                    signature,
                    seq,
                    b"id",
                    b"v4",
                    b"secp256k1",
                    b"\x02" + b"\x00" * 32,
                    b"zz",
                    b"\x00" * value_len,
                ]
            )
            while len(padded) < 301:
                value_len += 1
                padded = encode_rlp(
                    [
                        signature,
                        seq,
                        b"id",
                        b"v4",
                        b"secp256k1",
                        b"\x02" + b"\x00" * 32,
                        b"zz",
                        b"\x00" * value_len,
                    ]
                )
            while len(padded) > 301:
                value_len -= 1
                padded = encode_rlp(
                    [
                        signature,
                        seq,
                        b"id",
                        b"v4",
                        b"secp256k1",
                        b"\x02" + b"\x00" * 32,
                        b"zz",
                        b"\x00" * value_len,
                    ]
                )

            assert len(padded) == 301
            b64 = base64.urlsafe_b64encode(padded).decode().rstrip("=")

            with pytest.raises(ValueError, match="exceeds max size"):
                ENR.from_string(f"enr:{b64}")


class TestKeyOrderingEnforcement:
    """Tests for lexicographic key ordering enforcement."""

    def test_sorted_keys_accepted(self) -> None:
        """ENR with lexicographically sorted keys parses successfully."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        # Keys in sorted order: id, ip, secp256k1
        rlp = encode_rlp(
            [
                b"\x00" * 64,  # signature
                b"\x01",  # seq
                b"id",
                b"v4",
                b"ip",
                b"\x7f\x00\x00\x01",
                b"secp256k1",
                b"\x02" + b"\x00" * 32,
            ]
        )
        b64 = base64.urlsafe_b64encode(rlp).decode().rstrip("=")
        enr = ENR.from_string(f"enr:{b64}")
        assert enr is not None

    def test_unsorted_keys_rejected(self) -> None:
        """ENR with unsorted keys is rejected."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        # Keys out of order: secp256k1 before id
        rlp = encode_rlp(
            [
                b"\x00" * 64,  # signature
                b"\x01",  # seq
                b"secp256k1",  # Should be after "id"
                b"\x02" + b"\x00" * 32,
                b"id",
                b"v4",
            ]
        )
        b64 = base64.urlsafe_b64encode(rlp).decode().rstrip("=")

        with pytest.raises(ValueError, match="lexicographically sorted"):
            ENR.from_string(f"enr:{b64}")

    def test_duplicate_keys_rejected(self) -> None:
        """ENR with duplicate keys is rejected."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        # Duplicate "id" key
        rlp = encode_rlp(
            [
                b"\x00" * 64,  # signature
                b"\x01",  # seq
                b"id",
                b"v4",
                b"id",  # Duplicate!
                b"v5",
            ]
        )
        b64 = base64.urlsafe_b64encode(rlp).decode().rstrip("=")

        with pytest.raises(ValueError, match="lexicographically sorted"):
            ENR.from_string(f"enr:{b64}")


class TestRoundTripSerialization:
    """Tests for ENR round-trip serialization."""

    def test_roundtrip_official_enr(self) -> None:
        """Official ENR round-trips through parse and serialize."""
        enr1 = ENR.from_string(OFFICIAL_ENR_STRING)
        serialized = enr1.to_string()
        enr2 = ENR.from_string(serialized)

        assert enr1.seq == enr2.seq
        assert enr1.signature == enr2.signature
        assert enr1.pairs == enr2.pairs

    def test_roundtrip_preserves_all_fields(self) -> None:
        """Round-trip preserves all ENR fields."""
        import base64

        from lean_spec.types.rlp import encode_rlp

        rlp = encode_rlp(
            [
                b"\xab" * 64,  # signature
                b"\x42",  # seq = 66
                b"eth2",
                b"\x12\x34\x56\x78" + b"\x02\x00\x00\x00" + b"\x00" * 8,
                b"id",
                b"v4",
                b"ip",
                b"\xc0\xa8\x01\x01",
                b"secp256k1",
                b"\x02" + b"\x00" * 32,
                b"tcp",
                (9000).to_bytes(2, "big"),
            ]
        )
        b64 = base64.urlsafe_b64encode(rlp).decode().rstrip("=")

        enr1 = ENR.from_string(f"enr:{b64}")
        enr2 = ENR.from_string(enr1.to_string())

        assert enr1.seq == enr2.seq == Uint64(0x42)
        assert enr1.ip4 == enr2.ip4 == "192.168.1.1"
        assert enr1.tcp_port == enr2.tcp_port == 9000
        assert enr1.identity_scheme == enr2.identity_scheme == "v4"

    def test_to_string_produces_valid_enr_format(self) -> None:
        """to_string() produces valid 'enr:' prefixed string."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        result = enr.to_string()

        assert result.startswith("enr:")
        # Should not have padding
        assert "=" not in result


class TestSignatureVerification:
    """Tests for verify_signature() method."""

    def test_official_enr_signature_verifies(self) -> None:
        """Official EIP-778 test vector signature verifies correctly."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        assert enr.verify_signature()

    def test_self_signed_enr_verifies(self) -> None:
        """ENR signed with cryptography library verifies correctly."""
        from Crypto.Hash import keccak
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
        )

        from lean_spec.types.rlp import encode_rlp

        # Generate a test keypair using cryptography library.
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()
        compressed_pubkey = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        # Create content (keys must be sorted).
        content_items: list[bytes] = [
            b"\x01",
            b"id",
            b"v4",
            b"secp256k1",
            compressed_pubkey,
        ]
        content_rlp = encode_rlp(content_items)

        # Hash content.
        k = keccak.new(digest_bits=256)
        k.update(content_rlp)
        digest = k.digest()

        # Sign with ECDSA using Prehashed mode.
        signature_der = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

        # Convert DER signature to r || s format.
        r, s = decode_dss_signature(signature_der)
        sig_64 = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        # Create ENR.
        enr = ENR(
            signature=Bytes64(sig_64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: compressed_pubkey},
        )

        assert enr.verify_signature()

    def test_tampered_signature_fails_verification(self) -> None:
        """ENR with tampered signature fails verification."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)

        # Tamper with signature
        tampered_sig = bytes([enr.signature[0] ^ 0xFF]) + bytes(enr.signature[1:])
        tampered_enr = ENR(
            signature=Bytes64(tampered_sig),
            seq=enr.seq,
            pairs=enr.pairs,
        )

        assert not tampered_enr.verify_signature()

    def test_tampered_content_fails_verification(self) -> None:
        """ENR with tampered content fails verification."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)

        # Create ENR with different sequence number (content mismatch)
        tampered_enr = ENR(
            signature=enr.signature,
            seq=Uint64(int(enr.seq) + 1),  # Different sequence
            pairs=enr.pairs,
        )

        assert not tampered_enr.verify_signature()

    def test_missing_public_key_fails_verification(self) -> None:
        """ENR without public key fails verification."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},  # No secp256k1 key
        )

        assert not enr.verify_signature()


class TestNodeIdComputation:
    """Tests for compute_node_id() method."""

    def test_official_enr_node_id(self) -> None:
        """compute_node_id() returns correct node ID for official ENR."""
        enr = ENR.from_string(OFFICIAL_ENR_STRING)
        node_id = enr.compute_node_id()

        assert node_id is not None
        assert node_id.hex() == OFFICIAL_NODE_ID

    def test_node_id_none_without_public_key(self) -> None:
        """compute_node_id() returns None when public key is missing."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )

        assert enr.compute_node_id() is None


class TestIPv6Ports:
    """Tests for tcp6_port and udp6_port properties."""

    def test_tcp6_port_extracts_correctly(self) -> None:
        """tcp6_port extracts IPv6-specific TCP port."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.TCP6: (9001).to_bytes(2, "big"),
            },
        )
        assert enr.tcp6_port == 9001

    def test_tcp6_port_returns_none_when_missing(self) -> None:
        """tcp6_port returns None when tcp6 key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.tcp6_port is None

    def test_udp6_port_extracts_correctly(self) -> None:
        """udp6_port extracts IPv6-specific UDP port."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.UDP6: (30304).to_bytes(2, "big"),
            },
        )
        assert enr.udp6_port == 30304

    def test_udp6_port_returns_none_when_missing(self) -> None:
        """udp6_port returns None when udp6 key is absent."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.udp6_port is None

    def test_ipv6_ports_independent_of_ipv4(self) -> None:
        """IPv6 ports are independent from IPv4 ports."""
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={
                keys.ID: b"v4",
                keys.TCP: (9000).to_bytes(2, "big"),
                keys.TCP6: (9001).to_bytes(2, "big"),
                keys.UDP: (30303).to_bytes(2, "big"),
                keys.UDP6: (30304).to_bytes(2, "big"),
            },
        )
        assert enr.tcp_port == 9000
        assert enr.tcp6_port == 9001
        assert enr.udp_port == 30303
        assert enr.udp6_port == 30304
