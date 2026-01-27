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
from lean_spec.types import Uint64

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
    "CBOO"
    "nrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQ"
    "PKY0"
    "yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"
)
# Note: The ENR above has the base64 split across lines for readability,
# we need to join it.
OFFICIAL_ENR_STRING = (
    "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjz"
    "CBOOnrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQ"
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
    "76f2635f4e234738f308138e9eb9137e3e3df5266e3a1f11df72ecf1145ccb9c"
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

        from lean_spec.types.rlp import encode

        # RLP list with only signature
        rlp_data = encode([b"\x00" * 64])
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")

        with pytest.raises(ValueError, match=r"at least signature and seq"):
            ENR.from_string(f"enr:{b64_content}")

    def test_odd_number_of_kv_pairs_rejected(self) -> None:
        """ENR key/value pairs must be even count."""
        import base64

        from lean_spec.types.rlp import encode

        # [signature, seq, key1] - odd number after signature/seq
        rlp_data = encode([b"\x00" * 64, b"\x01", b"id"])
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

        from lean_spec.types.rlp import encode

        # [signature(64), seq(1), "id", "v4", "secp256k1", pubkey(33)]
        rlp_data = encode(
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
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert enr.identity_scheme == "v4"

    def test_identity_scheme_returns_none_when_missing(self) -> None:
        """identity_scheme returns None when 'id' key is absent."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert enr.identity_scheme is None

    def test_public_key_returns_33_bytes(self) -> None:
        """public_key returns 33-byte compressed secp256k1 key."""
        expected_key = b"\x03" + b"\xab" * 32
        enr = ENR(
            signature=b"\x00" * 64,
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
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.public_key is None

    def test_ip4_formats_address_correctly(self) -> None:
        """ip4 property formats IPv4 address as dotted string."""
        enr = ENR(
            signature=b"\x00" * 64,
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
                signature=b"\x00" * 64,
                seq=Uint64(1),
                pairs={keys.ID: b"v4", keys.IP: ip_bytes},
            )
            assert enr.ip4 == expected

    def test_ip4_returns_none_when_missing(self) -> None:
        """ip4 returns None when 'ip' key is absent."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.ip4 is None

    def test_ip4_returns_none_for_wrong_length(self) -> None:
        """ip4 returns None when IP bytes are not 4 bytes."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP: b"\x7f\x00\x00"},  # Only 3 bytes
        )
        assert enr.ip4 is None

    def test_ip6_formats_address_correctly(self) -> None:
        """ip6 property formats IPv6 address as colon-separated hex."""
        # ::1 (loopback)
        ipv6_bytes = b"\x00" * 15 + b"\x01"
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP6: ipv6_bytes},
        )
        assert enr.ip6 == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_ip6_returns_none_when_missing(self) -> None:
        """ip6 returns None when 'ip6' key is absent."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.ip6 is None

    def test_ip6_returns_none_for_wrong_length(self) -> None:
        """ip6 returns None when IP bytes are not 16 bytes."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP6: b"\x00" * 8},  # Only 8 bytes
        )
        assert enr.ip6 is None

    def test_udp_port_extracts_correctly(self) -> None:
        """udp_port extracts port number from big-endian bytes."""
        enr = ENR(
            signature=b"\x00" * 64,
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
                signature=b"\x00" * 64,
                seq=Uint64(1),
                pairs={keys.ID: b"v4", keys.UDP: port_bytes},
            )
            assert enr.udp_port == expected

    def test_udp_port_returns_none_when_missing(self) -> None:
        """udp_port returns None when 'udp' key is absent."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.udp_port is None

    def test_tcp_port_extracts_correctly(self) -> None:
        """tcp_port extracts port number from big-endian bytes."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.TCP: (9000).to_bytes(2, "big")},
        )
        assert enr.tcp_port == 9000

    def test_tcp_port_returns_none_when_missing(self) -> None:
        """tcp_port returns None when 'tcp' key is absent."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.tcp_port is None


class TestValidationMethods:
    """Tests for ENR validation methods."""

    def test_is_valid_returns_true_for_complete_v4_enr(self) -> None:
        """is_valid() returns True for complete v4 ENR."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert enr.is_valid()

    def test_is_valid_returns_false_for_missing_public_key(self) -> None:
        """is_valid() returns False when secp256k1 key is missing."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert not enr.is_valid()

    def test_is_valid_returns_false_for_wrong_identity_scheme(self) -> None:
        """is_valid() returns False for non-v4 identity scheme."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v5", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert not enr.is_valid()

    def test_is_valid_returns_false_for_missing_identity_scheme(self) -> None:
        """is_valid() returns False when 'id' key is missing."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert not enr.is_valid()

    def test_is_valid_returns_false_for_wrong_pubkey_length(self) -> None:
        """is_valid() returns False for public key != 33 bytes."""
        # 32 bytes (uncompressed prefix missing)
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x00" * 32},
        )
        assert not enr.is_valid()

        # 65 bytes (uncompressed format)
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x04" + b"\x00" * 64},
        )
        assert not enr.is_valid()

    def test_is_valid_returns_false_for_wrong_signature_length(self) -> None:
        """is_valid() returns False for signature != 64 bytes."""
        enr = ENR(
            signature=b"\x00" * 63,  # 63 bytes
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.SECP256K1: b"\x02" + b"\x00" * 32},
        )
        assert not enr.is_valid()


class TestMultiaddrGeneration:
    """Tests for multiaddr() method."""

    def test_multiaddr_with_ipv4_and_tcp(self) -> None:
        """multiaddr() generates correct format with IPv4 and TCP."""
        enr = ENR(
            signature=b"\x00" * 64,
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
            signature=b"\x00" * 64,
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
            signature=b"\x00" * 64,
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
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.TCP: (9000).to_bytes(2, "big")},
        )
        assert enr.multiaddr() is None

    def test_multiaddr_prefers_ipv4_over_ipv6(self) -> None:
        """multiaddr() uses IPv4 when both IPv4 and IPv6 are present."""
        enr = ENR(
            signature=b"\x00" * 64,
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
            signature=b"\x00" * 64,
            seq=Uint64(42),
            pairs={keys.ID: b"v4"},
        )
        result = str(enr)
        assert "seq=42" in result

    def test_str_includes_ip(self) -> None:
        """__str__() includes IP address when present."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP: b"\xc0\xa8\x01\x01"},
        )
        result = str(enr)
        assert "192.168.1.1" in result

    def test_str_includes_tcp_port(self) -> None:
        """__str__() includes TCP port when present."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.TCP: (9000).to_bytes(2, "big")},
        )
        result = str(enr)
        assert "tcp=9000" in result

    def test_str_includes_udp_port(self) -> None:
        """__str__() includes UDP port when present."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.UDP: (30303).to_bytes(2, "big")},
        )
        result = str(enr)
        assert "udp=30303" in result

    def test_str_minimal_enr(self) -> None:
        """__str__() works for minimal ENR."""
        enr = ENR(
            signature=b"\x00" * 64,
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
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.get(keys.ID) == b"v4"

    def test_get_missing_key(self) -> None:
        """get() returns None for missing key."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4"},
        )
        assert enr.get(keys.IP) is None

    def test_has_existing_key(self) -> None:
        """has() returns True for existing key."""
        enr = ENR(
            signature=b"\x00" * 64,
            seq=Uint64(1),
            pairs={keys.ID: b"v4", keys.IP: b"\x7f\x00\x00\x01"},
        )
        assert enr.has(keys.ID)
        assert enr.has(keys.IP)

    def test_has_missing_key(self) -> None:
        """has() returns False for missing key."""
        enr = ENR(
            signature=b"\x00" * 64,
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

        from lean_spec.types.rlp import encode

        rlp_data = encode(
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

        from lean_spec.types.rlp import encode

        ipv6_bytes = bytes.fromhex("20010db8000000000000000000000001")  # 2001:db8::1
        rlp_data = encode(
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

        from lean_spec.types.rlp import encode

        rlp_data = encode(
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

        from lean_spec.types.rlp import encode

        rlp_data = encode(
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

        from lean_spec.types.rlp import encode

        large_seq = (2**32).to_bytes(5, "big")
        rlp_data = encode(
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
