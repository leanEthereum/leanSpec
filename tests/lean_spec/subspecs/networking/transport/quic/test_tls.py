"""Tests for libp2p TLS certificate generation and ASN.1 encoding.

Tests verify behavior against the libp2p TLS spec:
    https://github.com/libp2p/specs/blob/master/tls/tls.md

The module under test hand-encodes ASN.1 DER instead of using a library,
so these tests validate both the encoding helpers and the full certificate
generation pipeline, including signature verification of the identity proof.
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lean_spec.subspecs.networking.transport.identity.keypair import IdentityKeypair
from lean_spec.subspecs.networking.transport.quic.tls import (
    KEY_TYPE_SECP256K1,
    LIBP2P_EXTENSION_OID,
    SIGNATURE_PREFIX,
    _create_extension_payload,
    _encode_asn1_length,
    _encode_asn1_octet_string,
    _encode_asn1_sequence,
    _encode_asn1_signed_key,
    generate_libp2p_certificate,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def identity_key() -> IdentityKeypair:
    """A fresh secp256k1 identity keypair for testing."""
    return IdentityKeypair.generate()


# ---------------------------------------------------------------------------
# Constants — sanity checks for protocol-defined values
# ---------------------------------------------------------------------------


class TestConstants:
    """Verify protocol-defined constants match the libp2p TLS spec."""

    def test_libp2p_extension_oid(self) -> None:
        """OID 1.3.6.1.4.1.53594.1.1 is the Protocol Labs assigned OID."""
        assert LIBP2P_EXTENSION_OID == x509.ObjectIdentifier("1.3.6.1.4.1.53594.1.1")

    def test_signature_prefix(self) -> None:
        """Prefix prevents cross-context signature replay."""
        assert SIGNATURE_PREFIX == b"libp2p-tls-handshake:"

    def test_key_type_secp256k1(self) -> None:
        """Key type 2 matches the libp2p protobuf KeyType enum for secp256k1."""
        assert KEY_TYPE_SECP256K1 == 2


# ---------------------------------------------------------------------------
# ASN.1 length encoding — must cover all 3 branches
#
# DER length encoding:
#   - Short form:    length < 128 → single byte
#   - Long 1-byte:   128 ≤ length < 256 → 0x81 + 1 byte
#   - Long 2-byte:   length ≥ 256 → 0x82 + 2 bytes (big-endian)
# ---------------------------------------------------------------------------


class TestEncodeAsn1Length:
    """Tests for DER length encoding covering all three code paths."""

    @pytest.mark.parametrize(
        ("length", "expected"),
        [
            (0, bytes([0])),
            (1, bytes([1])),
            (127, bytes([127])),
        ],
        ids=["zero", "one", "max-short-form"],
    )
    def test_short_form(self, length: int, expected: bytes) -> None:
        """Lengths below 128 use a single byte (short form)."""
        assert _encode_asn1_length(length) == expected

    @pytest.mark.parametrize(
        ("length", "expected"),
        [
            (128, bytes([0x81, 128])),
            (200, bytes([0x81, 200])),
            (255, bytes([0x81, 255])),
        ],
        ids=["min-long-1", "mid-long-1", "max-long-1"],
    )
    def test_one_byte_long_form(self, length: int, expected: bytes) -> None:
        """Lengths 128..255 use 0x81 prefix + 1 length byte."""
        assert _encode_asn1_length(length) == expected

    @pytest.mark.parametrize(
        ("length", "expected"),
        [
            (256, bytes([0x82, 0x01, 0x00])),
            (1000, bytes([0x82, 0x03, 0xE8])),
            (65535, bytes([0x82, 0xFF, 0xFF])),
        ],
        ids=["min-long-2", "mid-long-2", "max-u16"],
    )
    def test_two_byte_long_form(self, length: int, expected: bytes) -> None:
        """Lengths >= 256 use 0x82 prefix + 2 big-endian length bytes."""
        assert _encode_asn1_length(length) == expected


# ---------------------------------------------------------------------------
# ASN.1 OCTET STRING encoding
# ---------------------------------------------------------------------------


class TestEncodeAsn1OctetString:
    """Tests for ASN.1 OCTET STRING (tag 0x04) encoding."""

    def test_encodes_data_with_tag_and_length(self) -> None:
        """OCTET STRING has tag 0x04, correct length, and verbatim data."""
        result = _encode_asn1_octet_string(b"\xaa\xbb\xcc")
        assert result == bytes([0x04, 3, 0xAA, 0xBB, 0xCC])

    def test_empty_data(self) -> None:
        """Empty OCTET STRING is valid: tag 0x04, length 0, no content."""
        result = _encode_asn1_octet_string(b"")
        assert result == bytes([0x04, 0])

    def test_long_form_length(self) -> None:
        """Data >= 128 bytes triggers long-form length encoding."""
        data = bytes(range(256)) * 2  # 512 bytes
        result = _encode_asn1_octet_string(data)
        assert result[0] == 0x04
        assert result[1:4] == bytes([0x82, 0x02, 0x00])
        assert result[4:] == data


# ---------------------------------------------------------------------------
# ASN.1 SEQUENCE encoding
# ---------------------------------------------------------------------------


class TestEncodeAsn1Sequence:
    """Tests for ASN.1 SEQUENCE (tag 0x30) encoding."""

    def test_wraps_content_with_tag_and_length(self) -> None:
        """SEQUENCE has tag 0x30, correct length, and verbatim content."""
        content = bytes([0x04, 2, 0xAA, 0xBB])
        result = _encode_asn1_sequence(content)
        assert result == bytes([0x30, 4, 0x04, 2, 0xAA, 0xBB])

    def test_empty_sequence(self) -> None:
        """Empty SEQUENCE is valid: tag 0x30, length 0."""
        result = _encode_asn1_sequence(b"")
        assert result == bytes([0x30, 0])


# ---------------------------------------------------------------------------
# ASN.1 SignedKey — SEQUENCE { OCTET STRING, OCTET STRING }
# ---------------------------------------------------------------------------


class TestEncodeAsn1SignedKey:
    """Tests for the SignedKey ASN.1 structure used in the libp2p extension."""

    def test_structure_is_sequence_of_two_octet_strings(self) -> None:
        """Output is a SEQUENCE containing two OCTET STRINGs."""
        proto = b"\x08\x02\x12\x21" + bytes(33)
        sig = bytes(64)
        result = _encode_asn1_signed_key(proto, sig)

        assert result[0] == 0x30  # SEQUENCE tag

        # Parse inner content
        _, inner = _parse_der_tlv(result)
        # First OCTET STRING
        tag1, val1, rest = _parse_der_tlv_with_rest(inner)
        assert tag1 == 0x04
        assert val1 == proto
        # Second OCTET STRING
        tag2, val2, rest2 = _parse_der_tlv_with_rest(rest)
        assert tag2 == 0x04
        assert val2 == sig
        assert rest2 == b""


# ---------------------------------------------------------------------------
# Extension payload — protobuf + ASN.1 wrapping
# ---------------------------------------------------------------------------


class TestCreateExtensionPayload:
    """Tests for the libp2p extension payload construction."""

    def test_payload_is_valid_asn1_sequence(self, identity_key: IdentityKeypair) -> None:
        """The payload parses as an ASN.1 SEQUENCE of two OCTET STRINGs."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        payload = _create_extension_payload(identity_key, tls_public_bytes)

        assert payload[0] == 0x30
        _, inner = _parse_der_tlv(payload)
        tag1, val1, rest = _parse_der_tlv_with_rest(inner)
        tag2, val2, _ = _parse_der_tlv_with_rest(rest)
        assert tag1 == 0x04
        assert tag2 == 0x04

    def test_protobuf_encoding(self, identity_key: IdentityKeypair) -> None:
        """First OCTET STRING contains a protobuf-encoded PublicKey message."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        payload = _create_extension_payload(identity_key, tls_public_bytes)

        _, inner = _parse_der_tlv(payload)
        _, public_key_proto, _ = _parse_der_tlv_with_rest(inner)

        # Protobuf field 1 (Type): varint tag=0x08, value=2 (secp256k1)
        assert public_key_proto[0] == 0x08
        assert public_key_proto[1] == KEY_TYPE_SECP256K1
        # Protobuf field 2 (Data): length-delimited tag=0x12
        assert public_key_proto[2] == 0x12
        key_len = public_key_proto[3]
        assert key_len == 33  # compressed secp256k1
        key_data = public_key_proto[4 : 4 + key_len]
        assert key_data == identity_key.public_key.to_bytes()

    def test_signature_verifies(self, identity_key: IdentityKeypair) -> None:
        """The signature in the second OCTET STRING verifies against the identity key."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        payload = _create_extension_payload(identity_key, tls_public_bytes)

        _, inner = _parse_der_tlv(payload)
        _, _, rest = _parse_der_tlv_with_rest(inner)
        _, signature, _ = _parse_der_tlv_with_rest(rest)

        expected_message = SIGNATURE_PREFIX + tls_public_bytes
        assert identity_key.public_key.verify(expected_message, signature)


# ---------------------------------------------------------------------------
# Full certificate generation
# ---------------------------------------------------------------------------


class TestGenerateLibp2pCertificate:
    """Tests for the complete certificate generation pipeline."""

    def test_returns_parseable_pem(self, identity_key: IdentityKeypair) -> None:
        """Both PEM outputs are parseable by the cryptography library."""
        private_pem, cert_pem, cert = generate_libp2p_certificate(identity_key)

        loaded_key = serialization.load_pem_private_key(private_pem, password=None)
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)

        loaded_cert = x509.load_pem_x509_certificate(cert_pem)
        assert loaded_cert.serial_number == cert.serial_number

    def test_tls_key_is_p256(self, identity_key: IdentityKeypair) -> None:
        """The ephemeral TLS key uses P-256 (SECP256R1), not secp256k1."""
        private_pem, _, _ = generate_libp2p_certificate(identity_key)
        loaded_key = serialization.load_pem_private_key(private_pem, password=None)
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded_key.curve, ec.SECP256R1)

    def test_empty_subject_and_issuer(self, identity_key: IdentityKeypair) -> None:
        """Subject and issuer are empty to match rust-libp2p's format."""
        _, _, cert = generate_libp2p_certificate(identity_key)
        assert cert.subject == x509.Name([])
        assert cert.issuer == x509.Name([])

    def test_certificate_signed_with_sha256(self, identity_key: IdentityKeypair) -> None:
        """Certificate uses SHA-256 for the outer TLS signature."""
        _, _, cert = generate_libp2p_certificate(identity_key)
        assert cert.signature_hash_algorithm is not None
        assert cert.signature_hash_algorithm.name == "sha256"

    def test_validity_window(self, identity_key: IdentityKeypair) -> None:
        """not_valid_before is ~1 day before now, not_valid_after is ~365 days after now."""
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        _, _, cert = generate_libp2p_certificate(identity_key)

        not_before_delta = now - cert.not_valid_before_utc
        not_after_delta = cert.not_valid_after_utc - now

        tolerance = timedelta(minutes=5)
        assert abs(not_before_delta - timedelta(days=1)) < tolerance
        assert abs(not_after_delta - timedelta(days=365)) < tolerance

    def test_subject_key_identifier(self, identity_key: IdentityKeypair) -> None:
        """SKI extension is sha256(tls_public_key_der)[:20]."""
        _, _, cert = generate_libp2p_certificate(identity_key)

        ski_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski_ext.critical is False

        tls_public_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_ski = hashlib.sha256(tls_public_bytes).digest()[:20]
        assert ski_ext.value.digest == expected_ski

    def test_libp2p_extension_present_and_non_critical(self, identity_key: IdentityKeypair) -> None:
        """The libp2p extension is present with the correct OID and is non-critical."""
        _, _, cert = generate_libp2p_certificate(identity_key)

        ext = cert.extensions.get_extension_for_oid(LIBP2P_EXTENSION_OID)
        assert ext.critical is False
        assert isinstance(ext.value, x509.UnrecognizedExtension)

    def test_libp2p_extension_signature_verifies(self, identity_key: IdentityKeypair) -> None:
        """The identity proof signature in the extension verifies end-to-end."""
        _, _, cert = generate_libp2p_certificate(identity_key)

        ext = cert.extensions.get_extension_for_oid(LIBP2P_EXTENSION_OID)
        assert isinstance(ext.value, x509.UnrecognizedExtension)
        payload = ext.value.value

        # Parse ASN.1 SEQUENCE → two OCTET STRINGs
        _, inner = _parse_der_tlv(payload)
        _, _, rest = _parse_der_tlv_with_rest(inner)
        _, signature, _ = _parse_der_tlv_with_rest(rest)

        tls_public_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_message = SIGNATURE_PREFIX + tls_public_bytes
        assert identity_key.public_key.verify(expected_message, signature)

    def test_self_signed(self, identity_key: IdentityKeypair) -> None:
        """The certificate is self-signed: its TLS public key verifies the outer signature."""
        _, _, cert = generate_libp2p_certificate(identity_key)
        cert.verify_directly_issued_by(cert)

    def test_ephemeral_key_uniqueness(self, identity_key: IdentityKeypair) -> None:
        """Two calls with the same identity key produce different TLS keys."""
        pem1, _, cert1 = generate_libp2p_certificate(identity_key)
        pem2, _, cert2 = generate_libp2p_certificate(identity_key)

        assert pem1 != pem2
        assert cert1.serial_number != cert2.serial_number

    def test_returned_cert_matches_pem(self, identity_key: IdentityKeypair) -> None:
        """The returned certificate object matches the PEM encoding."""
        _, cert_pem, cert = generate_libp2p_certificate(identity_key)
        reparsed = x509.load_pem_x509_certificate(cert_pem)
        assert reparsed == cert


# ---------------------------------------------------------------------------
# DER parsing helpers (test-only)
#
# Minimal DER TLV parser for verifying hand-encoded ASN.1 output.
# ---------------------------------------------------------------------------


def _parse_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Parse a DER length field, return (length, bytes_consumed)."""
    first = data[offset]
    if first < 128:
        return first, 1
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, 1 + num_bytes


def _parse_der_tlv(data: bytes) -> tuple[int, bytes]:
    """Parse a single DER TLV, return (tag, value)."""
    tag = data[0]
    length, length_size = _parse_der_length(data, 1)
    value_start = 1 + length_size
    return tag, data[value_start : value_start + length]


def _parse_der_tlv_with_rest(data: bytes) -> tuple[int, bytes, bytes]:
    """Parse a single DER TLV, return (tag, value, remaining_bytes)."""
    tag = data[0]
    length, length_size = _parse_der_length(data, 1)
    value_start = 1 + length_size
    value_end = value_start + length
    return tag, data[value_start:value_end], data[value_end:]
