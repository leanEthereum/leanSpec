"""
Tests for libp2p TLS certificate generation and ASN.1 encoding.

Tests verify behavior against the libp2p TLS spec:
    https://github.com/libp2p/specs/blob/master/tls/tls.md

The module under test hand-encodes ASN.1 DER instead of using a library,
so these tests validate both the encoding helpers and the full certificate
generation pipeline, including signature verification of the identity proof.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lean_spec.node.networking.transport.identity.keypair import IdentityKeypair
from lean_spec.node.networking.transport.peer_id import KeyType
from lean_spec.node.networking.transport.quic.stream import QuicTransportError
from lean_spec.node.networking.transport.quic.tls import (
    LIBP2P_EXTENSION_OID,
    SIGNATURE_PREFIX,
    _create_extension_payload,
    _encode_asn1_length,
    _encode_asn1_octet_string,
    _encode_asn1_sequence,
    _encode_asn1_signed_key,
    generate_libp2p_certificate,
    verify_libp2p_certificate,
)

# Shared fixtures


@pytest.fixture
def identity_key() -> IdentityKeypair:
    """A fresh secp256k1 identity keypair for testing."""
    return IdentityKeypair.generate()


# Constants — sanity checks for protocol-defined values


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
        assert KeyType.SECP256K1 == 2


# ASN.1 length encoding — must cover all 3 branches
#
# DER length encoding:
#   - Short form:    length < 128 → single byte
#   - Long 1-byte:   128 ≤ length < 256 → 0x81 + 1 byte
#   - Long 2-byte:   length ≥ 256 → 0x82 + 2 bytes (big-endian)


class TestEncodeAsn1Length:
    """Tests for DER length encoding covering all three code paths."""

    @pytest.mark.parametrize(
        ("length", "expected_encoding"),
        [
            (0, bytes([0])),
            (1, bytes([1])),
            (127, bytes([127])),
        ],
        ids=["zero", "one", "max-short-form"],
    )
    def test_short_form(self, length: int, expected_encoding: bytes) -> None:
        """Lengths below 128 use a single byte (short form)."""
        assert _encode_asn1_length(length) == expected_encoding

    @pytest.mark.parametrize(
        ("length", "expected_encoding"),
        [
            (128, bytes([0x81, 128])),
            (200, bytes([0x81, 200])),
            (255, bytes([0x81, 255])),
        ],
        ids=["min-long-1", "mid-long-1", "max-long-1"],
    )
    def test_one_byte_long_form(self, length: int, expected_encoding: bytes) -> None:
        """Lengths 128..255 use 0x81 prefix + 1 length byte."""
        assert _encode_asn1_length(length) == expected_encoding

    @pytest.mark.parametrize(
        ("length", "expected_encoding"),
        [
            (256, bytes([0x82, 0x01, 0x00])),
            (1000, bytes([0x82, 0x03, 0xE8])),
            (65535, bytes([0x82, 0xFF, 0xFF])),
        ],
        ids=["min-long-2", "mid-long-2", "max-u16"],
    )
    def test_two_byte_long_form(self, length: int, expected_encoding: bytes) -> None:
        """Lengths >= 256 use 0x82 prefix + 2 big-endian length bytes."""
        assert _encode_asn1_length(length) == expected_encoding


# ASN.1 OCTET STRING encoding


class TestEncodeAsn1OctetString:
    """Tests for ASN.1 OCTET STRING (tag 0x04) encoding."""

    def test_encodes_data_with_tag_and_length(self) -> None:
        """OCTET STRING has tag 0x04, correct length, and verbatim data."""
        encoded = _encode_asn1_octet_string(b"\xaa\xbb\xcc")
        assert encoded == bytes([0x04, 3, 0xAA, 0xBB, 0xCC])

    def test_empty_data(self) -> None:
        """Empty OCTET STRING is valid: tag 0x04, length 0, no content."""
        encoded = _encode_asn1_octet_string(b"")
        assert encoded == bytes([0x04, 0])

    def test_long_form_length(self) -> None:
        """Data >= 128 bytes triggers long-form length encoding."""
        octet_payload = bytes(range(256)) * 2  # 512 bytes
        encoded = _encode_asn1_octet_string(octet_payload)
        assert encoded[0] == 0x04
        assert encoded[1:4] == bytes([0x82, 0x02, 0x00])
        assert encoded[4:] == octet_payload


# ASN.1 SEQUENCE encoding


class TestEncodeAsn1Sequence:
    """Tests for ASN.1 SEQUENCE (tag 0x30) encoding."""

    def test_wraps_content_with_tag_and_length(self) -> None:
        """SEQUENCE has tag 0x30, correct length, and verbatim content."""
        content = bytes([0x04, 2, 0xAA, 0xBB])
        encoded = _encode_asn1_sequence(content)
        assert encoded == bytes([0x30, 4, 0x04, 2, 0xAA, 0xBB])

    def test_empty_sequence(self) -> None:
        """Empty SEQUENCE is valid: tag 0x30, length 0."""
        encoded = _encode_asn1_sequence(b"")
        assert encoded == bytes([0x30, 0])


# ASN.1 SignedKey — SEQUENCE { OCTET STRING, OCTET STRING }


class TestEncodeAsn1SignedKey:
    """Tests for the SignedKey ASN.1 structure used in the libp2p extension."""

    def test_structure_is_sequence_of_two_octet_strings(self) -> None:
        """Output is a SEQUENCE containing two OCTET STRINGs."""
        protobuf = b"\x08\x02\x12\x21" + bytes(33)
        signature = bytes(64)
        encoded = _encode_asn1_signed_key(protobuf, signature)

        assert encoded[0] == 0x30  # SEQUENCE tag

        # Parse inner content
        _, inner = _parse_der_tlv(encoded)
        # First OCTET STRING
        tag1, first_octet_string_value, rest = _parse_der_tlv_with_rest(inner)
        assert tag1 == 0x04
        assert first_octet_string_value == protobuf
        # Second OCTET STRING
        tag2, second_octet_string_value, rest2 = _parse_der_tlv_with_rest(rest)
        assert tag2 == 0x04
        assert second_octet_string_value == signature
        assert rest2 == b""


# Extension payload — protobuf + ASN.1 wrapping


class TestCreateExtensionPayload:
    """Tests for the libp2p extension payload construction."""

    def test_payload_is_valid_asn1_sequence(self, identity_key: IdentityKeypair) -> None:
        """The payload parses as an ASN.1 SEQUENCE of two OCTET STRINGs."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        extension_payload = _create_extension_payload(identity_key, tls_public_bytes)

        assert extension_payload[0] == 0x30
        _, inner = _parse_der_tlv(extension_payload)
        tag1, first_octet_string_value, rest = _parse_der_tlv_with_rest(inner)
        tag2, second_octet_string_value, _ = _parse_der_tlv_with_rest(rest)
        assert tag1 == 0x04
        assert tag2 == 0x04

    def test_protobuf_encoding(self, identity_key: IdentityKeypair) -> None:
        """First OCTET STRING contains a protobuf-encoded PublicKey message."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        extension_payload = _create_extension_payload(identity_key, tls_public_bytes)

        _, inner = _parse_der_tlv(extension_payload)
        _, public_key_protobuf, _ = _parse_der_tlv_with_rest(inner)

        # Protobuf field 1 (Type): varint tag=0x08, value=2 (secp256k1)
        assert public_key_protobuf[0] == 0x08
        assert public_key_protobuf[1] == KeyType.SECP256K1
        # Protobuf field 2 (Data): length-delimited tag=0x12
        assert public_key_protobuf[2] == 0x12
        key_length = public_key_protobuf[3]
        assert key_length == 33  # compressed secp256k1
        key_data = public_key_protobuf[4 : 4 + key_length]
        assert key_data == bytes(identity_key.public_key.to_bytes())

    def test_signature_verifies(self, identity_key: IdentityKeypair) -> None:
        """The signature in the second OCTET STRING verifies against the identity key."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        extension_payload = _create_extension_payload(identity_key, tls_public_bytes)

        _, inner = _parse_der_tlv(extension_payload)
        _, _, rest = _parse_der_tlv_with_rest(inner)
        _, signature, _ = _parse_der_tlv_with_rest(rest)

        expected_message = SIGNATURE_PREFIX + tls_public_bytes
        assert identity_key.public_key.verify(expected_message, signature)


# Full certificate generation


class TestGenerateLibp2pCertificate:
    """Tests for the complete certificate generation pipeline."""

    def test_returns_parseable_pem(self, identity_key: IdentityKeypair) -> None:
        """Both PEM outputs are parseable by the cryptography library."""
        private_pem, certificate_pem, certificate = generate_libp2p_certificate(identity_key)

        loaded_key = serialization.load_pem_private_key(private_pem, password=None)
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)

        loaded_certificate = x509.load_pem_x509_certificate(certificate_pem)
        assert loaded_certificate.serial_number == certificate.serial_number

    def test_tls_key_is_p256(self, identity_key: IdentityKeypair) -> None:
        """The ephemeral TLS key uses P-256 (SECP256R1), not secp256k1."""
        private_pem, _, _ = generate_libp2p_certificate(identity_key)
        loaded_key = serialization.load_pem_private_key(private_pem, password=None)
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert isinstance(loaded_key.curve, ec.SECP256R1)

    def test_empty_subject_and_issuer(self, identity_key: IdentityKeypair) -> None:
        """Subject and issuer are empty to match rust-libp2p's format."""
        _, _, certificate = generate_libp2p_certificate(identity_key)
        assert certificate.subject == x509.Name([])
        assert certificate.issuer == x509.Name([])

    def test_certificate_signed_with_sha256(self, identity_key: IdentityKeypair) -> None:
        """Certificate uses SHA-256 for the outer TLS signature."""
        _, _, certificate = generate_libp2p_certificate(identity_key)
        assert certificate.signature_hash_algorithm is not None
        assert certificate.signature_hash_algorithm.name == "sha256"

    def test_validity_window(self, identity_key: IdentityKeypair) -> None:
        """not_valid_before is ~1 day before now, not_valid_after is ~365 days after now."""
        now = datetime.now(timezone.utc)
        _, _, certificate = generate_libp2p_certificate(identity_key)

        not_before_delta = now - certificate.not_valid_before_utc
        not_after_delta = certificate.not_valid_after_utc - now

        tolerance = timedelta(minutes=5)
        assert abs(not_before_delta - timedelta(days=1)) < tolerance
        assert abs(not_after_delta - timedelta(days=365)) < tolerance

    def test_subject_key_identifier(self, identity_key: IdentityKeypair) -> None:
        """SKI extension is sha256(tls_public_key_der)[:20]."""
        _, _, certificate = generate_libp2p_certificate(identity_key)

        ski_ext = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski_ext.critical is False

        tls_public_bytes = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_ski = hashlib.sha256(tls_public_bytes).digest()[:20]
        assert ski_ext.value.digest == expected_ski

    def test_libp2p_extension_present_and_non_critical(self, identity_key: IdentityKeypair) -> None:
        """The libp2p extension is present with the correct OID and is non-critical."""
        _, _, certificate = generate_libp2p_certificate(identity_key)

        ext = certificate.extensions.get_extension_for_oid(LIBP2P_EXTENSION_OID)
        assert ext.critical is False
        assert isinstance(ext.value, x509.UnrecognizedExtension)

    def test_libp2p_extension_signature_verifies(self, identity_key: IdentityKeypair) -> None:
        """The identity proof signature in the extension verifies end-to-end."""
        _, _, certificate = generate_libp2p_certificate(identity_key)

        ext = certificate.extensions.get_extension_for_oid(LIBP2P_EXTENSION_OID)
        assert isinstance(ext.value, x509.UnrecognizedExtension)
        extension_payload = ext.value.value

        # Parse ASN.1 SEQUENCE → two OCTET STRINGs
        _, inner = _parse_der_tlv(extension_payload)
        _, _, rest = _parse_der_tlv_with_rest(inner)
        _, signature, _ = _parse_der_tlv_with_rest(rest)

        tls_public_bytes = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_message = SIGNATURE_PREFIX + tls_public_bytes
        assert identity_key.public_key.verify(expected_message, signature)

    def test_self_signed(self, identity_key: IdentityKeypair) -> None:
        """The certificate is self-signed: its TLS public key verifies the outer signature."""
        _, _, certificate = generate_libp2p_certificate(identity_key)
        certificate.verify_directly_issued_by(certificate)

    def test_ephemeral_key_uniqueness(self, identity_key: IdentityKeypair) -> None:
        """Two calls with the same identity key produce different TLS keys."""
        pem1, _, cert1 = generate_libp2p_certificate(identity_key)
        pem2, _, cert2 = generate_libp2p_certificate(identity_key)

        assert pem1 != pem2
        assert cert1.serial_number != cert2.serial_number

    def test_returned_certificate_matches_pem(self, identity_key: IdentityKeypair) -> None:
        """The returned certificate object matches the PEM encoding."""
        _, certificate_pem, certificate = generate_libp2p_certificate(identity_key)
        reparsed = x509.load_pem_x509_certificate(certificate_pem)
        assert reparsed == certificate


# Certificate verification — the inverse of generation


class TestVerifyLibp2pCertificate:
    """Tests for recovering and validating a peer identity from its certificate."""

    def test_roundtrip_recovers_peer_id(self, identity_key: IdentityKeypair) -> None:
        """Verifying a freshly generated certificate recovers the generating peer identity."""
        _, _, certificate = generate_libp2p_certificate(identity_key)
        assert verify_libp2p_certificate(certificate) == identity_key.to_peer_id()

    def test_tampered_signature_is_rejected(self, identity_key: IdentityKeypair) -> None:
        """Flipping one byte of the identity signature makes verification fail."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_protobuf = (
            bytes([0x08, KeyType.SECP256K1, 0x12, 33]) + identity_key.public_key.to_bytes()
        )
        signature = bytearray(identity_key.sign(SIGNATURE_PREFIX + tls_public_bytes))
        signature[-1] ^= 0x01
        tampered_extension_payload = _encode_asn1_signed_key(public_key_protobuf, bytes(signature))

        tampered_certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(tls_private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.UnrecognizedExtension(LIBP2P_EXTENSION_OID, tampered_extension_payload),
                critical=False,
            )
            .sign(tls_private, hashes.SHA256())
        )

        with pytest.raises(QuicTransportError) as exception_info:
            verify_libp2p_certificate(tampered_certificate)
        assert str(exception_info.value) == (
            "Peer identity signature does not match the certificate TLS key."
        )

    def test_missing_extension_is_rejected(self) -> None:
        """A self-signed certificate without the libp2p extension is rejected."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        certificate_without_extension = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(tls_private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(tls_private, hashes.SHA256())
        )

        with pytest.raises(QuicTransportError) as exception_info:
            verify_libp2p_certificate(certificate_without_extension)
        assert str(exception_info.value) == (
            "Peer certificate is missing the libp2p identity extension."
        )

    def test_wrong_key_type_is_rejected(self, identity_key: IdentityKeypair) -> None:
        """A SignedKey declaring a non-secp256k1 key type is rejected."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        ed25519_public_key_protobuf = (
            bytes([0x08, KeyType.ED25519, 0x12, 33]) + identity_key.public_key.to_bytes()
        )
        signature = identity_key.sign(SIGNATURE_PREFIX + tls_public_bytes)
        extension_payload = _encode_asn1_signed_key(ed25519_public_key_protobuf, signature)

        certificate_with_wrong_key_type = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(tls_private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.UnrecognizedExtension(LIBP2P_EXTENSION_OID, extension_payload),
                critical=False,
            )
            .sign(tls_private, hashes.SHA256())
        )

        with pytest.raises(QuicTransportError) as exception_info:
            verify_libp2p_certificate(certificate_with_wrong_key_type)
        assert str(exception_info.value) == (
            "Peer identity key type is not secp256k1: <KeyType.ED25519: 1>."
        )

    def test_trailing_bytes_in_extension_are_rejected(self, identity_key: IdentityKeypair) -> None:
        """Extra bytes after the SignedKey SEQUENCE are rejected as malformed ASN.1."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_protobuf = (
            bytes([0x08, KeyType.SECP256K1, 0x12, 33]) + identity_key.public_key.to_bytes()
        )
        signature = identity_key.sign(SIGNATURE_PREFIX + tls_public_bytes)
        extension_payload_with_trailing_byte = (
            _encode_asn1_signed_key(public_key_protobuf, signature) + b"\x00"
        )

        certificate_with_trailing_byte = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(tls_private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.UnrecognizedExtension(
                    LIBP2P_EXTENSION_OID, extension_payload_with_trailing_byte
                ),
                critical=False,
            )
            .sign(tls_private, hashes.SHA256())
        )

        with pytest.raises(QuicTransportError) as exception_info:
            verify_libp2p_certificate(certificate_with_trailing_byte)
        assert str(exception_info.value) == "Peer certificate SignedKey has trailing bytes."

    def test_off_curve_public_key_is_rejected(self, identity_key: IdentityKeypair) -> None:
        """A compressed point that is not on the secp256k1 curve is rejected."""
        tls_private = ec.generate_private_key(ec.SECP256R1())
        tls_public_bytes = tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        off_curve_compressed_point = bytes([0x02]) + b"\xff" * 32
        off_curve_public_key_protobuf = (
            bytes([0x08, KeyType.SECP256K1, 0x12, 33]) + off_curve_compressed_point
        )
        signature = identity_key.sign(SIGNATURE_PREFIX + tls_public_bytes)
        extension_payload = _encode_asn1_signed_key(off_curve_public_key_protobuf, signature)

        certificate_with_off_curve_key = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(tls_private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.UnrecognizedExtension(LIBP2P_EXTENSION_OID, extension_payload),
                critical=False,
            )
            .sign(tls_private, hashes.SHA256())
        )

        with pytest.raises(QuicTransportError) as exception_info:
            verify_libp2p_certificate(certificate_with_off_curve_key)
        assert str(exception_info.value) == (
            "Peer identity public key is not a valid secp256k1 point."
        )

    def test_signature_over_foreign_tls_key_is_rejected(
        self, identity_key: IdentityKeypair
    ) -> None:
        """A proof signed over another certificate's TLS key fails on the wrong certificate."""
        # Sign the identity proof over a foreign TLS public key.
        foreign_tls_private = ec.generate_private_key(ec.SECP256R1())
        foreign_tls_public_bytes = foreign_tls_private.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_protobuf = (
            bytes([0x08, KeyType.SECP256K1, 0x12, 33]) + identity_key.public_key.to_bytes()
        )
        signature_over_foreign_key = identity_key.sign(SIGNATURE_PREFIX + foreign_tls_public_bytes)
        extension_payload = _encode_asn1_signed_key(public_key_protobuf, signature_over_foreign_key)

        # Embed that proof in a certificate carrying a different TLS key.
        own_tls_private = ec.generate_private_key(ec.SECP256R1())
        certificate_with_mismatched_proof = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(x509.Name([]))
            .public_key(own_tls_private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(
                x509.UnrecognizedExtension(LIBP2P_EXTENSION_OID, extension_payload),
                critical=False,
            )
            .sign(own_tls_private, hashes.SHA256())
        )

        with pytest.raises(QuicTransportError) as exception_info:
            verify_libp2p_certificate(certificate_with_mismatched_proof)
        assert str(exception_info.value) == (
            "Peer identity signature does not match the certificate TLS key."
        )


# DER parsing helpers (test-only)
#
# Minimal DER TLV parser for verifying hand-encoded ASN.1 output.


def _parse_der_length(der_bytes: bytes, offset: int) -> tuple[int, int]:
    """Parse a DER length field, return (length, bytes_consumed)."""
    first = der_bytes[offset]
    if first < 128:
        return first, 1
    num_bytes = first & 0x7F
    length = int.from_bytes(der_bytes[offset + 1 : offset + 1 + num_bytes], "big")
    return length, 1 + num_bytes


def _parse_der_tlv(der_bytes: bytes) -> tuple[int, bytes]:
    """Parse a single DER TLV, return (tag, value)."""
    tag = der_bytes[0]
    length, length_size = _parse_der_length(der_bytes, 1)
    value_start = 1 + length_size
    return tag, der_bytes[value_start : value_start + length]


def _parse_der_tlv_with_rest(der_bytes: bytes) -> tuple[int, bytes, bytes]:
    """Parse a single DER TLV, return (tag, value, remaining_bytes)."""
    tag = der_bytes[0]
    length, length_size = _parse_der_length(der_bytes, 1)
    value_start = 1 + length_size
    value_end = value_start + length
    return tag, der_bytes[value_start:value_end], der_bytes[value_end:]
