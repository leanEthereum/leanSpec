"""
libp2p TLS certificate generation and verification.

libp2p uses TLS 1.3 with a custom extension to bind peer IDs to TLS certificates.
Each peer:
    1. Generates an ephemeral TLS key pair (P-256 or Ed25519)
    2. Creates a self-signed certificate with the libp2p extension
    3. The extension contains a signature proving identity key ownership

The extension format (OID 1.3.6.1.4.1.53594.1.1):
    - protobuf-encoded PublicKey (identity key)
    - signature over "libp2p-tls-handshake:" + TLS public key bytes

Why this design? TLS certificates are normally validated against a CA. libp2p
has no CA - peers prove identity through cryptographic signatures. The extension
binds the TLS key to the libp2p identity key.

References:
    - libp2p TLS spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
    - OID registry: 1.3.6.1.4.1.53594 is assigned to Protocol Labs
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lean_spec.node.networking.transport.identity import IdentityKeypair, Secp256k1PublicKey
from lean_spec.node.networking.transport.peer_id import KeyType, PeerId, PublicKeyProtobuf
from lean_spec.node.networking.transport.quic.stream import QuicTransportError
from lean_spec.node.networking.varint import VarintError, decode_varint

LIBP2P_EXTENSION_OID: Final = x509.ObjectIdentifier("1.3.6.1.4.1.53594.1.1")
"""libp2p TLS extension OID (Protocol Labs assigned)."""

SIGNATURE_PREFIX: Final = b"libp2p-tls-handshake:"
"""
Prefix for the signed payload.

The signature proves ownership of the identity key over this specific TLS key.
Without a prefix, the signature could potentially be replayed in other contexts.
"""


def generate_libp2p_certificate(
    identity_key: IdentityKeypair,
) -> tuple[bytes, bytes, x509.Certificate]:
    """
    Generate a self-signed certificate with libp2p extension.

    Creates an ephemeral P-256 TLS key pair and a certificate containing:
        - Random subject/issuer (privacy - doesn't reveal identity)
        - Short validity (security - limits key exposure)
        - libp2p extension with identity proof

    Args:
        identity_key: secp256k1 identity keypair for signing.

    Returns:
        (private_key_pem, certificate_pem, certificate) tuple.
    """
    # Generate ephemeral P-256 key for TLS.
    #
    # Why P-256 and not secp256k1?
    #   1. P-256 has better TLS library support
    #   2. TLS key is ephemeral, only used for this connection
    #   3. secp256k1 identity is proven via the extension signature
    tls_private = ec.generate_private_key(ec.SECP256R1())
    tls_public = tls_private.public_key()

    # Get TLS public key bytes for signing.
    #
    # The signature binds our identity key to this specific TLS key.
    # We use the SubjectPublicKeyInfo format (DER-encoded public key).
    tls_public_bytes = tls_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create the libp2p extension payload.
    #
    # Format: protobuf-encoded SignedKey message
    #   - PublicKey: our secp256k1 identity public key
    #   - Signature: over (prefix + tls_public_bytes)
    extension_payload = _create_extension_payload(identity_key, tls_public_bytes)

    # Build the certificate.
    #
    # Empty subject/issuer to match rust-libp2p's format.
    # The peer identity is proven via the libp2p extension, not the DN.
    # Short validity (1 hour) limits key compromise exposure.
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([])

    # Compute Subject Key Identifier from public key.
    #
    # SKI is the SHA-256 hash of the TLS public key, truncated to 20 bytes.
    # This matches webpki's expected format for self-signed certificates.
    ski_digest = hashlib.sha256(tls_public_bytes).digest()[:20]

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))  # Allow clock skew
        .not_valid_after(now + timedelta(days=365))  # Longer validity like rcgen
        # Subject Key Identifier for self-signed certificate validation.
        .add_extension(
            x509.SubjectKeyIdentifier(ski_digest),
            critical=False,
        )
        # libp2p extension with identity proof.
        #
        # NOT marked critical so that standard TLS libraries don't reject it
        # before the libp2p verifier can check it.
        .add_extension(
            x509.UnrecognizedExtension(LIBP2P_EXTENSION_OID, extension_payload),
            critical=False,
        )
        .sign(tls_private, hashes.SHA256())
    )

    # Serialize to PEM for aioquic configuration.
    private_pem = tls_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

    return private_pem, certificate_pem, certificate


def _create_extension_payload(
    identity_key: IdentityKeypair,
    tls_public_bytes: bytes,
) -> bytes:
    """
    Create the libp2p extension payload.

    The extension uses ASN.1 DER encoding:

        SignedKey ::= SEQUENCE {
            publicKey OCTET STRING,  -- protobuf-encoded PublicKey
            signature OCTET STRING   -- raw r||s signature
        }

    The publicKey OCTET STRING contains a protobuf-encoded PublicKey message:

        message PublicKey {
            KeyType Type = 1;
            bytes Data = 2;
        }
    """
    # Get compressed public key (33 bytes for secp256k1).
    public_key_compressed = identity_key.public_key.to_bytes()

    # Create signature over (prefix + tls_public_bytes).
    #
    # The signature format: py-libp2p uses DER-encoded signatures
    # (via coincurve), so we keep the DER format from our sign() method.
    to_sign = SIGNATURE_PREFIX + tls_public_bytes
    signature = identity_key.sign(to_sign)  # DER-encoded signature

    # Encode PublicKey as protobuf.
    #   Field 1 (Type): tag=0x08, value=2 (secp256k1)
    #   Field 2 (Data): tag=0x12, length, bytes
    public_key_protobuf = (
        bytes([0x08, KeyType.SECP256K1, 0x12, len(public_key_compressed)]) + public_key_compressed
    )

    # Encode as ASN.1 DER SEQUENCE.
    #
    # SignedKey ::= SEQUENCE {
    #     publicKey OCTET STRING,
    #     signature OCTET STRING
    # }
    return _encode_asn1_signed_key(public_key_protobuf, signature)


def _encode_asn1_signed_key(public_key_protobuf: bytes, signature: bytes) -> bytes:
    """
    Encode SignedKey as ASN.1 DER.

    ASN.1 structure:
        SEQUENCE {
            OCTET STRING (public_key_protobuf),
            OCTET STRING (signature)
        }
    """
    # Encode the two OCTET STRINGs.
    octet1 = _encode_asn1_octet_string(public_key_protobuf)
    octet2 = _encode_asn1_octet_string(signature)

    # Encode the SEQUENCE.
    content = octet1 + octet2
    return _encode_asn1_sequence(content)


def _encode_asn1_octet_string(data: bytes) -> bytes:
    """Encode bytes as ASN.1 OCTET STRING."""
    # Tag 0x04 = OCTET STRING
    return bytes([0x04]) + _encode_asn1_length(len(data)) + data


def _encode_asn1_sequence(content: bytes) -> bytes:
    """Encode content as ASN.1 SEQUENCE."""
    # Tag 0x30 = SEQUENCE
    return bytes([0x30]) + _encode_asn1_length(len(content)) + content


def _encode_asn1_length(length: int) -> bytes:
    """Encode length in ASN.1 DER format."""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, length >> 8, length & 0xFF])


def verify_libp2p_certificate(certificate: x509.Certificate) -> PeerId:
    """
    Verify a peer's libp2p certificate and recover its PeerId.

    This is the exact inverse of the generation side.
    It locates the libp2p extension, decodes the SignedKey structure,
    and checks that the identity key signed this certificate's TLS key.

    A passing verification proves the peer controls the secp256k1 identity key
    bound to the ephemeral TLS key used in the handshake.

    Args:
        certificate: The peer's self-signed certificate from the TLS handshake.

    Returns:
        The PeerId derived from the verified identity public key.

    Raises:
        QuicTransportError: If the extension is absent or malformed.
        QuicTransportError: If the key type is not secp256k1.
        QuicTransportError: If the identity signature does not verify.
    """
    # Locate the libp2p extension by its OID.
    #
    # Without it the certificate carries no identity proof, so it is unusable.
    try:
        extension = certificate.extensions.get_extension_for_oid(LIBP2P_EXTENSION_OID)
    except x509.ExtensionNotFound as exception:
        raise QuicTransportError(
            "Peer certificate is missing the libp2p identity extension."
        ) from exception

    # The extension value is an UnrecognizedExtension carrying the DER payload.
    extension_payload = extension.value
    if not isinstance(extension_payload, x509.UnrecognizedExtension):
        raise QuicTransportError("Peer certificate libp2p extension has an unexpected encoding.")

    # Decode the SignedKey SEQUENCE into its two OCTET STRINGs.
    public_key_protobuf, signature = _decode_asn1_signed_key(extension_payload.value)

    # Parse the protobuf PublicKey into its key type and raw key bytes.
    identity_public_key_protobuf = _decode_public_key_protobuf(public_key_protobuf)

    # Only secp256k1 identities are valid on this network.
    if identity_public_key_protobuf.key_type != KeyType.SECP256K1:
        raise QuicTransportError(
            f"Peer identity key type is not secp256k1: {identity_public_key_protobuf.key_type!r}."
        )

    # Reconstruct the signed payload exactly as the generator built it.
    #
    # The generator signed the prefix followed by the SubjectPublicKeyInfo
    # DER encoding of the certificate's own TLS public key.
    tls_public_key_der = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signed_payload = SIGNATURE_PREFIX + tls_public_key_der

    # Reconstruct the secp256k1 identity public key from the compressed bytes.
    #
    # A malformed point is rejected here before any signature check runs.
    try:
        identity_public_key = Secp256k1PublicKey(
            _key=ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(),
                identity_public_key_protobuf.key_data,
            )
        )
    except ValueError as exception:
        raise QuicTransportError(
            "Peer identity public key is not a valid secp256k1 point."
        ) from exception

    # Verify the DER signature over the payload using ECDSA-SHA256.
    if not identity_public_key.verify(signed_payload, signature):
        raise QuicTransportError("Peer identity signature does not match the certificate TLS key.")

    # Derive the PeerId from the verified identity public key.
    return PeerId.from_public_key(identity_public_key_protobuf)


def _decode_asn1_signed_key(data: bytes) -> tuple[bytes, bytes]:
    """
    Decode a SignedKey SEQUENCE of two OCTET STRINGs.

    The inverse of the SignedKey encoder.

    Args:
        data: DER-encoded SignedKey SEQUENCE.

    Returns:
        The (public_key_protobuf, signature) pair.

    Raises:
        QuicTransportError: If the structure is malformed or has trailing bytes.
    """
    # The whole payload must be exactly one SEQUENCE.
    sequence_content, sequence_end = _decode_asn1_sequence(data, 0)
    if sequence_end != len(data):
        raise QuicTransportError("Peer certificate SignedKey has trailing bytes.")

    # The SEQUENCE holds two OCTET STRINGs back to back.
    public_key_protobuf, after_first = _decode_asn1_octet_string(sequence_content, 0)
    signature, after_second = _decode_asn1_octet_string(sequence_content, after_first)
    if after_second != len(sequence_content):
        raise QuicTransportError("Peer certificate SignedKey has unexpected extra fields.")

    return public_key_protobuf, signature


def _decode_public_key_protobuf(data: bytes) -> PublicKeyProtobuf:
    """
    Decode a libp2p protobuf PublicKey message.

    The wire format is field 1 (KeyType varint) then field 2 (length-delimited Data).

    Args:
        data: Protobuf-encoded PublicKey bytes.

    Returns:
        The decoded public key in protobuf form.

    Raises:
        QuicTransportError: If the message is malformed or has trailing bytes.
    """
    # Field 1: Type, tag 0x08, varint.
    if len(data) < 1 or data[0] != 0x08:
        raise QuicTransportError("Peer identity protobuf is missing the key type field.")
    try:
        key_type_value, type_consumed = decode_varint(data, 1)
    except VarintError as exception:
        raise QuicTransportError("Peer identity protobuf has a malformed key type.") from exception

    # Field 2: Data, tag 0x12, length-delimited bytes.
    data_tag_offset = 1 + type_consumed
    if len(data) <= data_tag_offset or data[data_tag_offset] != 0x12:
        raise QuicTransportError("Peer identity protobuf is missing the key data field.")
    try:
        key_data_length, length_consumed = decode_varint(data, data_tag_offset + 1)
    except VarintError as exception:
        raise QuicTransportError(
            "Peer identity protobuf has a malformed key data length."
        ) from exception

    key_data_offset = data_tag_offset + 1 + length_consumed
    key_data_end = key_data_offset + key_data_length
    if key_data_end != len(data):
        raise QuicTransportError("Peer identity protobuf has an inconsistent key data length.")
    key_data = data[key_data_offset:key_data_end]

    try:
        key_type = KeyType(key_type_value)
    except ValueError as exception:
        raise QuicTransportError(
            f"Peer identity protobuf has an unknown key type: {key_type_value}."
        ) from exception

    return PublicKeyProtobuf(key_type=key_type, key_data=key_data)


def _decode_asn1_sequence(data: bytes, offset: int) -> tuple[bytes, int]:
    """
    Decode an ASN.1 SEQUENCE and return its content bytes.

    Args:
        data: Buffer containing the SEQUENCE.
        offset: Position of the SEQUENCE tag.

    Returns:
        The (content, end_offset) pair, where end_offset is just past the content.

    Raises:
        QuicTransportError: If the tag is wrong or the length overflows the buffer.
    """
    # Tag 0x30 = SEQUENCE.
    if offset >= len(data) or data[offset] != 0x30:
        raise QuicTransportError("Peer certificate SignedKey is not an ASN.1 SEQUENCE.")
    length, length_end = _decode_asn1_length(data, offset + 1)
    content_end = length_end + length
    if content_end > len(data):
        raise QuicTransportError("Peer certificate SignedKey SEQUENCE length overflows.")
    return data[length_end:content_end], content_end


def _decode_asn1_octet_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """
    Decode an ASN.1 OCTET STRING and return its content bytes.

    Args:
        data: Buffer containing the OCTET STRING.
        offset: Position of the OCTET STRING tag.

    Returns:
        The (content, end_offset) pair, where end_offset is just past the content.

    Raises:
        QuicTransportError: If the tag is wrong or the length overflows the buffer.
    """
    # Tag 0x04 = OCTET STRING.
    if offset >= len(data) or data[offset] != 0x04:
        raise QuicTransportError("Peer certificate SignedKey field is not an ASN.1 OCTET STRING.")
    length, length_end = _decode_asn1_length(data, offset + 1)
    content_end = length_end + length
    if content_end > len(data):
        raise QuicTransportError("Peer certificate SignedKey OCTET STRING length overflows.")
    return data[length_end:content_end], content_end


def _decode_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
    """
    Decode an ASN.1 DER length field.

    The inverse of the length encoder, supporting short form and one or two
    long-form length octets.

    Args:
        data: Buffer containing the length field.
        offset: Position of the first length octet.

    Returns:
        The (length, end_offset) pair, where end_offset is just past the length octets.

    Raises:
        QuicTransportError: If the length encoding is truncated or unsupported.
    """
    if offset >= len(data):
        raise QuicTransportError("Peer certificate ASN.1 length is truncated.")

    first = data[offset]

    # Short form: the length fits in the low seven bits of one octet.
    if first < 0x80:
        return first, offset + 1

    # Long form: the low seven bits give the number of length octets that follow.
    num_length_octets = first & 0x7F
    if num_length_octets == 0 or num_length_octets > 2:
        raise QuicTransportError("Peer certificate ASN.1 length uses an unsupported form.")
    if offset + 1 + num_length_octets > len(data):
        raise QuicTransportError("Peer certificate ASN.1 length is truncated.")

    length = int.from_bytes(data[offset + 1 : offset + 1 + num_length_octets], "big")
    return length, offset + 1 + num_length_octets
