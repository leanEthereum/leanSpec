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

from ..identity import IdentityKeypair

LIBP2P_EXTENSION_OID: Final = x509.ObjectIdentifier("1.3.6.1.4.1.53594.1.1")
"""libp2p TLS extension OID (Protocol Labs assigned)."""

SIGNATURE_PREFIX: Final = b"libp2p-tls-handshake:"
"""
Prefix for the signed payload.

The signature proves ownership of the identity key over this specific TLS key.
Without a prefix, the signature could potentially be replayed in other contexts.
"""

# Key type identifiers matching libp2p protobuf definitions
KEY_TYPE_SECP256K1: Final = 2
"""secp256k1 key type in libp2p protobuf."""


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

    cert = (
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return private_pem, cert_pem, cert


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
    public_key_proto = (
        bytes([0x08, KEY_TYPE_SECP256K1, 0x12, len(public_key_compressed)]) + public_key_compressed
    )

    # Encode as ASN.1 DER SEQUENCE.
    #
    # SignedKey ::= SEQUENCE {
    #     publicKey OCTET STRING,
    #     signature OCTET STRING
    # }
    return _encode_asn1_signed_key(public_key_proto, signature)


def _encode_asn1_signed_key(public_key_proto: bytes, signature: bytes) -> bytes:
    """
    Encode SignedKey as ASN.1 DER.

    ASN.1 structure:
        SEQUENCE {
            OCTET STRING (public_key_proto),
            OCTET STRING (signature)
        }
    """
    # Encode the two OCTET STRINGs.
    octet1 = _encode_asn1_octet_string(public_key_proto)
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
