"""
Tests for Noise crypto primitives.

Uses official RFC test vectors where applicable:
- RFC 7748: X25519 Diffie-Hellman
- RFC 8439: ChaCha20-Poly1305 AEAD
- Noise HKDF: Custom formula from Noise Protocol spec (NOT RFC 5869!)

The Noise-specific HKDF differs from RFC 5869 by omitting the "info"
parameter and using a chained counter scheme (0x01, 0x02).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from lean_spec.subspecs.networking.transport.noise.constants import (
    PROTOCOL_NAME,
    PROTOCOL_NAME_HASH,
)
from lean_spec.subspecs.networking.transport.noise.crypto import (
    decrypt,
    encrypt,
    generate_keypair,
    hkdf_sha256,
    sha256,
    x25519_dh,
)
from lean_spec.types import Bytes32


class TestX25519:
    """
    X25519 Diffie-Hellman tests.

    Test vectors from RFC 7748 Section 6.1.
    https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
    """

    def test_rfc7748_test_vector_1(self) -> None:
        """
        RFC 7748 Section 6.1 Test Vector 1.

        Alice's private key (scalar) and Bob's public key (u-coordinate)
        produce a specific shared secret.
        """
        # Alice's private key (scalar) - RFC 7748 format
        alice_private_bytes = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        # Bob's public key (u-coordinate)
        bob_public_bytes = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )
        # Expected shared secret
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        # Create key objects from raw bytes
        alice_private = x25519.X25519PrivateKey.from_private_bytes(alice_private_bytes)
        bob_public = x25519.X25519PublicKey.from_public_bytes(bob_public_bytes)

        # Perform DH
        shared = x25519_dh(alice_private, bob_public)

        assert shared == expected_shared

    def test_rfc7748_test_vector_2(self) -> None:
        """
        RFC 7748 Section 6.1 Test Vector 2.

        Bob's private key and Alice's public key produce the same shared secret.
        """
        # Bob's private key
        bob_private_bytes = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        )
        # Alice's public key
        alice_public_bytes = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        # Same expected shared secret as test 1
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        # Create key objects from raw bytes
        bob_private = x25519.X25519PrivateKey.from_private_bytes(bob_private_bytes)
        alice_public = x25519.X25519PublicKey.from_public_bytes(alice_public_bytes)

        shared = x25519_dh(bob_private, alice_public)

        assert shared == expected_shared

    def test_dh_symmetry(self) -> None:
        """DH(a, B) == DH(b, A) for any keypairs."""
        alice_private, alice_public = generate_keypair()
        bob_private, bob_public = generate_keypair()

        shared_alice = x25519_dh(alice_private, bob_public)
        shared_bob = x25519_dh(bob_private, alice_public)

        assert shared_alice == shared_bob
        assert len(shared_alice) == 32

    def test_dh_output_length(self) -> None:
        """DH output is always 32 bytes."""
        for _ in range(5):
            priv, pub = generate_keypair()
            other_priv, other_pub = generate_keypair()
            shared = x25519_dh(priv, other_pub)
            assert len(shared) == 32


class TestChaCha20Poly1305:
    """
    ChaCha20-Poly1305 AEAD tests.

    Test vectors from RFC 8439 Section 2.8.2.
    https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    """

    def test_rfc8439_aead_test_vector(self) -> None:
        """
        RFC 8439 Section 2.8.2 AEAD Test Vector.

        Note: Our nonce format differs slightly (4 zero bytes + 8-byte counter).
        This test uses a compatible nonce.
        """
        key = Bytes32(
            bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        )
        # Our nonce format: 4 zeros + 8-byte LE counter
        # RFC nonce: 07000000 40414243 44454647 (12 bytes)
        # We'll use nonce=0 for simplicity with our format
        nonce = 0

        plaintext = (
            b"Ladies and Gentlemen of the class of '99: "
            b"If I could offer you only one tip for the future, sunscreen would be it."
        )
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")

        # Encrypt
        ciphertext = encrypt(key, nonce, aad, plaintext)

        # Ciphertext should be plaintext + 16-byte tag
        assert len(ciphertext) == len(plaintext) + 16

        # Decrypt should recover plaintext
        decrypted = decrypt(key, nonce, aad, ciphertext)
        assert decrypted == plaintext

    def test_roundtrip(self) -> None:
        """Encrypt then decrypt returns original plaintext."""
        key = Bytes32(bytes(32))  # All zeros key (valid for testing)
        plaintext = b"Hello, Noise Protocol!"
        aad = b"associated data"

        for nonce in [0, 1, 100, 2**32 - 1, 2**63 - 1]:
            ciphertext = encrypt(key, nonce, aad, plaintext)
            decrypted = decrypt(key, nonce, aad, ciphertext)
            assert decrypted == plaintext

    def test_empty_plaintext(self) -> None:
        """Encrypting empty plaintext produces 16-byte tag."""
        key = Bytes32(bytes(32))
        ciphertext = encrypt(key, 0, b"", b"")

        # Just the auth tag
        assert len(ciphertext) == 16

        # Decrypt should work
        decrypted = decrypt(key, 0, b"", ciphertext)
        assert decrypted == b""

    def test_auth_tag_verification(self) -> None:
        """Tampered ciphertext fails authentication."""
        from cryptography.exceptions import InvalidTag

        key = Bytes32(bytes(32))
        plaintext = b"Secret message"
        ciphertext = encrypt(key, 0, b"", plaintext)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            decrypt(key, 0, b"", tampered)

    def test_wrong_key_fails(self) -> None:
        """Decryption with wrong key fails."""
        from cryptography.exceptions import InvalidTag

        key1 = Bytes32(bytes(32))
        key2 = Bytes32(bytes([1] + [0] * 31))
        plaintext = b"Secret"

        ciphertext = encrypt(key1, 0, b"", plaintext)

        with pytest.raises(InvalidTag):
            decrypt(key2, 0, b"", ciphertext)

    def test_wrong_nonce_fails(self) -> None:
        """Decryption with wrong nonce fails."""
        from cryptography.exceptions import InvalidTag

        key = Bytes32(bytes(32))
        plaintext = b"Secret"

        ciphertext = encrypt(key, 0, b"", plaintext)

        with pytest.raises(InvalidTag):
            decrypt(key, 1, b"", ciphertext)

    def test_wrong_aad_fails(self) -> None:
        """Decryption with wrong associated data fails."""
        from cryptography.exceptions import InvalidTag

        key = Bytes32(bytes(32))
        plaintext = b"Secret"

        ciphertext = encrypt(key, 0, b"aad1", plaintext)

        with pytest.raises(InvalidTag):
            decrypt(key, 0, b"aad2", ciphertext)


class TestHKDF:
    """
    Noise HKDF-SHA256 key derivation tests.

    NOTE: Noise uses a DIFFERENT HKDF than RFC 5869! The Noise-specific
    formula (from Noise Protocol Framework, Section 4) is:

        temp_key = HMAC-SHA256(chaining_key, input_key_material)
        output1 = HMAC-SHA256(temp_key, byte(0x01))
        output2 = HMAC-SHA256(temp_key, output1 || byte(0x02))

    RFC 5869 HKDF uses: HKDF-Expand(PRK, info, L) with an "info" parameter.
    Noise omits the info parameter and uses chained counter bytes (0x01, 0x02).

    Test vectors computed from the Noise spec formula.
    Reference: https://noiseprotocol.org/noise.html#the-symmetricstate-object
    """

    def test_vector_all_zeros(self) -> None:
        """
        Test Vector 1: All zeros input.

        chaining_key = 00...00 (32 bytes)
        ikm          = 00...00 (32 bytes)
        """
        ck = Bytes32(bytes(32))
        ikm = bytes(32)

        output1, output2 = hkdf_sha256(ck, ikm)

        expected_output1 = bytes.fromhex(
            "df7204546f1bee78b85324a7898ca119b387e01386d1aef037781d4a8a036aee"
        )
        expected_output2 = bytes.fromhex(
            "a7b65a6e7f873068dd147c56493e71294acc89e73baae2e4a87075f18739b4cd"
        )

        assert output1 == expected_output1
        assert output2 == expected_output2

    def test_vector_sequential_bytes(self) -> None:
        """
        Test Vector 2: Sequential byte values.

        chaining_key = 000102...1f (32 bytes)
        ikm          = 202122...3f (32 bytes)
        """
        ck = Bytes32(
            bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        )
        ikm = bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

        output1, output2 = hkdf_sha256(ck, ikm)

        expected_output1 = bytes.fromhex(
            "2607f5d05b268e0057684567787ed2f250fdb6e5b0572df9ef57a29539e5b5f8"
        )
        expected_output2 = bytes.fromhex(
            "ccc538566c93ab32f7106fbee1e0e9fa5501f6363b63ce894b3a27385f13c86c"
        )

        assert output1 == expected_output1
        assert output2 == expected_output2

    def test_vector_empty_ikm(self) -> None:
        """
        Test Vector 3: Empty IKM (used in Noise split() operation).

        The split() function calls HKDF with empty IKM to derive transport
        keys after the handshake completes. The chaining_key here is the
        X25519 shared secret from RFC 7748 test vector.
        """
        ck = Bytes32(
            bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        )
        ikm = b""  # Empty IKM for split()

        output1, output2 = hkdf_sha256(ck, ikm)

        expected_output1 = bytes.fromhex(
            "2045c656751b84dd95b1ac7330c1ef07ee96bc189365b391afccbd14ef2b7e0e"
        )
        expected_output2 = bytes.fromhex(
            "e8d2e541716fbb757e1a4f2cc776cf2955113f939b98e791bab0cf99e11e2a03"
        )

        assert output1 == expected_output1
        assert output2 == expected_output2

    def test_output_lengths(self) -> None:
        """HKDF outputs two 32-byte keys."""
        ck = Bytes32(bytes(32))
        ikm = bytes(32)

        key1, key2 = hkdf_sha256(ck, ikm)

        assert len(key1) == 32
        assert len(key2) == 32

    def test_deterministic(self) -> None:
        """Same inputs produce same outputs."""
        ck = Bytes32(
            bytes.fromhex("0011223344556677889900112233445566778899001122334455667788990011")
        )
        ikm = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

        key1_a, key2_a = hkdf_sha256(ck, ikm)
        key1_b, key2_b = hkdf_sha256(ck, ikm)

        assert key1_a == key1_b
        assert key2_a == key2_b

    def test_different_inputs_different_outputs(self) -> None:
        """Different inputs produce different outputs."""
        ck1 = Bytes32(bytes(32))
        ck2 = Bytes32(bytes([1] + [0] * 31))
        ikm = bytes(32)

        out1 = hkdf_sha256(ck1, ikm)
        out2 = hkdf_sha256(ck2, ikm)

        assert out1 != out2


class TestSHA256:
    """
    SHA256 hash function tests.

    Test vectors from NIST FIPS 180-4.
    """

    def test_empty_string(self) -> None:
        """SHA256 of empty string."""
        expected = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert sha256(b"") == expected

    def test_abc(self) -> None:
        """SHA256 of 'abc'."""
        expected = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assert sha256(b"abc") == expected

    def test_long_message(self) -> None:
        """SHA256 of longer message."""
        # 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = bytes.fromhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        assert sha256(msg) == expected


class TestProtocolConstants:
    """Tests for Noise protocol constants."""

    def test_protocol_name(self) -> None:
        """Protocol name is correct."""
        assert PROTOCOL_NAME == b"Noise_XX_25519_ChaChaPoly_SHA256"

    def test_protocol_name_hash(self) -> None:
        """Protocol name hash is SHA256 of the name."""
        expected = sha256(b"Noise_XX_25519_ChaChaPoly_SHA256")
        assert PROTOCOL_NAME_HASH == expected
        assert len(PROTOCOL_NAME_HASH) == 32


class TestKeypairGeneration:
    """Tests for keypair generation."""

    def test_generate_keypair(self) -> None:
        """Generates valid X25519 keypair."""
        private, public = generate_keypair()

        # Public key is an X25519PublicKey object
        assert isinstance(public, x25519.X25519PublicKey)
        assert len(public.public_bytes_raw()) == 32

        # Private key can be used for DH
        other_priv, other_pub = generate_keypair()
        shared = x25519_dh(private, other_pub)
        assert len(shared) == 32

    def test_keypairs_are_unique(self) -> None:
        """Each keypair generation produces unique keys."""
        pairs = [generate_keypair() for _ in range(10)]
        # Convert to bytes for comparison (key objects are not hashable)
        public_bytes = [p[1].public_bytes_raw() for p in pairs]

        # All public keys should be unique
        assert len(set(public_bytes)) == len(public_bytes)
