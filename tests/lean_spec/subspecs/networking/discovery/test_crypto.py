"""Tests for Discovery v5 cryptographic primitives."""

import pytest

from lean_spec.subspecs.networking.discovery.crypto import (
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ecdh_agree,
    generate_secp256k1_keypair,
    pubkey_to_compressed,
    pubkey_to_uncompressed,
    sign_id_nonce,
    verify_id_nonce_signature,
)


class TestAesCtr:
    """Tests for AES-CTR encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that decryption reverses encryption."""
        key = bytes(16)
        iv = bytes(16)
        plaintext = b"Hello, Discovery v5!"

        ciphertext = aes_ctr_encrypt(key, iv, plaintext)
        decrypted = aes_ctr_decrypt(key, iv, ciphertext)

        assert decrypted == plaintext

    def test_encryption_produces_different_output(self):
        """Test that encryption actually transforms the data."""
        key = bytes.fromhex("00" * 16)
        iv = bytes.fromhex("00" * 16)
        plaintext = b"test data"

        ciphertext = aes_ctr_encrypt(key, iv, plaintext)

        assert ciphertext != plaintext

    def test_different_ivs_produce_different_ciphertext(self):
        """Test that different IVs produce different ciphertext."""
        key = bytes(16)
        plaintext = b"same data"

        iv1 = bytes.fromhex("00" * 16)
        iv2 = bytes.fromhex("01" + "00" * 15)

        ct1 = aes_ctr_encrypt(key, iv1, plaintext)
        ct2 = aes_ctr_encrypt(key, iv2, plaintext)

        assert ct1 != ct2

    def test_invalid_key_length_raises(self):
        """Test that invalid key length raises ValueError."""
        with pytest.raises(ValueError, match="Key must be 16 bytes"):
            aes_ctr_encrypt(bytes(15), bytes(16), b"data")

    def test_invalid_iv_length_raises(self):
        """Test that invalid IV length raises ValueError."""
        with pytest.raises(ValueError, match="IV must be 16 bytes"):
            aes_ctr_encrypt(bytes(16), bytes(15), b"data")


class TestAesGcm:
    """Tests for AES-GCM encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that decryption reverses encryption."""
        key = bytes(16)
        nonce = bytes(12)
        plaintext = b"Hello, Discovery v5!"
        aad = b"additional data"

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    def test_ciphertext_includes_auth_tag(self):
        """Test that ciphertext is longer than plaintext (includes 16-byte tag)."""
        key = bytes(16)
        nonce = bytes(12)
        plaintext = b"test"
        aad = b""

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        assert len(ciphertext) == len(plaintext) + 16

    def test_wrong_aad_fails_decryption(self):
        """Test that wrong AAD causes authentication failure."""
        from cryptography.exceptions import InvalidTag

        key = bytes(16)
        nonce = bytes(12)
        plaintext = b"secret"
        aad = b"correct aad"

        ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(key, nonce, ciphertext, b"wrong aad")

    def test_invalid_key_length_raises(self):
        """Test that invalid key length raises ValueError."""
        with pytest.raises(ValueError, match="Key must be 16 bytes"):
            aes_gcm_encrypt(bytes(15), bytes(12), b"data", b"")

    def test_invalid_nonce_length_raises(self):
        """Test that invalid nonce length raises ValueError."""
        with pytest.raises(ValueError, match="Nonce must be 12 bytes"):
            aes_gcm_encrypt(bytes(16), bytes(11), b"data", b"")


class TestEcdh:
    """Tests for secp256k1 ECDH key agreement."""

    def test_ecdh_symmetric(self):
        """Test that ECDH produces the same shared secret for both parties."""
        priv_a, pub_a = generate_secp256k1_keypair()
        priv_b, pub_b = generate_secp256k1_keypair()

        secret_ab = ecdh_agree(priv_a, pub_b)
        secret_ba = ecdh_agree(priv_b, pub_a)

        assert secret_ab == secret_ba

    def test_ecdh_produces_32_byte_secret(self):
        """Test that ECDH produces a 32-byte shared secret."""
        priv_a, pub_a = generate_secp256k1_keypair()
        priv_b, pub_b = generate_secp256k1_keypair()

        secret = ecdh_agree(priv_a, pub_b)

        assert len(secret) == 32

    def test_different_keypairs_produce_different_secrets(self):
        """Test that different keypairs produce different shared secrets."""
        priv_a, pub_a = generate_secp256k1_keypair()
        priv_b, pub_b = generate_secp256k1_keypair()
        priv_c, pub_c = generate_secp256k1_keypair()

        secret_ab = ecdh_agree(priv_a, pub_b)
        secret_ac = ecdh_agree(priv_a, pub_c)

        assert secret_ab != secret_ac


class TestKeypairGeneration:
    """Tests for secp256k1 keypair generation."""

    def test_generates_32_byte_private_key(self):
        """Test that generated private key is 32 bytes."""
        priv, pub = generate_secp256k1_keypair()
        assert len(priv) == 32

    def test_generates_33_byte_compressed_public_key(self):
        """Test that generated public key is 33 bytes (compressed)."""
        priv, pub = generate_secp256k1_keypair()
        assert len(pub) == 33

    def test_public_key_starts_with_02_or_03(self):
        """Test that compressed public key has correct prefix."""
        priv, pub = generate_secp256k1_keypair()
        assert pub[0] in (0x02, 0x03)

    def test_generates_different_keys_each_time(self):
        """Test that each generation produces different keys."""
        priv1, pub1 = generate_secp256k1_keypair()
        priv2, pub2 = generate_secp256k1_keypair()

        assert priv1 != priv2
        assert pub1 != pub2


class TestPubkeyConversion:
    """Tests for public key format conversion."""

    def test_compressed_to_uncompressed_to_compressed(self):
        """Test roundtrip conversion."""
        _, compressed = generate_secp256k1_keypair()

        uncompressed = pubkey_to_uncompressed(compressed)
        recompressed = pubkey_to_compressed(uncompressed)

        assert recompressed == compressed

    def test_uncompressed_is_65_bytes(self):
        """Test that uncompressed format is 65 bytes."""
        _, compressed = generate_secp256k1_keypair()
        uncompressed = pubkey_to_uncompressed(compressed)

        assert len(uncompressed) == 65

    def test_uncompressed_starts_with_04(self):
        """Test that uncompressed format has 0x04 prefix."""
        _, compressed = generate_secp256k1_keypair()
        uncompressed = pubkey_to_uncompressed(compressed)

        assert uncompressed[0] == 0x04


def make_challenge_data(id_nonce: bytes = bytes(16)) -> bytes:
    """Build mock challenge_data for testing.

    Format: masking-iv (16) + static-header (23) + authdata (24) = 63 bytes.
    The authdata contains the id_nonce (16) + enr_seq (8).
    """
    masking_iv = bytes(16)
    # static-header: protocol-id (6) + version (2) + flag (1) + nonce (12) + authdata-size (2)
    static_header = b"discv5" + b"\x00\x01\x01" + bytes(12) + b"\x00\x18"
    # authdata: id-nonce (16) + enr-seq (8)
    authdata = id_nonce + bytes(8)
    return masking_iv + static_header + authdata


class TestIdNonceSignature:
    """Tests for ID nonce signing and verification."""

    def test_sign_and_verify(self):
        """Test that signature verifies correctly."""
        priv, pub = generate_secp256k1_keypair()
        challenge_data = make_challenge_data()
        dest_node_id = bytes(32)

        # Need a valid ephemeral pubkey.
        _, eph_pub = generate_secp256k1_keypair()

        signature = sign_id_nonce(priv, challenge_data, eph_pub, dest_node_id)

        assert verify_id_nonce_signature(signature, challenge_data, eph_pub, dest_node_id, pub)

    def test_signature_is_64_bytes(self):
        """Test that signature is 64 bytes (r || s)."""
        priv, _ = generate_secp256k1_keypair()
        _, eph_pub = generate_secp256k1_keypair()
        challenge_data = make_challenge_data()
        dest_node_id = bytes(32)

        signature = sign_id_nonce(priv, challenge_data, eph_pub, dest_node_id)

        assert len(signature) == 64

    def test_wrong_pubkey_fails_verification(self):
        """Test that verification fails with wrong public key."""
        priv, _ = generate_secp256k1_keypair()
        _, wrong_pub = generate_secp256k1_keypair()
        _, eph_pub = generate_secp256k1_keypair()
        challenge_data = make_challenge_data()
        dest_node_id = bytes(32)

        signature = sign_id_nonce(priv, challenge_data, eph_pub, dest_node_id)

        result = verify_id_nonce_signature(
            signature, challenge_data, eph_pub, dest_node_id, wrong_pub
        )
        assert not result

    def test_wrong_challenge_data_fails_verification(self):
        """Test that verification fails with wrong challenge data."""
        priv, pub = generate_secp256k1_keypair()
        _, eph_pub = generate_secp256k1_keypair()
        challenge_data = make_challenge_data()
        wrong_challenge_data = make_challenge_data(bytes.fromhex("01" + "00" * 15))
        dest_node_id = bytes(32)

        signature = sign_id_nonce(priv, challenge_data, eph_pub, dest_node_id)

        assert not verify_id_nonce_signature(
            signature, wrong_challenge_data, eph_pub, dest_node_id, pub
        )
