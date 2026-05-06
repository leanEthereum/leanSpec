"""Test vectors for Discovery v5 cryptographic primitives.

These vectors use official devp2p specification key material so that
client teams can verify their ECDH, HKDF, signing, and encryption
implementations against a known reference.

Reference:
    https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
"""

import pytest
from consensus_testing import DiscoveryCryptoTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

# Official devp2p spec key material.
NODE_A_PRIVKEY = "0xeef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
NODE_A_PUBKEY = "0x0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
NODE_A_ID = "0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"

NODE_B_PRIVKEY = "0x66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
NODE_B_PUBKEY = "0x0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
NODE_B_ID = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"

SPEC_EPHEMERAL_KEY = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
SPEC_EPHEMERAL_PUBKEY = "0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"

SPEC_CHALLENGE_DATA = (
    "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c"
    "00180102030405060708090a0b0c0d0e0f100000000000000000"
)

# Pre-computed signature for NODE_A signing with SPEC_CHALLENGE_DATA.
SPEC_SIGNATURE = (
    "0xe622b72727fd64529187b6e4f7241caadac052f840122474d91de305f7bb5cc4"
    "5d0457b5f6ba72c8bbc82480dea2e2cd3eabca6984f6bd7bd3b54a80fe749fa6"
)


# --- ECDH ---


def test_ecdh_node_a_to_b(discovery_crypto: DiscoveryCryptoTestFiller) -> None:
    """ECDH(A_priv, B_pub) produces deterministic shared secret."""
    discovery_crypto(
        operation="ecdh",
        input={"privateKey": NODE_A_PRIVKEY, "publicKey": NODE_B_PUBKEY},
    )


def test_ecdh_node_b_to_a(discovery_crypto: DiscoveryCryptoTestFiller) -> None:
    """ECDH(B_priv, A_pub) must equal ECDH(A_priv, B_pub) (symmetry)."""
    discovery_crypto(
        operation="ecdh",
        input={"privateKey": NODE_B_PRIVKEY, "publicKey": NODE_A_PUBKEY},
    )


def test_ecdh_ephemeral_to_b(discovery_crypto: DiscoveryCryptoTestFiller) -> None:
    """ECDH with spec ephemeral key and Node B. Used in handshake key derivation."""
    discovery_crypto(
        operation="ecdh",
        input={"privateKey": SPEC_EPHEMERAL_KEY, "publicKey": NODE_B_PUBKEY},
    )


# --- Key derivation ---


def test_key_derivation_spec_vector(
    discovery_crypto: DiscoveryCryptoTestFiller,
) -> None:
    """HKDF key derivation with official spec challenge data."""
    # Shared secret from ECDH(ephemeral, B_pub).
    shared_secret = "0x022c82f214eb37159111712add00040fcdf73fd4d7d0b7c0f980da4d099aa59ba4"
    discovery_crypto(
        operation="key_derivation",
        input={
            "sharedSecret": shared_secret,
            "initiatorId": NODE_A_ID,
            "recipientId": NODE_B_ID,
            "challengeData": SPEC_CHALLENGE_DATA,
        },
    )


# --- ID nonce signing ---


def test_id_nonce_sign_spec_vector(
    discovery_crypto: DiscoveryCryptoTestFiller,
) -> None:
    """Sign ID nonce with Node A's key and spec challenge data."""
    discovery_crypto(
        operation="id_nonce_sign",
        input={
            "privateKey": NODE_A_PRIVKEY,
            "challengeData": SPEC_CHALLENGE_DATA,
            "ephemeralPubkey": SPEC_EPHEMERAL_PUBKEY,
            "destNodeId": NODE_B_ID,
        },
    )


# --- ID nonce verification ---


def test_id_nonce_verify_valid(discovery_crypto: DiscoveryCryptoTestFiller) -> None:
    """Verify valid signature from Node A."""
    discovery_crypto(
        operation="id_nonce_verify",
        input={
            "signature": SPEC_SIGNATURE,
            "challengeData": SPEC_CHALLENGE_DATA,
            "ephemeralPubkey": SPEC_EPHEMERAL_PUBKEY,
            "destNodeId": NODE_B_ID,
            "publicKey": NODE_A_PUBKEY,
        },
    )


def test_id_nonce_verify_wrong_pubkey(
    discovery_crypto: DiscoveryCryptoTestFiller,
) -> None:
    """Verification fails with wrong public key (Node B instead of A)."""
    discovery_crypto(
        operation="id_nonce_verify",
        input={
            "signature": SPEC_SIGNATURE,
            "challengeData": SPEC_CHALLENGE_DATA,
            "ephemeralPubkey": SPEC_EPHEMERAL_PUBKEY,
            "destNodeId": NODE_B_ID,
            "publicKey": NODE_B_PUBKEY,
        },
    )


def test_id_nonce_verify_wrong_challenge(
    discovery_crypto: DiscoveryCryptoTestFiller,
) -> None:
    """Verification fails with different challenge data."""
    wrong_challenge = "0x" + "ff" * 63
    discovery_crypto(
        operation="id_nonce_verify",
        input={
            "signature": SPEC_SIGNATURE,
            "challengeData": wrong_challenge,
            "ephemeralPubkey": SPEC_EPHEMERAL_PUBKEY,
            "destNodeId": NODE_B_ID,
            "publicKey": NODE_A_PUBKEY,
        },
    )


# --- AES-GCM ---


def test_aes_gcm_encrypt_spec_ping(
    discovery_crypto: DiscoveryCryptoTestFiller,
) -> None:
    """AES-GCM encrypt a PING message with spec key and nonce."""
    discovery_crypto(
        operation="aes_gcm_encrypt",
        input={
            "key": "0x9f2d77db7004bf8a1a85107ac686990b",
            "nonce": "0x27b5af763c446acd2749fe8e",
            "plaintext": "0x01c20101",
            "aad": "0x",
        },
    )


def test_aes_gcm_encrypt_empty_plaintext(
    discovery_crypto: DiscoveryCryptoTestFiller,
) -> None:
    """AES-GCM with empty plaintext. Output is just the 16-byte auth tag."""
    discovery_crypto(
        operation="aes_gcm_encrypt",
        input={
            "key": "0x9f2d77db7004bf8a1a85107ac686990b",
            "nonce": "0x27b5af763c446acd2749fe8e",
            "plaintext": "0x",
            "aad": "0x",
        },
    )


def test_aes_gcm_encrypt_with_aad(
    discovery_crypto: DiscoveryCryptoTestFiller,
) -> None:
    """AES-GCM with additional authenticated data (packet header)."""
    discovery_crypto(
        operation="aes_gcm_encrypt",
        input={
            "key": "0x9f2d77db7004bf8a1a85107ac686990b",
            "nonce": "0x27b5af763c446acd2749fe8e",
            "plaintext": "0x01c20101",
            "aad": "0x0102030405060708090a0b0c0d0e0f10",
        },
    )


# --- Node ID ---


def test_node_id_from_node_a(discovery_crypto: DiscoveryCryptoTestFiller) -> None:
    """Compute Node A's ID from its compressed public key."""
    discovery_crypto(
        operation="node_id",
        input={"publicKey": NODE_A_PUBKEY},
    )


def test_node_id_from_node_b(discovery_crypto: DiscoveryCryptoTestFiller) -> None:
    """Compute Node B's ID from its compressed public key."""
    discovery_crypto(
        operation="node_id",
        input={"publicKey": NODE_B_PUBKEY},
    )
