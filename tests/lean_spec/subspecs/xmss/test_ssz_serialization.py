"""Tests for SSZ serialization of XMSS types."""

from lean_spec.subspecs.xmss.constants import TEST_CONFIG
from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME
from lean_spec.types import Bytes32, Uint64


def test_public_key_ssz_roundtrip() -> None:
    """Test that PublicKey can be SSZ serialized and deserialized."""
    # Generate a key pair
    activation_epoch = Uint64(0)
    num_active_epochs = Uint64(32)
    public_key, secret_key = TEST_SIGNATURE_SCHEME.key_gen(activation_epoch, num_active_epochs)

    # Serialize to bytes using SSZ
    pk_bytes = public_key.encode_bytes()

    # Deserialize from bytes
    recovered_pk = PublicKey.decode_bytes(pk_bytes)

    # Verify the recovered public key matches the original
    assert recovered_pk.root == public_key.root
    assert recovered_pk.parameter == public_key.parameter
    assert recovered_pk == public_key


def test_signature_ssz_roundtrip() -> None:
    """Test that Signature can be SSZ serialized and deserialized."""
    # Generate a key pair and sign a message
    activation_epoch = Uint64(0)
    num_active_epochs = Uint64(32)
    public_key, secret_key = TEST_SIGNATURE_SCHEME.key_gen(activation_epoch, num_active_epochs)

    message = Bytes32(bytes([42] * 32))
    epoch = Uint64(0)
    signature = TEST_SIGNATURE_SCHEME.sign(secret_key, epoch, message)

    # Serialize to bytes using SSZ
    sig_bytes = signature.encode_bytes()

    # Deserialize from bytes
    recovered_sig = Signature.decode_bytes(sig_bytes)

    # Verify the recovered signature matches the original
    assert recovered_sig.path.siblings == signature.path.siblings
    assert recovered_sig.rho == signature.rho
    assert recovered_sig.hashes == signature.hashes
    assert recovered_sig == signature

    # Verify the signature still verifies
    assert TEST_SIGNATURE_SCHEME.verify(public_key, epoch, message, recovered_sig)


def test_secret_key_ssz_roundtrip() -> None:
    """Test that SecretKey can be SSZ serialized and deserialized."""
    # Generate a key pair
    activation_epoch = Uint64(0)
    num_active_epochs = Uint64(32)
    public_key, secret_key = TEST_SIGNATURE_SCHEME.key_gen(activation_epoch, num_active_epochs)

    # Serialize to bytes using SSZ
    sk_bytes = secret_key.encode_bytes()

    # Deserialize from bytes
    from lean_spec.subspecs.xmss.containers import SecretKey

    recovered_sk = SecretKey.decode_bytes(sk_bytes)

    # Verify the recovered secret key matches the original
    assert recovered_sk.prf_key == secret_key.prf_key
    assert recovered_sk.parameter == secret_key.parameter
    assert recovered_sk.activation_epoch == secret_key.activation_epoch
    assert recovered_sk.num_active_epochs == secret_key.num_active_epochs
    assert recovered_sk.top_tree == secret_key.top_tree
    assert recovered_sk.left_bottom_tree_index == secret_key.left_bottom_tree_index
    assert recovered_sk.left_bottom_tree == secret_key.left_bottom_tree
    assert recovered_sk.right_bottom_tree == secret_key.right_bottom_tree
    assert recovered_sk == secret_key

    # Verify the recovered secret key can still sign
    message = Bytes32(bytes([99] * 32))
    epoch = Uint64(1)
    signature = TEST_SIGNATURE_SCHEME.sign(recovered_sk, epoch, message)
    assert TEST_SIGNATURE_SCHEME.verify(public_key, epoch, message, signature)


def test_deterministic_serialization() -> None:
    """Test that serialization is deterministic."""
    # Generate a key pair
    activation_epoch = Uint64(0)
    num_active_epochs = Uint64(32)
    public_key, secret_key = TEST_SIGNATURE_SCHEME.key_gen(activation_epoch, num_active_epochs)

    # Serialize multiple times
    pk_bytes1 = public_key.encode_bytes()
    pk_bytes2 = public_key.encode_bytes()
    sk_bytes1 = secret_key.encode_bytes()
    sk_bytes2 = secret_key.encode_bytes()

    # Verify serialization is deterministic
    assert pk_bytes1 == pk_bytes2
    assert sk_bytes1 == sk_bytes2

    # Sign a message multiple times with deterministic randomness
    message = Bytes32(bytes([42] * 32))
    epoch = Uint64(0)
    sig1 = TEST_SIGNATURE_SCHEME.sign(secret_key, epoch, message)
    sig2 = TEST_SIGNATURE_SCHEME.sign(secret_key, epoch, message)

    # Signatures should be identical (deterministic signing)
    assert sig1 == sig2

    sig_bytes1 = sig1.encode_bytes()
    sig_bytes2 = sig2.encode_bytes()
    assert sig_bytes1 == sig_bytes2


def test_signature_size_matches_config() -> None:
    """Verify SIGNATURE_LEN_BYTES matches actual SSZ-encoded size."""
    activation_epoch = Uint64(0)
    num_active_epochs = Uint64(32)
    public_key, secret_key = TEST_SIGNATURE_SCHEME.key_gen(activation_epoch, num_active_epochs)

    message = Bytes32(bytes([42] * 32))
    epoch = Uint64(0)
    signature = TEST_SIGNATURE_SCHEME.sign(secret_key, epoch, message)

    encoded = signature.encode_bytes()
    assert len(encoded) == TEST_CONFIG.SIGNATURE_LEN_BYTES


def test_public_key_size_matches_config() -> None:
    """Verify PUBLIC_KEY_LEN_BYTES matches actual SSZ-encoded size."""
    activation_epoch = Uint64(0)
    num_active_epochs = Uint64(32)
    public_key, _ = TEST_SIGNATURE_SCHEME.key_gen(activation_epoch, num_active_epochs)

    encoded = public_key.encode_bytes()
    assert len(encoded) == TEST_CONFIG.PUBLIC_KEY_LEN_BYTES
