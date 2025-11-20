"""Tests for consensus Signature container."""

from lean_spec.subspecs.containers import Signature
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME
from lean_spec.types import Uint64


class TestSignatureFromXmss:
    """Tests for Signature.from_xmss conversion method."""

    def test_from_xmss_roundtrip_with_verify(self) -> None:
        """Test that a signature created via from_xmss can be verified."""

        # Generate a test key pair
        pk, sk = TEST_SIGNATURE_SCHEME.key_gen(Uint64(0), Uint64(10))

        # Create a test message (must be exactly 32 bytes)
        message = b"test message for signing123456\x00\x00"  # 32 bytes
        assert len(message) == 32
        epoch = Uint64(0)

        # Sign the message
        xmss_sig = TEST_SIGNATURE_SCHEME.sign(sk, epoch, message)

        # Convert to consensus signature
        consensus_sig = Signature.from_xmss(xmss_sig, TEST_SIGNATURE_SCHEME)

        # Verify using the consensus signature's verify method
        assert consensus_sig.verify(pk, epoch, message, TEST_SIGNATURE_SCHEME)
