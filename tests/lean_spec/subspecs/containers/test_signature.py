"""Tests for consensus Signature container."""

import pytest

from lean_spec.subspecs.containers import Signature
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.constants import TEST_CONFIG
from lean_spec.subspecs.xmss.containers import HashTreeOpening
from lean_spec.subspecs.xmss.containers import Signature as XmssSignature
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME


class TestSignatureFromXmss:
    """Tests for Signature.from_xmss conversion method."""

    def test_from_xmss_basic_conversion(self) -> None:
        """Test that from_xmss correctly converts an XMSS signature to consensus format."""
        # Create a valid XMSS signature
        path = HashTreeOpening(
            siblings=[[Fp(value=i) for i in range(TEST_CONFIG.HASH_LEN_FE)]]
            * TEST_CONFIG.LOG_LIFETIME
        )
        rho = [Fp(value=i) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        hashes = [
            [Fp(value=i + j) for i in range(TEST_CONFIG.HASH_LEN_FE)]
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        xmss_sig = XmssSignature(path=path, rho=rho, hashes=hashes)

        # Convert to consensus signature
        consensus_sig = Signature.from_xmss(xmss_sig, TEST_SIGNATURE_SCHEME)

        # Verify it's the correct type and length
        assert isinstance(consensus_sig, Signature)
        assert len(consensus_sig) == Signature.LENGTH



    def test_from_xmss_preserves_data(self) -> None:
        """Test that from_xmss preserves the XMSS signature data."""
        # Create an XMSS signature with distinct values
        path = HashTreeOpening(
            siblings=[
                [Fp(value=i * j) for i in range(TEST_CONFIG.HASH_LEN_FE)]
                for j in range(TEST_CONFIG.LOG_LIFETIME)
            ]
        )
        rho = [Fp(value=i * 10) for i in range(TEST_CONFIG.RAND_LEN_FE)]
        hashes = [
            [Fp(value=i + j * 100) for i in range(TEST_CONFIG.HASH_LEN_FE)]
            for j in range(TEST_CONFIG.DIMENSION)
        ]
        xmss_sig = XmssSignature(path=path, rho=rho, hashes=hashes)

        # Convert to consensus format
        consensus_sig = Signature.from_xmss(xmss_sig, TEST_SIGNATURE_SCHEME)

        # The beginning of the consensus signature should match the XMSS bytes
        raw_xmss = xmss_sig.to_bytes(TEST_CONFIG)
        assert bytes(consensus_sig)[: len(raw_xmss)] == raw_xmss

    def test_from_xmss_roundtrip_with_verify(self) -> None:
        """Test that a signature created via from_xmss can be verified."""
        from lean_spec.types import Uint64

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


