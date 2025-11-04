"""Signature container."""

from __future__ import annotations

from lean_spec.runtime_config import USE_TEST_SCHEME
from lean_spec.types import Bytes3100

from ..xmss.containers import PublicKey
from ..xmss.containers import Signature as XmssSignature
from ..xmss.interface import PROD_SIGNATURE_SCHEME, TEST_SIGNATURE_SCHEME


class Signature(Bytes3100):
    """Represents aggregated signature produced by the leanVM (SNARKs in the future)."""

    def verify(self, public_key: PublicKey, epoch: int, message: bytes) -> bool:
        """Verify the signature using XMSS verification algorithm."""
        try:
            if USE_TEST_SCHEME:
                scheme = TEST_SIGNATURE_SCHEME
                # TEST_CONFIG expects 796 bytes, but Signature is always 3100 bytes.
                # Slice to the expected size for test config, assumes padding to the right.
                signature_data = bytes(self)[: scheme.config.SIGNATURE_LEN_BYTES]
                signature = XmssSignature.from_bytes(signature_data, scheme.config)
            else:
                scheme = PROD_SIGNATURE_SCHEME
                signature = XmssSignature.from_bytes(bytes(self), scheme.config)
            return bool(scheme.verify(public_key, epoch, message, signature))
        except Exception:
            return False
