"""Signature container."""

from __future__ import annotations

from lean_spec.types import Bytes3116, Uint64

from ..xmss.containers import PublicKey
from ..xmss.containers import Signature as XmssSignature
from ..xmss.interface import TEST_SIGNATURE_SCHEME, GeneralizedXmssScheme


class Signature(Bytes3116):
    """Represents aggregated signature produced by the leanVM (SNARKs in the future)."""

    def verify(
        self,
        public_key: PublicKey,
        epoch: Uint64,
        message: bytes,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
    ) -> bool:
        """Verify the signature using XMSS verification algorithm."""
        try:
            # Signature container is always 3116 bytes, but scheme config may expect less.
            # Slice to the expected size if needed, assumes padding to the right.
            signature_data = bytes(self)[: scheme.config.SIGNATURE_LEN_BYTES]
            signature = XmssSignature.from_bytes(signature_data, scheme.config)
            return scheme.verify(public_key, epoch, message, signature)
        except Exception:
            return False
