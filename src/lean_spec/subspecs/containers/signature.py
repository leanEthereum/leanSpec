"""Signature container."""

from __future__ import annotations

from lean_spec.types import Bytes3100

from ..xmss.containers import PublicKey
from ..xmss.containers import Signature as XmssSignature
from ..xmss.interface import DEFAULT_SIGNATURE_SCHEME


class Signature(Bytes3100):
    """Represents aggregated signature produced by the leanVM (SNARKs in the future)."""

    def verify(self, public_key: PublicKey, epoch: int, message: bytes) -> bool:
        """Verify the signature using XMSS verification algorithm."""
        try:
            scheme = DEFAULT_SIGNATURE_SCHEME
            # Signature container is always 3100 bytes, but scheme config may expect less.
            # Slice to the expected size if needed, assumes padding to the right.
            signature_data = bytes(self)[: scheme.config.SIGNATURE_LEN_BYTES]
            signature = XmssSignature.from_bytes(signature_data, scheme.config)
            return scheme.verify(public_key, epoch, message, signature)
        except Exception:
            return False
