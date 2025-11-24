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

    @classmethod
    def from_xmss(
        cls, xmss_signature: XmssSignature, scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME
    ) -> Signature:
        """
        Create a consensus `Signature` container from an XMSS signature object.

        Applies the consensus-layer fixed-length padding, delegating all encoding
        details to the XMSS container itself.
        """
        raw = xmss_signature.to_bytes(scheme.config)
        if len(raw) > cls.LENGTH:
            raise ValueError(
                f"XMSS signature length {len(raw)} exceeds container size {cls.LENGTH}"
            )

        # Pad on the right to the fixed-length container expected by consensus.
        return cls(raw.ljust(cls.LENGTH, b"\x00"))
