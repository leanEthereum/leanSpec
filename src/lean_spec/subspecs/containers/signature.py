"""Signature container."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.types import Bytes3100

if TYPE_CHECKING:
    from ..xmss.constants import SIGNATURE_PADDING_LENGTH
    from ..xmss.containers import PublicKey
    from ..xmss.containers import Signature as XmssSignature
    from ..xmss.interface import PROD_SIGNATURE_SCHEME, TEST_SIGNATURE_SCHEME


class Signature(Bytes3100):
    """Represents aggregated signature produced by the leanVM (SNARKs in the future)."""

    @classmethod
    def from_xmss(cls, xmss_sig: XmssSignature) -> Signature:
        """
        Create a protocol Signature from an XMSS signature.

        Args:
            xmss_sig: The XMSS signature to convert.

        Returns:
            A protocol Signature containing the serialized XMSS signature.
        """
        return cls(xmss_sig.to_bytes())

    def to_xmss(self) -> XmssSignature:
        """
        Convert this protocol Signature to an XMSS signature.

        Returns:
            The XMSS signature.

        Raises:
            ValueError: If the signature cannot be deserialized.
        """
        return XmssSignature.from_bytes(bytes(self))

    def verify(
        self,
        public_key: PublicKey,
        epoch: int,
        message: bytes,
    ) -> bool:
        """
        Verify this signature using XMSS verification.

        Args:
            public_key: XMSS public key for verification.
            epoch: Epoch number for the signature.
            message: Message that was signed.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            xmss_sig = self.to_xmss()
            # check padding
            if bytes(self)[-SIGNATURE_PADDING_LENGTH:] == b"\x00" * SIGNATURE_PADDING_LENGTH:
                signature_scheme = TEST_SIGNATURE_SCHEME
            else:
                signature_scheme = PROD_SIGNATURE_SCHEME
            return signature_scheme.verify(public_key, epoch, message, xmss_sig)
        except ValueError:
            # Signature deserialization failed
            return False
