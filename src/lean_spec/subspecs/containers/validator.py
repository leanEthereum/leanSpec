"""Validator container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.types import Bytes52, Container

if TYPE_CHECKING:
    from ..xmss.containers import PublicKey as XmssPublicKey


class Validator(Container):
    """Represents a validator's static metadata."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    @classmethod
    def from_xmss_pubkey(cls, xmss_pubkey: XmssPublicKey) -> Validator:
        """
        Create a Validator from an XMSS public key.

        Args:
            xmss_pubkey: The XMSS public key.

        Returns:
            A Validator with the serialized XMSS public key.
        """
        return cls(pubkey=Bytes52(xmss_pubkey.to_bytes()))

    def get_xmss_pubkey(self) -> XmssPublicKey:
        """
        Get the XMSS public key from this validator.

        Returns:
            The XMSS public key.

        Raises:
            ValueError: If the public key cannot be deserialized.
        """
        return XmssPublicKey.from_bytes(bytes(self.pubkey))
