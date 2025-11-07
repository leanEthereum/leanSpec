"""Validator container for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes52, Container

from ..xmss.containers import PublicKey
from ..xmss.interface import DEFAULT_SIGNATURE_SCHEME


class Validator(Container):
    """Represents a validator's static metadata."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    def get_pubkey(self) -> PublicKey:
        """Get the XMSS public key from this validator."""
        return PublicKey.from_bytes(bytes(self.pubkey), DEFAULT_SIGNATURE_SCHEME.config)
