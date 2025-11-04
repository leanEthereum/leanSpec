"""Validator container for the Lean Ethereum consensus specification."""

from lean_spec.runtime_config import USE_TEST_SCHEME
from lean_spec.types import Bytes52, Container

from ..xmss.containers import PublicKey
from ..xmss.interface import PROD_SIGNATURE_SCHEME, TEST_SIGNATURE_SCHEME


class Validator(Container):
    """Represents a validator's static metadata."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    def get_pubkey(self) -> PublicKey:
        """Get the XMSS public key from this validator."""
        if USE_TEST_SCHEME:
            scheme = TEST_SIGNATURE_SCHEME
        else:
            scheme = PROD_SIGNATURE_SCHEME

        return PublicKey.from_bytes(bytes(self.pubkey), scheme.config)
