"""Validator container for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes52, Container


class Validator(Container):
    """Represents a validator's static metadata."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""
