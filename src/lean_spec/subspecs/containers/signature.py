"""Signature container."""

from __future__ import annotations

from lean_spec.types import Bytes3100


class Signature(Bytes3100):
    """Represents aggregated signature produced by the leanVM (SNARKs in the future)."""

    @staticmethod
    def is_valid(signature: Signature) -> bool:
        """Return True when the placeholder signature is the zero value."""
        # TODO: Replace placeholder check once aggregated signatures are
        # wired in as part of the multi-proof integration work.
        return signature == Signature.zero()

    @classmethod
    def zero(cls) -> Signature:
        """Return the zero (placeholder) signature."""
        return cls(Bytes3100.zero())
