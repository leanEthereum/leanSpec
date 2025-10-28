"""Signature container."""

from __future__ import annotations

from lean_spec.types import Bytes4000


class Signature(Bytes4000):
    """Represents aggregated signature produced by the leanVM (SNARKs in the future)."""

    @staticmethod
    def _is_valid_signature(signature: Bytes4000) -> bool:
        """Return True when the placeholder signature is the zero value."""
        # TODO: Replace placeholder check once aggregated signatures are
        # wired in as part of the multi-proof integration work.
        return signature == Bytes4000.zero()

    @classmethod
    def zero(cls) -> Signature:
        """Return the zero (placeholder) signature."""
        return cls(Bytes4000.zero())
