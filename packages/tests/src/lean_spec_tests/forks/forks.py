"""Devnet fork definition."""

from .base import BaseFork


class Devnet(BaseFork):
    """
    Devnet fork for lean Ethereum consensus layer.

    This is the initial fork for the lean Ethereum protocol.
    """

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "Devnet"
