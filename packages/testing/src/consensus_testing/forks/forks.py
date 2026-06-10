"""Consensus fork definitions for test fixture generation."""

from consensus_testing.forks.base import BaseFork


class Lstar(BaseFork):
    """Lstar fork — base fork for the lean Ethereum protocol."""

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "Lstar"
