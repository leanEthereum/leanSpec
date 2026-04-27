"""Consensus fork definitions for test fixture generation."""

from framework.forks import BaseFork

from lean_spec.forks.lstar.spec import LstarSpec


class Lstar(BaseFork):
    """Lstar fork — base fork for the lean Ethereum protocol."""

    @classmethod
    def name(cls) -> str:
        """Return the fork name."""
        return "Lstar"

    @classmethod
    def spec_class(cls) -> type[LstarSpec]:
        """Return the ForkProtocol implementation for this fork."""
        return LstarSpec

    @classmethod
    def state_class(cls) -> type:
        """Return the State container class for this fork."""
        return LstarSpec.state_class
