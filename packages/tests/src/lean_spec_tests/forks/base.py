"""Base fork class for consensus layer testing."""

from abc import ABC, abstractmethod


class BaseFork(ABC):
    """
    Base class for consensus layer forks.

    Each fork represents a specific version of the consensus layer protocol.
    """

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """
        Return the name of the fork as it appears in test fixtures.

        This is used in the 'network' field of generated fixtures.
        """
        pass

    @classmethod
    def __str__(cls) -> str:
        """Return string representation of the fork."""
        return cls.name()

    @classmethod
    def __repr__(cls) -> str:
        """Return repr of the fork."""
        return f"Fork({cls.name()})"
