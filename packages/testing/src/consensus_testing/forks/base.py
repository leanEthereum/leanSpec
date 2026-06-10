"""Base fork class for spec test generation."""

from abc import ABC, ABCMeta, abstractmethod


class BaseForkMeta(ABCMeta):
    """
    Metaclass for BaseFork enabling fork ordering via inheritance.

    Fork ordering works by checking subclass relationships.
    For example, if ForkB inherits from ForkA, then ForkA precedes ForkB.
    """

    def __repr__(cls: "type[BaseFork]") -> str:
        """Print the name of the fork, instead of the class."""
        return cls.name()

    def __le__(cls: "type[BaseFork]", other: "type[BaseFork]") -> bool:
        """Check if this fork is older or equal to another (cls <= other)."""
        return cls is other or issubclass(other, cls)


class BaseFork(ABC, metaclass=BaseForkMeta):
    """
    Base class for spec test forks.

    Each fork represents a specific version of the protocol.
    Forks form an inheritance hierarchy where newer forks inherit from older ones.
    """

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """
        Return the name of the fork as it appears in test fixtures.

        By default, this is the class name (e.g., "Lstar" for consensus).
        This is used in the 'network' field of generated fixtures.
        """
        pass
