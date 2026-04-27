"""Base fork class for Ethereum layer testing."""

from abc import ABC, ABCMeta, abstractmethod
from typing import ClassVar


class BaseForkMeta(ABCMeta):
    """
    Metaclass for BaseFork enabling fork comparisons via inheritance.

    Fork comparisons work by checking subclass relationships.
    For example, if ForkB inherits from ForkA, then ForkA < ForkB.

    This metaclass is shared across both consensus and execution layers,
    allowing consistent fork comparison logic regardless of layer.
    """

    @abstractmethod
    def name(cls) -> str:
        """Return the name of the fork."""
        pass

    def __repr__(cls) -> str:
        """Print the name of the fork, instead of the class."""
        return cls.name()

    def __gt__(cls, other: "BaseForkMeta") -> bool:
        """Check if this fork is newer than another (cls > other)."""
        return cls is not other and BaseForkMeta._is_subclass_of(cls, other)

    def __ge__(cls, other: "BaseForkMeta") -> bool:
        """Check if this fork is newer or equal to another (cls >= other)."""
        return cls is other or BaseForkMeta._is_subclass_of(cls, other)

    def __lt__(cls, other: "BaseForkMeta") -> bool:
        """Check if this fork is older than another (cls < other)."""
        return cls is not other and BaseForkMeta._is_subclass_of(other, cls)

    def __le__(cls, other: "BaseForkMeta") -> bool:
        """Check if this fork is older or equal to another (cls <= other)."""
        return cls is other or BaseForkMeta._is_subclass_of(other, cls)

    @staticmethod
    def _is_subclass_of(a: "BaseForkMeta", b: "BaseForkMeta") -> bool:
        """Check if fork `a` is a subclass of fork `b`."""
        return issubclass(a, b)


class BaseFork(ABC, metaclass=BaseForkMeta):
    """
    Base class for Ethereum layer forks.

    Each fork represents a specific version of the protocol (consensus or execution).
    Forks form an inheritance hierarchy where newer forks inherit from older ones.

    This base class is shared across both consensus and execution layers, but each
    layer will define its own fork hierarchy with different fork names and properties.
    """

    # Fork metadata
    _ignore: ClassVar[bool] = False
    """If True, this fork will be excluded from the primary fork set."""

    def __init_subclass__(
        cls,
        *,
        ignore: bool = False,
    ) -> None:
        """
        Initialize fork subclass with metadata.

        Args:
            ignore: If True, exclude this fork from ALL_FORKS.
        """
        super().__init_subclass__()
        cls._ignore = ignore

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """
        Return the name of the fork as it appears in test fixtures.

        By default, this is the class name (e.g., "Lstar" for consensus,
        "Shanghai" for execution).
        This is used in the 'network' field of generated fixtures.
        """
        pass

    @classmethod
    def ignore(cls) -> bool:
        """Return whether this fork should be ignored in test generation."""
        return cls._ignore
