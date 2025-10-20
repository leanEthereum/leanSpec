"""Base fork class for consensus layer testing."""

from abc import ABC, ABCMeta, abstractmethod
from typing import ClassVar, Set, Type


class BaseForkMeta(ABCMeta):
    """
    Metaclass for BaseFork enabling fork comparisons via inheritance.

    Fork comparisons work by checking subclass relationships.
    For example, if ForkB inherits from ForkA, then ForkA < ForkB.
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
        """
        Check if fork `a` is a subclass of fork `b`.

        For transition forks, checks if the destination fork is a subclass.
        """
        # Handle transition forks by checking their destination
        a = BaseForkMeta._maybe_transitioned(a)
        b = BaseForkMeta._maybe_transitioned(b)
        return issubclass(a, b)

    @staticmethod
    def _maybe_transitioned(fork_cls: "BaseForkMeta") -> "BaseForkMeta":
        """
        Return the destination fork if this is a transition fork. Otherwise,
        return the fork as-is.
        """
        if hasattr(fork_cls, "transitions_to"):
            return fork_cls.transitions_to()  # type: ignore[no-any-return]
        return fork_cls


class BaseFork(ABC, metaclass=BaseForkMeta):
    """
    Base class for consensus layer forks.

    Each fork represents a specific version of the consensus layer protocol.
    Forks form an inheritance hierarchy where newer forks inherit from older ones.
    """

    # Fork metadata
    _ignore: ClassVar[bool] = False
    """If True, this fork will be excluded from the primary fork set."""

    _children: ClassVar[Set[Type["BaseFork"]]] = set()
    """Set of forks that directly inherit from this fork."""

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
        cls._children = set()

        # Track parent-child relationships
        base_class = cls.__bases__[0]
        if base_class != BaseFork and hasattr(base_class, "_children"):
            base_class._children.add(cls)

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """
        Return the name of the fork as it appears in test fixtures.

        By default, this is the class name (e.g., "Devnet").
        This is used in the 'network' field of generated fixtures.
        """
        pass

    @classmethod
    def ignore(cls) -> bool:
        """Return whether this fork should be ignored in test generation."""
        return cls._ignore

    @classmethod
    def __str__(cls) -> str:
        """Return string representation of the fork."""
        return cls.name()

    @classmethod
    def __repr__(cls) -> str:
        """Return repr of the fork."""
        return f"Fork({cls.name()})"
