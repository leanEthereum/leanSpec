"""Byte Type"""

from .uint import Uint8


class Byte(Uint8):
    """
    The `byte` type, represented as a subclass of `Uint8`.

    While it has the same serialization and validation rules as `Uint8`,
    this distinct type allows for semantic differentiation between opaque
    byte data and a numerical `uint8` value.
    """

    def __repr__(self) -> str:
        """Return the official string representation as a hex value."""
        return f"Byte({hex(self)})"
