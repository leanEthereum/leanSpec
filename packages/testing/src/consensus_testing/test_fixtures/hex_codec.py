"""Shared 0x-prefixed hex codec for test fixtures."""


def to_hex(data: bytes) -> str:
    """Format raw bytes as a 0x-prefixed hex string."""
    return "0x" + data.hex()


def from_hex(hex_string: str) -> bytes:
    """Decode a 0x-prefixed hex string to bytes."""
    return bytes.fromhex(hex_string.removeprefix("0x"))
