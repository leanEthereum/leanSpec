"""
ENR Key Constants (EIP-778)

ENR keys can be any byte sequence, but ASCII text is preferred.

These constants define pre-defined keys with standard meanings.

See: https://eips.ethereum.org/EIPS/eip-778
"""

from typing import Final

EnrKey = str
"""Type alias for ENR keys (can be any string/bytes per EIP-778)"""

# EIP-778 Standard Keys
ID: Final[EnrKey] = "id"
"""Identity scheme name. Required. Currently only "v4" is defined."""

SECP256K1: Final[EnrKey] = "secp256k1"
"""Compressed secp256k1 public key (33 bytes). Required for "v4" scheme."""

IP: Final[EnrKey] = "ip"
"""IPv4 address (4 bytes)."""

TCP: Final[EnrKey] = "tcp"
"""TCP port (big-endian integer)."""

UDP: Final[EnrKey] = "udp"
"""UDP port for discovery (big-endian integer)."""

IP6: Final[EnrKey] = "ip6"
"""IPv6 address (16 bytes)."""

TCP6: Final[EnrKey] = "tcp6"
"""IPv6-specific TCP port."""

UDP6: Final[EnrKey] = "udp6"
"""IPv6-specific UDP port."""

# Ethereum Consensus Extensions
ETH2: Final[EnrKey] = "eth2"
"""Ethereum consensus fork data (16 bytes)."""

ATTNETS: Final[EnrKey] = "attnets"
"""Attestation subnet subscriptions (8 bytes bitvector)."""

SYNCNETS: Final[EnrKey] = "syncnets"
"""Sync committee subnet subscriptions (1 byte bitvector)."""

IS_AGGREGATOR: Final[EnrKey] = "is_aggregator"
"""Aggregator capability flag (1 byte: 0x00 = false, 0x01 = true)."""
