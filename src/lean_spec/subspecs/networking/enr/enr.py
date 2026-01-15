"""
Ethereum Node Record (EIP-778)
==============================

ENR is an open format for p2p connectivity information that improves upon
the node discovery v4 protocol by providing:

1. **Flexibility**: Arbitrary key/value pairs for any transport protocol
2. **Cryptographic Agility**: Support for multiple identity schemes
3. **Authoritative Updates**: Sequence numbers to determine record freshness

Record Structure
----------------

An ENR is an RLP-encoded list::

    record = [signature, seq, k1, v1, k2, v2, ...]

Where:
- `signature`: 64-byte secp256k1 signature (r || s, no recovery id)
- `seq`: 64-bit sequence number (increases on each update)
- `k, v`: Sorted key/value pairs (keys are lexicographically ordered)

The signature covers the content `[seq, k1, v1, k2, v2, ...]` (excluding itself).

Size Limit
----------

Maximum encoded size is **300 bytes**. This ensures ENRs fit in a single
UDP packet and can be included in size-constrained protocols like DNS.

Text Encoding
-------------

Text form is URL-safe base64 with `enr:` prefix::

    enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjz...

"v4" Identity Scheme
--------------------

The default scheme uses secp256k1:
- **Sign**: keccak256(content), then secp256k1 signature
- **Verify**: Check signature against `secp256k1` key in record
- **Node ID**: keccak256(uncompressed_public_key)

References:
----------
- EIP-778: https://eips.ethereum.org/EIPS/eip-778
"""

from typing import ClassVar

from lean_spec.subspecs.networking.types import Multiaddr, NodeId, SeqNumber
from lean_spec.types import StrictBaseModel

from . import keys
from .eth2 import AttestationSubnets, Eth2Data
from .keys import EnrKey


class ENR(StrictBaseModel):
    r"""
    Ethereum Node Record (EIP-778).

    Example from EIP-778 (IPv4 127.0.0.1, UDP 30303)::

        enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04j...

    Which decodes to RLP::

        [
          7098ad865b00a582...,   # signature (64 bytes)
          01,                    # seq = 1
          "id", "v4",
          "ip", 7f000001,        # 127.0.0.1
          "secp256k1", 03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138,
          "udp", 765f,           # 30303
        ]
    """

    MAX_SIZE: ClassVar[int] = 300
    """Maximum RLP-encoded size in bytes (EIP-778)."""

    SCHEME: ClassVar[str] = "v4"
    """Supported identity scheme."""

    signature: bytes
    """64-byte secp256k1 signature (r || s concatenated, no recovery id)."""

    seq: SeqNumber
    """Sequence number. MUST increase on any record change."""

    pairs: dict[EnrKey, bytes]
    """Key/value pairs. Keys must be unique and sorted lexicographically."""

    node_id: NodeId | None = None
    """32-byte node ID derived from public key via keccak256."""

    def get(self, key: EnrKey) -> bytes | None:
        """Get value by key, or None if absent."""
        return self.pairs.get(key)

    def has(self, key: EnrKey) -> bool:
        """Check if key is present."""
        return key in self.pairs

    @property
    def identity_scheme(self) -> str | None:
        """Get identity scheme (should be "v4")."""
        id_bytes = self.get(keys.ID)
        return id_bytes.decode("utf-8") if id_bytes else None

    @property
    def public_key(self) -> bytes | None:
        """Get compressed secp256k1 public key (33 bytes)."""
        return self.get(keys.SECP256K1)

    @property
    def ip4(self) -> str | None:
        """IPv4 address as dotted string (e.g., "127.0.0.1")."""
        ip_bytes = self.get(keys.IP)
        return ".".join(str(b) for b in ip_bytes) if ip_bytes and len(ip_bytes) == 4 else None

    @property
    def ip6(self) -> str | None:
        """IPv6 address as colon-separated hex."""
        ip_bytes = self.get(keys.IP6)
        if ip_bytes and len(ip_bytes) == 16:
            return ":".join(ip_bytes[i : i + 2].hex() for i in range(0, 16, 2))
        return None

    @property
    def tcp_port(self) -> int | None:
        """TCP port (applies to both IPv4 and IPv6 unless tcp6 is set)."""
        port = self.get(keys.TCP)
        return int.from_bytes(port, "big") if port else None

    @property
    def udp_port(self) -> int | None:
        """UDP port for discovery (applies to both unless udp6 is set)."""
        port = self.get(keys.UDP)
        return int.from_bytes(port, "big") if port else None

    def multiaddr(self) -> Multiaddr | None:
        """Construct multiaddress from endpoint info."""
        if self.ip4 and self.tcp_port:
            return f"/ip4/{self.ip4}/tcp/{self.tcp_port}"
        if self.ip6 and self.tcp_port:
            return f"/ip6/{self.ip6}/tcp/{self.tcp_port}"
        return None

    # =========================================================================
    # Ethereum Consensus Extensions
    # =========================================================================

    @property
    def eth2_data(self) -> Eth2Data | None:
        """Parse eth2 key: fork_digest(4) + next_fork_version(4) + next_fork_epoch(8)."""
        eth2_bytes = self.get(keys.ETH2)
        if eth2_bytes and len(eth2_bytes) >= 16:
            from lean_spec.types import Uint64
            from lean_spec.types.byte_arrays import Bytes4

            return Eth2Data(
                fork_digest=Bytes4(eth2_bytes[0:4]),
                next_fork_version=Bytes4(eth2_bytes[4:8]),
                next_fork_epoch=Uint64(int.from_bytes(eth2_bytes[8:16], "little")),
            )
        return None

    @property
    def attestation_subnets(self) -> AttestationSubnets | None:
        """Parse attnets key (SSZ Bitvector[64])."""
        attnets = self.get(keys.ATTNETS)
        return AttestationSubnets.decode_bytes(attnets) if attnets and len(attnets) == 8 else None

    # =========================================================================
    # Validation
    # =========================================================================

    def is_valid(self) -> bool:
        """
        Check structural validity (does NOT verify cryptographic signature).

        A valid ENR has:
        - Identity scheme "v4"
        - 33-byte compressed secp256k1 public key
        - 64-byte signature
        """
        return (
            self.identity_scheme == self.SCHEME
            and self.public_key is not None
            and len(self.public_key) == 33
            and len(self.signature) == 64
        )

    def is_compatible_with(self, other: "ENR") -> bool:
        """Check fork compatibility via eth2 fork digest."""
        self_eth2, other_eth2 = self.eth2_data, other.eth2_data
        if self_eth2 is None or other_eth2 is None:
            return False
        return self_eth2.fork_digest == other_eth2.fork_digest

    # =========================================================================
    # Display
    # =========================================================================

    def __str__(self) -> str:
        """Human-readable summary."""
        parts = [f"ENR(seq={self.seq}"]
        if self.ip4:
            parts.append(f"ip={self.ip4}")
        if self.tcp_port:
            parts.append(f"tcp={self.tcp_port}")
        if self.udp_port:
            parts.append(f"udp={self.udp_port}")
        if eth2 := self.eth2_data:
            parts.append(f"fork={eth2.fork_digest.hex()}")
        return ", ".join(parts) + ")"
