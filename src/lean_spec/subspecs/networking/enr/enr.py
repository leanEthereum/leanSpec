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

from __future__ import annotations

import base64
from typing import ClassVar

from typing_extensions import Self

from lean_spec.subspecs.networking.types import Multiaddr, NodeId, SeqNumber
from lean_spec.types import (
    Bytes32,
    Bytes33,
    Bytes64,
    StrictBaseModel,
    Uint64,
    rlp,
)
from lean_spec.types.byte_arrays import Bytes4

from . import keys
from .eth2 import AttestationSubnets, Eth2Data, SyncCommitteeSubnets
from .keys import EnrKey

ENR_PREFIX = "enr:"
"""Text prefix for ENR strings."""


class ENR(StrictBaseModel):
    """Ethereum Node Record (EIP-778)."""

    MAX_SIZE: ClassVar[int] = 300
    """Maximum RLP-encoded size in bytes (EIP-778)."""

    SCHEME: ClassVar[str] = "v4"
    """Supported identity scheme."""

    signature: Bytes64
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
    def public_key(self) -> Bytes33 | None:
        """Get compressed secp256k1 public key (33 bytes)."""
        raw = self.get(keys.SECP256K1)
        return Bytes33(raw) if raw is not None and len(raw) == 33 else None

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

    @property
    def tcp6_port(self) -> int | None:
        """IPv6-specific TCP port. Falls back to tcp_port if not set."""
        port = self.get(keys.TCP6)
        return int.from_bytes(port, "big") if port else None

    @property
    def udp6_port(self) -> int | None:
        """IPv6-specific UDP port. Falls back to udp_port if not set."""
        port = self.get(keys.UDP6)
        return int.from_bytes(port, "big") if port else None

    def multiaddr(self) -> Multiaddr | None:
        """Construct multiaddress from endpoint info."""
        if self.ip4 and self.tcp_port:
            return f"/ip4/{self.ip4}/tcp/{self.tcp_port}"
        if self.ip6 and self.tcp_port:
            return f"/ip6/{self.ip6}/tcp/{self.tcp_port}"
        return None

    @property
    def eth2_data(self) -> Eth2Data | None:
        """Parse eth2 key: fork_digest(4) + next_fork_version(4) + next_fork_epoch(8)."""
        eth2_bytes = self.get(keys.ETH2)
        if eth2_bytes and len(eth2_bytes) >= 16:
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

    @property
    def sync_committee_subnets(self) -> SyncCommitteeSubnets | None:
        """Parse syncnets key (SSZ Bitvector[4])."""
        syncnets = self.get(keys.SYNCNETS)
        if syncnets and len(syncnets) == 1:
            return SyncCommitteeSubnets.decode_bytes(syncnets)
        return None

    def is_valid(self) -> bool:
        """
        Check structural validity (does NOT verify cryptographic signature).

        A valid ENR has:
        - Identity scheme "v4"
        - 33-byte compressed secp256k1 public key (Bytes33)
        - 64-byte signature (Bytes64, enforced by type)
        """
        return self.identity_scheme == self.SCHEME and self.public_key is not None

    def is_compatible_with(self, other: "ENR") -> bool:
        """Check fork compatibility via eth2 fork digest."""
        self_eth2, other_eth2 = self.eth2_data, other.eth2_data
        if self_eth2 is None or other_eth2 is None:
            return False
        return self_eth2.fork_digest == other_eth2.fork_digest

    def _build_content_items(self) -> list[bytes]:
        """
        Build the list of content items for RLP encoding.

        Returns [seq, k1, v1, k2, v2, ...] with keys sorted lexicographically.
        """
        sorted_keys = sorted(self.pairs.keys())

        # Sequence number: minimal big-endian, empty bytes for zero.
        seq_bytes = self.seq.to_bytes(8, "big").lstrip(b"\x00") or b""
        items: list[bytes] = [seq_bytes]

        for key in sorted_keys:
            items.append(key.encode("utf-8"))
            items.append(self.pairs[key])

        return items

    def _content_rlp(self) -> bytes:
        """
        Get RLP-encoded content for signing (excludes signature).

        Returns the RLP encoding of [seq, k1, v1, k2, v2, ...].
        """
        return rlp.encode_rlp(self._build_content_items())

    def verify_signature(self) -> bool:
        """
        Cryptographically verify the ENR signature.

        Per EIP-778 "v4" identity scheme:

        1. Compute keccak256 hash of content RLP (seq + sorted key/value pairs)
        2. Verify the 64-byte secp256k1 signature against the public key

        Returns True if signature is valid, False otherwise.
        """
        from Crypto.Hash import keccak
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            encode_dss_signature,
        )

        if self.public_key is None:
            return False

        try:
            # Hash the content (excludes signature).
            content = self._content_rlp()
            k = keccak.new(digest_bits=256)
            k.update(content)
            digest = k.digest()

            # Load the compressed public key.
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), bytes(self.public_key)
            )

            # Convert r||s (64 bytes) to DER-encoded signature.
            r = int.from_bytes(self.signature[:32], "big")
            s = int.from_bytes(self.signature[32:], "big")
            der_signature = encode_dss_signature(r, s)

            # Verify signature against pre-hashed digest.
            # SHA256 is used as the algorithm marker since it has the same 32-byte digest size.
            public_key.verify(der_signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
            return True
        except Exception:
            return False

    def compute_node_id(self) -> NodeId | None:
        """
        Compute the node ID from the public key.

        Per EIP-778 "v4" identity scheme: keccak256(uncompressed_pubkey).
        The hash is computed over the 64-byte x||y coordinates.
        """
        from Crypto.Hash import keccak
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        if self.public_key is None:
            return None

        try:
            # Uncompress public key to 65 bytes (0x04 || x || y).
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), self.public_key
            )
            uncompressed = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )

            # Hash the 64-byte x||y (excluding 0x04 prefix).
            k = keccak.new(digest_bits=256)
            k.update(uncompressed[1:])
            return Bytes32(k.digest())
        except Exception:
            return None

    def to_rlp(self) -> bytes:
        """
        Serialize to RLP bytes.

        Format: [signature, seq, k1, v1, k2, v2, ...]
        Keys are sorted lexicographically per EIP-778.
        """
        items = [bytes(self.signature)] + self._build_content_items()
        return rlp.encode_rlp(items)

    def to_string(self) -> str:
        """
        Serialize to text representation.

        Format: "enr:" + base64url(RLP) without padding.
        """
        rlp_bytes = self.to_rlp()
        b64_content = base64.urlsafe_b64encode(rlp_bytes).decode("utf-8").rstrip("=")
        return ENR_PREFIX + b64_content

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

    @classmethod
    def from_rlp(cls, rlp_data: bytes) -> Self:
        """
        Parse an ENR from RLP-encoded bytes.

        Used when parsing ENRs from Discovery v5 NODES responses
        or handshake packets.

        Args:
            rlp_data: RLP-encoded ENR bytes.

        Returns:
            Parsed ENR instance with computed node_id.

        Raises:
            ValueError: If the RLP data is malformed.
        """
        # RLP decode: [signature, seq, k1, v1, k2, v2, ...]
        try:
            items = rlp.decode_rlp_list(rlp_data)
        except rlp.RLPDecodingError as e:
            raise ValueError(f"Invalid RLP encoding: {e}") from e

        # EIP-778 requires ENRs to be at most 300 bytes.
        if len(rlp_data) > cls.MAX_SIZE:
            raise ValueError(f"ENR exceeds max size: {len(rlp_data)} > {cls.MAX_SIZE}")

        if len(items) < 2:
            raise ValueError("ENR must have at least signature and seq")

        if len(items) % 2 != 0:
            raise ValueError("ENR key/value pairs must be even")

        signature_raw = items[0]
        if len(signature_raw) != 64:
            raise ValueError(f"ENR signature must be 64 bytes, got {len(signature_raw)}")
        signature = Bytes64(signature_raw)

        seq_bytes = items[1]
        seq = int.from_bytes(seq_bytes, "big") if seq_bytes else 0

        # Parse key/value pairs.
        #
        # Keys are strings, values are arbitrary bytes.
        # EIP-778 requires keys to be lexicographically sorted.
        pairs: dict[str, bytes] = {}
        prev_key: str | None = None
        for i in range(2, len(items), 2):
            key = items[i].decode("utf-8")
            if prev_key is not None and key <= prev_key:
                raise ValueError(
                    f"ENR keys must be lexicographically sorted per EIP-778: "
                    f"'{key}' follows '{prev_key}'"
                )
            value = items[i + 1]
            pairs[key] = value
            prev_key = key

        enr = cls(
            signature=signature,
            seq=Uint64(seq),
            pairs=pairs,
        )

        # Compute and store node_id for routing/identification.
        node_id = enr.compute_node_id()
        if node_id is not None:
            return enr.model_copy(update={"node_id": node_id})

        return enr

    @classmethod
    def from_string(cls, enr_text: str) -> Self:
        """
        Parse an ENR from its text representation.

        Text format is URL-safe base64 with `enr:` prefix.

        Args:
            enr_text: ENR string (e.g., "enr:-IS4Q...")

        Returns:
            Parsed ENR instance.

        Raises:
            ValueError: If the string is malformed or RLP decoding fails.
        """
        if not enr_text.startswith(ENR_PREFIX):
            raise ValueError(f"ENR must start with '{ENR_PREFIX}'")

        # Extract base64url content after prefix.
        b64_content = enr_text[len(ENR_PREFIX) :]

        # Base64url decode (add padding if needed).
        #
        # Python's base64.urlsafe_b64decode requires proper padding.
        padding = 4 - (len(b64_content) % 4)
        if padding != 4:
            b64_content += "=" * padding

        try:
            rlp_data = base64.urlsafe_b64decode(b64_content)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}") from e

        return cls.from_rlp(rlp_data)
