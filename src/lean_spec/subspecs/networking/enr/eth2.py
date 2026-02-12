"""
Ethereum Consensus ENR Extensions.

Ethereum consensus clients extend ENR with additional keys for fork
compatibility and subnet discovery.

The "eth2" key contains 16 bytes:
- fork_digest (4 bytes): current fork identifier
- next_fork_version (4 bytes): version of next scheduled fork
- next_fork_epoch (8 bytes): epoch when next fork activates (little-endian)

Subnet subscription keys (SSZ Bitvectors):
- attnets: Bitvector[64] - attestation subnets (bit i = subscribed to subnet i)
- syncnets: Bitvector[4] - sync committee subnets

See: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
"""

from typing import ClassVar

from lean_spec.subspecs.networking.types import ForkDigest, Version
from lean_spec.types import StrictBaseModel, Uint64
from lean_spec.types.bitfields import BaseBitvector
from lean_spec.types.boolean import Boolean

FAR_FUTURE_EPOCH = Uint64(2**64 - 1)
"""Sentinel value indicating no scheduled fork."""


class Eth2Data(StrictBaseModel):
    """
    Ethereum consensus data stored in ENR `eth2` key (16 bytes).

    SSZ: fork_digest (4) + next_fork_version (4) + next_fork_epoch (8)
    """

    fork_digest: ForkDigest
    """Current active fork identifier (4 bytes)."""

    next_fork_version: Version
    """Fork version of next scheduled fork. Equals current version if none scheduled."""

    next_fork_epoch: Uint64
    """Epoch when next fork activates. FAR_FUTURE_EPOCH if none scheduled."""

    @classmethod
    def no_scheduled_fork(cls, current_digest: ForkDigest, current_version: Version) -> "Eth2Data":
        """Create Eth2Data indicating no scheduled fork."""
        return cls(
            fork_digest=current_digest,
            next_fork_version=current_version,
            next_fork_epoch=FAR_FUTURE_EPOCH,
        )


class AttestationSubnets(BaseBitvector):
    """
    Attestation subnet subscriptions (ENR `attnets` key).

    SSZ Bitvector[64] where bit i indicates subscription to subnet i.
    """

    LENGTH: ClassVar[int] = 64
    """64 attestation subnets."""

    @classmethod
    def none(cls) -> "AttestationSubnets":
        """No subscriptions."""
        return cls(data=[Boolean(False)] * cls.LENGTH)

    @classmethod
    def all(cls) -> "AttestationSubnets":
        """Subscribe to all 64 subnets."""
        return cls(data=[Boolean(True)] * cls.LENGTH)

    @classmethod
    def from_subnet_ids(cls, subnet_ids: list[int]) -> "AttestationSubnets":
        """Subscribe to specific subnets."""
        bits = [Boolean(False)] * cls.LENGTH
        for sid in subnet_ids:
            if not 0 <= sid < cls.LENGTH:
                raise ValueError(f"Subnet ID must be 0-63, got {sid}")
            bits[sid] = Boolean(True)
        return cls(data=bits)

    def is_subscribed(self, subnet_id: int) -> bool:
        """Check if subscribed to a subnet."""
        if not 0 <= subnet_id < self.LENGTH:
            raise ValueError(f"Subnet ID must be 0-63, got {subnet_id}")
        return bool(self.data[subnet_id])

    def subscribed_subnets(self) -> list[int]:
        """List of subscribed subnet IDs."""
        return [i for i in range(self.LENGTH) if self.data[i]]

    def subscription_count(self) -> int:
        """Number of subscribed subnets."""
        return sum(1 for b in self.data if b)


class SyncCommitteeSubnets(BaseBitvector):
    """
    Sync committee subnet subscriptions (ENR `syncnets` key).

    SSZ Bitvector[4] where bit i indicates subscription to sync subnet i.
    """

    LENGTH: ClassVar[int] = 4
    """4 sync committee subnets."""

    @classmethod
    def none(cls) -> "SyncCommitteeSubnets":
        """No subscriptions."""
        return cls(data=[Boolean(False)] * cls.LENGTH)

    @classmethod
    def all(cls) -> "SyncCommitteeSubnets":
        """Subscribe to all 4 subnets."""
        return cls(data=[Boolean(True)] * cls.LENGTH)

    @classmethod
    def from_subnet_ids(cls, subnet_ids: list[int]) -> "SyncCommitteeSubnets":
        """Subscribe to specific sync subnets."""
        bits = [Boolean(False)] * cls.LENGTH
        for sid in subnet_ids:
            if not 0 <= sid < cls.LENGTH:
                raise ValueError(f"Sync subnet ID must be 0-3, got {sid}")
            bits[sid] = Boolean(True)
        return cls(data=bits)

    def is_subscribed(self, subnet_id: int) -> bool:
        """Check if subscribed to a sync subnet."""
        if not 0 <= subnet_id < self.LENGTH:
            raise ValueError(f"Sync subnet ID must be 0-3, got {subnet_id}")
        return bool(self.data[subnet_id])

    def subscribed_subnets(self) -> list[int]:
        """List of subscribed sync subnet IDs."""
        return [i for i in range(self.LENGTH) if self.data[i]]

    def subscription_count(self) -> int:
        """Number of subscribed sync subnets."""
        return sum(1 for b in self.data if b)
