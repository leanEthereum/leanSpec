"""Scalar identifiers naming validators, subnets, and the registry index space."""

from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import SSZList, Uint64


class SubnetId(Uint64):
    """Subnet identifier (0-63) for attestation subnet partitioning."""


class ValidatorIndex(Uint64):
    """A validator's index in the registry, as a 64-bit unsigned integer."""

    @classmethod
    def proposer_for_slot(cls, slot: Slot, num_validators: Uint64) -> "ValidatorIndex":
        """
        Return the validator index responsible for proposing at the given slot.

        Round-robin selection: the proposer is slot modulo registry size.
        """
        return cls(int(slot) % int(num_validators))

    def is_within_registry(self, num_validators: Uint64) -> bool:
        """Check if this index is within valid bounds for a registry of given size."""
        return int(self) < int(num_validators)

    def compute_subnet_id(self, num_committees: Uint64) -> SubnetId:
        """
        Compute the attestation subnet id for this validator.

        Args:
            num_committees: Positive number of committees.

        Returns:
            A SubnetId in 0..(num_committees-1).
        """
        return SubnetId(int(self) % int(num_committees))


class ValidatorIndices(SSZList[ValidatorIndex]):
    """List of validator indices up to the registry limit."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
