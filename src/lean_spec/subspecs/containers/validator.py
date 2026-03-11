"""Validator container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.types import Bytes52, Container, SSZList, Uint64

from ..xmss.containers import PublicKey
from .slot import Slot


class SubnetId(Uint64):
    """Subnet identifier (0-63) for attestation subnet partitioning."""


class ValidatorIndex(Uint64):
    """Represents a validator's unique index as a 64-bit unsigned integer."""

    def is_proposer_for(self, slot: Slot, num_validators: Uint64) -> bool:
        """
        Check if this validator is the proposer for the given slot.

        Uses round-robin proposer selection per the lean protocol spec.
        """
        return int(slot) % int(num_validators) == int(self)

    def is_valid(self, num_validators: Uint64) -> bool:
        """Check if this index is within valid bounds for a registry of given size."""
        return int(self) < int(num_validators)

    def compute_subnet_id(self, num_committees: Uint64) -> SubnetId:
        """Compute the attestation subnet id for this validator.

        Args:
            num_committees: Positive number of committees.

        Returns:
            A SubnetId in 0..(num_committees-1).
        """
        return SubnetId(int(self) % int(num_committees))


class ValidatorIndices(SSZList[ValidatorIndex]):
    """List of validator indices up to registry limit."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    attestation_pubkey: Bytes52
    """XMSS public key for signing attestations."""

    proposal_pubkey: Bytes52
    """XMSS public key for signing proposer attestations in blocks."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_attestation_pubkey(self) -> PublicKey:
        """Get the XMSS public key used for attestation verification."""
        return PublicKey.decode_bytes(bytes(self.attestation_pubkey))

    def get_proposal_pubkey(self) -> PublicKey:
        """Get the XMSS public key used for proposer attestation verification."""
        return PublicKey.decode_bytes(bytes(self.proposal_pubkey))
