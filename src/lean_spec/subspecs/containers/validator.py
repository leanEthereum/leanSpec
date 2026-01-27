"""Validator container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from functools import total_ordering

from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.types import Bytes52, Container, SSZList, Uint64

from ..xmss.containers import PublicKey
from .slot import Slot


@total_ordering
class ValidatorIndex(Uint64):
    """Represents a validator's unique index as a 64-bit unsigned integer."""

    def is_proposer_for(self, slot: Slot, num_validators: int) -> bool:
        """
        Check if this validator is the proposer for the given slot.

        Uses round-robin proposer selection per the lean protocol spec.
        """
        return int(slot) % num_validators == int(self)

    def is_valid(self, num_validators: int) -> bool:
        """Check if this index is within valid bounds for a registry of given size."""
        return int(self) < num_validators


class ValidatorIndices(SSZList[ValidatorIndex]):
    """List of validator indices up to registry limit."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_pubkey(self) -> PublicKey:
        """Get the XMSS public key from this validator."""
        return PublicKey.decode_bytes(bytes(self.pubkey))
