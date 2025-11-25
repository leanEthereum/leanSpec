"""Validator container for the Lean Ethereum consensus specification."""

from __future__ import annotations

from lean_spec.types import Bytes52, Container, ValidatorIndex

from ..xmss.containers import PublicKey
from ..xmss.interface import TEST_SIGNATURE_SCHEME, GeneralizedXmssScheme
from .attestation import Attestation, AttestationData


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    pubkey: Bytes52
    """XMSS one-time signature public key."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_pubkey(self, scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME) -> PublicKey:
        """Get the XMSS public key from this validator."""
        return PublicKey.from_bytes(bytes(self.pubkey), scheme.config)

    def produce_attestation(self, data: AttestationData) -> Attestation:
        """
        Produce an attestation from attestation data.

        This method wraps AttestationData with the validator's identity to create
        a complete Attestation object ready for signing and broadcast.

        Args:
            data: The attestation data containing slot, head, target, and source.

        Returns:
            A fully constructed Attestation object with this validator's index.
        """
        return Attestation(
            validator_id=self.index,
            data=data,
        )
