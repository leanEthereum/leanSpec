"""Genesis configuration and the validator registry."""

from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.ssz import Bytes52, Container, SSZList, Uint64


class GenesisConfig(Container):
    """
    Holds temporary configuration properties for simplified consensus.

    Note: These fields support a simplified round-robin block production
    in the absence of more complex mechanisms like RANDAO or deposits.
    """

    model_config = Container.model_config | {"frozen": True}

    genesis_time: Uint64
    """The timestamp of the genesis block."""


class Validator(Container):
    """Represents a validator's static metadata and operational interface."""

    model_config = Container.model_config | {"frozen": True}

    attestation_public_key: Bytes52
    """XMSS public key for signing attestations."""

    proposal_public_key: Bytes52
    """XMSS public key for signing proposer attestations in blocks."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""

    def get_attestation_public_key(self) -> PublicKey:
        """Get the XMSS public key used for attestation verification."""
        return PublicKey.decode_bytes(bytes(self.attestation_public_key))

    def get_proposal_public_key(self) -> PublicKey:
        """Get the XMSS public key used for proposer attestation verification."""
        return PublicKey.decode_bytes(bytes(self.proposal_public_key))


class Validators(SSZList[Validator]):
    """Validator registry tracked in the state."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
