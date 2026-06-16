"""The validator registry tracked in the consensus state."""

from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.ssz import Bytes52, Container, SSZList


class Validator(Container):
    """A validator's static registry entry."""

    attestation_public_key: Bytes52
    """XMSS public key for signing attestations."""

    proposal_public_key: Bytes52
    """XMSS public key the proposer signs the block root with."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""


class Validators(SSZList[Validator]):
    """Validator registry tracked in the state."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
