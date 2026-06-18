"""The validator registry tracked in the consensus state."""

from typing import Self

from pydantic import model_validator

from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.ssz import Bytes52, Container, SSZList
from lean_spec.spec.ssz.exceptions import SSZValueError


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

    @model_validator(mode="after")
    def _require_index_matches_position(self) -> Self:
        """Reject any registry whose stored validator indices disagree with their positions."""
        for registry_position, validator in enumerate(self.data):
            if int(validator.index) != registry_position:
                raise SSZValueError(
                    f"validator at position {registry_position} has "
                    f"index {int(validator.index)}, "
                    f"but the registry index must equal the list position"
                )
        return self
