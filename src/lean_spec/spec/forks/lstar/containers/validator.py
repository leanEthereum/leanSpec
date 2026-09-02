"""The validator registry tracked in the consensus state."""

from typing import IO, Self, cast, override

from pydantic import model_validator

from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.ssz_types import Bytes52, Container, ContainerInvariantError, List


class Validator(Container):
    """A validator's static registry entry."""

    attestation_public_key: Bytes52
    """XMSS public key for signing attestations."""

    proposal_public_key: Bytes52
    """XMSS public key the proposer signs the block root with."""

    index: ValidatorIndex = ValidatorIndex(0)
    """Validator index in the registry."""


class Validators(List[Validator]):
    """Validator registry tracked in the state."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    @model_validator(mode="after")
    def _check_index_matches_position(self) -> Self:
        """Reject any registry whose stored validator indices disagree with their positions."""
        self._require_index_matches_position()
        return self

    def _require_index_matches_position(self) -> None:
        """Refuse a registry whose stored validator indices disagree with their positions."""
        for registry_position, validator in enumerate(self.data):
            if int(validator.index) != registry_position:
                raise ContainerInvariantError(
                    f"validator at position {registry_position} has "
                    f"index {int(validator.index)}, "
                    f"but the registry index must equal the list position"
                )

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read a registry, then re-check the rule the sequence decoder builds past."""
        registry = cast(Self, super().deserialize(stream, scope))
        registry._require_index_matches_position()
        return registry
