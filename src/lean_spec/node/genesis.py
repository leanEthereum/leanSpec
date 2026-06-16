"""Genesis configuration loader for the cross-client YAML format."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator

from lean_spec.base import StrictBaseModel
from lean_spec.spec.forks import (
    VALIDATOR_REGISTRY_LIMIT,
    Validator,
    ValidatorIndex,
    Validators,
)
from lean_spec.spec.ssz import Bytes52, Uint64


class GenesisValidatorEntry(StrictBaseModel):
    """A single validator's public keys in the genesis configuration."""

    attestation_public_key: Bytes52
    """XMSS public key for signing attestations."""

    proposal_public_key: Bytes52
    """XMSS public key the proposer signs the block root with."""

    @field_validator("attestation_public_key", "proposal_public_key", mode="before")
    @classmethod
    def _yaml_int_to_hex(cls, field_value: Any) -> Any:
        """
        Re-encode integer inputs as hex.

        A YAML parser reads an unquoted 0x value as an int rather than a hex string.
        """
        if isinstance(field_value, int):
            return f"0x{field_value:0{Bytes52.LENGTH * 2}x}"
        return field_value


class GenesisConfig(StrictBaseModel):
    """The network-wide origin: when slot 0 begins and which validators secure the chain."""

    model_config = StrictBaseModel.model_config | {"extra": "ignore"}

    genesis_time: Uint64 = Field(alias="GENESIS_TIME")
    """Unix timestamp in seconds when slot 0 begins."""

    genesis_validators: list[GenesisValidatorEntry] = Field(alias="GENESIS_VALIDATORS")
    """Validators present at slot 0, in registry order."""

    @field_validator("genesis_validators", mode="before")
    @classmethod
    def _reject_oversized_validator_set(cls, genesis_validators: Any) -> Any:
        """Bound the set before decoding."""
        registry_limit = int(VALIDATOR_REGISTRY_LIMIT)
        if isinstance(genesis_validators, list) and len(genesis_validators) > registry_limit:
            raise ValueError(
                f"genesis validator count {len(genesis_validators)} "
                f"exceeds registry limit {registry_limit}"
            )
        return genesis_validators

    def to_validators(self) -> Validators:
        """Build the validator set, assigning each one a sequential index from 0."""
        return Validators(
            data=[
                Validator(
                    attestation_public_key=genesis_validator.attestation_public_key,
                    proposal_public_key=genesis_validator.proposal_public_key,
                    index=ValidatorIndex(validator_index),
                )
                for validator_index, genesis_validator in enumerate(self.genesis_validators)
            ]
        )

    @classmethod
    def from_yaml_file(cls, path: Path | str) -> GenesisConfig:
        """Load and validate configuration from a genesis YAML file."""
        return cls.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
