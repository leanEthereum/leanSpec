"""Genesis configuration loader.

Loads genesis configuration from YAML files compatible with ream and zeam.

The expected YAML format matches the cross-client convention:

    GENESIS_TIME: 1704085200
    GENESIS_VALIDATORS:
    - attestation_pubkey: 0xe2a03c16122c7e0f...
      proposal_pubkey: 0x0767e65924063f79...
    - attestation_pubkey: 0xabcdef0123456789...
      proposal_pubkey: 0x9876543210fedcba...
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator

from lean_spec.base import StrictBaseModel
from lean_spec.spec.forks import Validator, ValidatorIndex, Validators
from lean_spec.spec.ssz import Bytes52, Uint64


class GenesisValidatorEntry(StrictBaseModel):
    """A single validator's public keys in the genesis configuration."""

    attestation_pubkey: Bytes52
    """XMSS public key for signing attestations."""

    proposal_pubkey: Bytes52
    """XMSS public key for signing proposer attestations in blocks."""

    @field_validator("attestation_pubkey", "proposal_pubkey", mode="before")
    @classmethod
    def parse_hex_pubkey(cls, v: Any) -> Bytes52:
        """
        Convert hex strings or integers to validated Bytes52 pubkeys.

        YAML parsers may interpret 0x-prefixed values as integers.
        """
        if isinstance(v, int):
            v = f"0x{v:0104x}"
        return Bytes52(v)


class GenesisConfig(StrictBaseModel):
    """
    Configuration that establishes the birth of an Ethereum consensus chain.

    Genesis is the shared starting point for all participants in the network.
    Without a common genesis, nodes cannot agree on the chain's history.
    Every block traces its ancestry back to this origin.

    The genesis configuration solves two fundamental coordination problems:

    - Time Synchronization: All nodes agree on when slots begin
    - Initial Trust: Bootstrap validators that can produce and attest blocks

    Field names use UPPERCASE to match cross-client YAML convention.
    Pydantic aliases map them to snake_case Python attributes.

    Extra YAML keys (e.g. ACTIVE_EPOCH, VALIDATOR_COUNT) are ignored so configs
    from lean-quickstart and other generators load without error.
    """

    model_config = StrictBaseModel.model_config | {"extra": "ignore"}

    genesis_time: Uint64 = Field(alias="GENESIS_TIME")
    """
    Unix timestamp (seconds since 1970-01-01 UTC) when slot 0 begins.

    Anchors the chain's clock to real-world time.

    Nodes compute the current slot as: (now - genesis_time) / slot_duration.

    Immutable once the chain launches.
    """

    genesis_validators: list[GenesisValidatorEntry] = Field(alias="GENESIS_VALIDATORS")
    """
    Validators trusted to secure the chain from slot 0.

    Each entry contains two XMSS public keys:

    - attestation_pubkey: for signing attestations
    - proposal_pubkey: for signing proposer attestations in blocks

    Security note: 2/3+ collusion controls the chain until new validators join.
    """

    def to_validators(self) -> Validators:
        """
        Build the genesis validator set with assigned indices.

        Each validator needs an index for the registry.
        Indices are assigned sequentially starting from 0.
        """
        return Validators(
            data=[
                Validator(
                    attestation_pubkey=entry.attestation_pubkey,
                    proposal_pubkey=entry.proposal_pubkey,
                    index=ValidatorIndex(i),
                )
                for i, entry in enumerate(self.genesis_validators)
            ]
        )

    @classmethod
    def from_yaml_file(cls, path: Path | str) -> GenesisConfig:
        """
        Load configuration from a YAML file.

        Use this to load shared genesis files distributed to all clients.
        Compatible with ream's config.yaml format.

        Raises:
            FileNotFoundError: If the file does not exist.
            yaml.YAMLError: If the file is not valid YAML.
            pydantic.ValidationError: If the data fails validation.
        """
        path = Path(path)
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)
