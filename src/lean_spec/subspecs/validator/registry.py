"""Validator registry for managing validator keys.

Loads validator keys from YAML configuration files compatible with ream and zeam.

The registry supports two YAML files:

1. **validators.yaml** - Maps node IDs to validator indices:

       lean_spec_0:
       - 0
       - 1
       lean_spec_1:
       - 2

2. **validator-keys-manifest.yaml** - Contains key metadata and file paths:

       key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8
       hash_function: Poseidon1
       num_validators: 3
       validators:
       - index: 0
         pubkey_hex: 0xe2a03c...
         privkey_file: validator_0_sk.ssz
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator

from lean_spec.forks.lstar.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.xmss import SecretKey
from lean_spec.types import Bytes52

logger = logging.getLogger(__name__)

type NodeValidatorMapping = dict[str, list[int]]
"""Mapping from node identifier to list of validator indices."""


class ValidatorManifestEntry(BaseModel):
    """Single validator entry from the manifest file."""

    index: ValidatorIndex
    """Validator index in the registry."""

    attestation_pubkey_hex: Bytes52
    """XMSS public key for signing attestations."""

    proposal_pubkey_hex: Bytes52
    """XMSS public key for signing block proposals."""

    attestation_privkey_file: str
    """Filename of the attestation private key file."""

    proposal_privkey_file: str
    """Filename of the proposal private key file."""

    @field_validator("attestation_pubkey_hex", "proposal_pubkey_hex", mode="before")
    @classmethod
    def parse_pubkey(cls, v: object) -> Bytes52:
        """
        Convert hex strings to validated Bytes52 pubkeys.

        Only accepts hex strings and existing Bytes52 instances.
        Integers and other types are rejected.
        """
        if isinstance(v, Bytes52):
            return v
        if isinstance(v, str):
            return Bytes52(v)
        raise TypeError(f"Expected hex string or Bytes52, got {type(v).__name__}")


class ValidatorManifest(BaseModel):
    """
    Key metadata from validator-keys-manifest.yaml.

    Contains cryptographic scheme info and validator key paths.
    This format matches ream's manifest structure.
    """

    key_scheme: str
    """Signature scheme identifier (e.g., SIGTopLevelTargetSumLifetime32Dim64Base8)."""

    hash_function: str
    """Hash function used (e.g., Poseidon1)."""

    encoding: str
    """Encoding type (e.g., TargetSum)."""

    lifetime: int
    """Key lifetime in epochs."""

    log_num_active_epochs: int
    """Log base 2 of active epochs."""

    num_active_epochs: int
    """Number of active epochs."""

    num_validators: int
    """Total validator count."""

    validators: list[ValidatorManifestEntry]
    """List of validator entries with key paths."""

    @classmethod
    def from_yaml_file(cls, path: Path) -> ValidatorManifest:
        """
        Load manifest from YAML file.

        Args:
            path: Path to validator-keys-manifest.yaml.

        Returns:
            Validated ValidatorManifest instance.
        """
        with path.open() as f:
            return cls.model_validate(yaml.safe_load(f))


def load_node_validator_mapping(path: Path) -> NodeValidatorMapping:
    """
    Load node-to-validator index mapping from validators.yaml.

    Maps node identifiers to lists of validator indices they control.

    Args:
        path: Path to validators.yaml.

    Returns:
        Mapping from node ID to list of validator indices.
        Empty dict if file is empty.
    """
    with path.open() as f:
        data = yaml.safe_load(f)
    # YAML returns None for empty file
    return data or {}


@dataclass(frozen=True, slots=True)
class ValidatorEntry:
    """
    A single validator's key material.

    Holds the index and both secret keys needed for signing.
    Attestation and proposal keys are separate to allow independent
    OTS signing within the same slot.
    """

    index: ValidatorIndex
    """Validator index in the registry."""

    attestation_secret_key: SecretKey
    """Secret key for signing attestations."""

    proposal_secret_key: SecretKey
    """Secret key for signing block proposals."""


@dataclass(slots=True)
class ValidatorRegistry:
    """
    Registry of validator keys controlled by this node.

    The registry holds secret keys for validators assigned to this node.
    It provides lookup by validator index for signing operations.
    """

    _validators: dict[ValidatorIndex, ValidatorEntry] = field(default_factory=dict)
    """Map from validator index to entry."""

    def add(self, entry: ValidatorEntry) -> None:
        """
        Add or replace a validator entry in the registry.

        Replaces any existing entry with the same index.
        Used to persist updated key state after signing.

        Args:
            entry: Validator entry to add.
        """
        self._validators[entry.index] = entry

    def get(self, index: ValidatorIndex) -> ValidatorEntry | None:
        """
        Get validator entry by index.

        Args:
            index: Validator index to look up.

        Returns:
            Validator entry if found, None otherwise.
        """
        return self._validators.get(index)

    def __contains__(self, index: ValidatorIndex) -> bool:
        """Check if we control this validator."""
        return index in self._validators

    def indices(self) -> ValidatorIndices:
        """
        Get all validator indices we control.

        Returns:
            ValidatorIndices collection.
        """
        return ValidatorIndices(data=list(self._validators.keys()))

    def primary_index(self) -> ValidatorIndex | None:
        """
        Get the primary validator index for store-level identity.

        Returns the first validator index in the registry.
        With ATTESTATION_COMMITTEE_COUNT = 1, all validators share subnet 0,
        so a single ID suffices for store-level operations.

        Returns:
            First validator index, or None if registry is empty.
        """
        if not self._validators:
            return None
        return next(iter(self._validators))

    def __len__(self) -> int:
        """Number of validators in the registry."""
        return len(self._validators)

    @classmethod
    def from_yaml(
        cls,
        node_id: str,
        validators_path: Path | str,
        manifest_path: Path | str,
    ) -> ValidatorRegistry:
        """
        Load validator registry from YAML configuration files.

        Loading process:

        1. Read validators.yaml to find indices assigned to this node
        2. Read manifest to get key file paths
        3. Load secret keys from SSZ files

        Args:
            node_id: Identifier for this node in validators.yaml.
            validators_path: Path to validators.yaml.
            manifest_path: Path to validator-keys-manifest.yaml.

        Returns:
            Registry populated with validator keys for this node.
        """
        validators_path = Path(validators_path)
        manifest_path = Path(manifest_path)

        # Load node-to-validator mapping.
        node_mapping = load_node_validator_mapping(validators_path)

        # Get indices assigned to this node.
        assigned_indices = node_mapping.get(node_id, [])
        if not assigned_indices:
            return cls()

        # Load manifest with key metadata.
        manifest = ValidatorManifest.from_yaml_file(manifest_path)

        # Build index lookup from manifest.
        manifest_by_index = {v.index: v for v in manifest.validators}

        # Load keys for assigned validators.
        registry = cls()
        manifest_dir = manifest_path.parent

        for index in assigned_indices:
            entry = manifest_by_index.get(ValidatorIndex(index))
            if entry is None:
                # Validator index in validators.yaml but missing from manifest.
                # This can happen if the manifest was regenerated with fewer validators.
                logger.warning(
                    "Validator index %d assigned to node %s but not found in manifest",
                    index,
                    node_id,
                )
                continue

            # Load attestation secret key from SSZ file.
            att_key_path = manifest_dir / entry.attestation_privkey_file
            try:
                attestation_secret_key = SecretKey.decode_bytes(att_key_path.read_bytes())
            except FileNotFoundError as e:
                raise ValueError(f"Attestation key file not found: {att_key_path}") from e
            except Exception as e:
                raise ValueError(
                    f"Failed to load attestation key for validator {index}: {e}"
                ) from e

            # Load proposal secret key from SSZ file.
            prop_key_path = manifest_dir / entry.proposal_privkey_file
            try:
                proposal_secret_key = SecretKey.decode_bytes(prop_key_path.read_bytes())
            except FileNotFoundError as e:
                raise ValueError(f"Proposal key file not found: {prop_key_path}") from e
            except Exception as e:
                raise ValueError(f"Failed to load proposal key for validator {index}: {e}") from e

            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(index),
                    attestation_secret_key=attestation_secret_key,
                    proposal_secret_key=proposal_secret_key,
                )
            )

        return registry
