"""
Validator key loading.

Two YAML files describe the keys.

- validators.yaml maps each node to the validator indices it controls:

    lean_spec_0:
    - 0
    - 1
    lean_spec_1:
    - 2

- validator-keys-manifest.yaml lists each validator's key metadata and file paths:

    key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8
    hash_function: Poseidon
    num_validators: 3
    validators:
    - index: 0
      public_key_hex: 0xe2a03c...
      private_key_file: validator_0_secret_key.ssz
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel

from lean_spec.spec.crypto.xmss import SecretKey
from lean_spec.spec.forks import ValidatorIndex, ValidatorIndices
from lean_spec.spec.ssz import Bytes52

logger = logging.getLogger(__name__)


class ValidatorManifestEntry(BaseModel):
    """Single validator entry from the manifest file."""

    index: ValidatorIndex
    """Validator index in the registry."""

    attestation_public_key_hex: Bytes52
    """XMSS public key for signing attestations."""

    proposal_public_key_hex: Bytes52
    """XMSS public key for signing block proposals."""

    attestation_private_key_file: str
    """Filename of the attestation private key file."""

    proposal_private_key_file: str
    """Filename of the proposal private key file."""


class ValidatorManifest(BaseModel):
    """Key metadata for every validator, matching the ream manifest format."""

    key_scheme: str
    """Signature scheme identifier (e.g., SIGTopLevelTargetSumLifetime32Dim64Base8)."""

    hash_function: str
    """Hash function used (e.g., Poseidon)."""

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
        """Load and validate a manifest from a YAML file."""
        with path.open() as f:
            return cls.model_validate(yaml.safe_load(f))


@dataclass(frozen=True, slots=True)
class ValidatorEntry:
    """
    A single validator's key material.

    Attestation and proposal keys are separate.
    This lets one validator sign both within the same slot without OTS conflict.
    """

    index: ValidatorIndex
    """Validator index in the registry."""

    attestation_secret_key: SecretKey
    """Secret key for signing attestations."""

    proposal_secret_key: SecretKey
    """Secret key for signing block proposals."""


@dataclass(slots=True)
class ValidatorRegistry:
    """Signing keys for the validators this node controls."""

    _validators: dict[ValidatorIndex, ValidatorEntry] = field(default_factory=dict)
    """Map from validator index to entry."""

    def add(self, entry: ValidatorEntry) -> None:
        """Add a validator entry, replacing any existing entry with the same index."""
        self._validators[entry.index] = entry

    def get(self, index: ValidatorIndex) -> ValidatorEntry | None:
        """Return the validator entry for an index, or None if not controlled."""
        return self._validators.get(index)

    def __contains__(self, index: ValidatorIndex) -> bool:
        """Check if we control this validator."""
        return index in self._validators

    def indices(self) -> ValidatorIndices:
        """Return every validator index this node controls."""
        return ValidatorIndices(data=list(self._validators.keys()))

    def primary_index(self) -> ValidatorIndex | None:
        """
        The store-level identity for this node, or None if it controls no validators.

        Every validator shares the single attestation subnet.
        So the first controlled index suffices for store-level operations.
        """
        if not self._validators:
            return None
        return next(iter(self._validators))

    def __len__(self) -> int:
        """Number of validators in the registry."""
        return len(self._validators)

    @classmethod
    def from_keys_directory(cls, node_id: str, base_directory: Path | str) -> ValidatorRegistry:
        """
        Load a registry from the ream/zeam keystore layout.

        Reads validators.yaml and hash-sig-keys/validator-keys-manifest.yaml,
        both relative to the base directory.

        A missing manifest raises FileNotFoundError.
        A missing validators mapping is allowed and yields an empty registry.
        """
        base = Path(base_directory)
        manifest_path = base / "hash-sig-keys" / "validator-keys-manifest.yaml"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Validator keys manifest not found: {manifest_path}")
        return cls.from_yaml(
            node_id=node_id,
            validators_path=base / "validators.yaml",
            manifest_path=manifest_path,
        )

    @classmethod
    def from_yaml(
        cls,
        node_id: str,
        validators_path: Path | str,
        manifest_path: Path | str,
    ) -> ValidatorRegistry:
        """Load a registry for one node from its validators.yaml and manifest files."""
        validators_path = Path(validators_path)
        manifest_path = Path(manifest_path)

        # Read the node-to-validator mapping; an empty file parses to None.
        with validators_path.open() as validators_file:
            node_mapping = yaml.safe_load(validators_file) or {}

        # Get indices assigned to this node.
        assigned_indices = node_mapping.get(node_id, [])
        if not assigned_indices:
            return cls()

        # Load manifest with key metadata.
        manifest = ValidatorManifest.from_yaml_file(manifest_path)

        # Build index lookup from manifest.
        manifest_by_index = {
            manifest_validator.index: manifest_validator
            for manifest_validator in manifest.validators
        }

        # Load keys for assigned validators.
        registry = cls()
        manifest_directory = manifest_path.parent

        for validator_index in assigned_indices:
            manifest_entry = manifest_by_index.get(ValidatorIndex(validator_index))
            if manifest_entry is None:
                # Validator index in validators.yaml but missing from manifest.
                # This can happen if the manifest was regenerated with fewer validators.
                logger.warning(
                    "Validator index %d assigned to node %s but not found in manifest",
                    validator_index,
                    node_id,
                )
                continue

            # Decode the attestation key from its SSZ file.
            attestation_key_path = manifest_directory / manifest_entry.attestation_private_key_file
            try:
                attestation_secret_key = SecretKey.decode_bytes(attestation_key_path.read_bytes())
            except FileNotFoundError as exception:
                raise ValueError(
                    f"Attestation key file not found: {attestation_key_path}"
                ) from exception
            except Exception as exception:
                raise ValueError(
                    f"Failed to load attestation key for validator {validator_index}: {exception}"
                ) from exception

            # Decode the proposal key from its SSZ file.
            proposal_key_path = manifest_directory / manifest_entry.proposal_private_key_file
            try:
                proposal_secret_key = SecretKey.decode_bytes(proposal_key_path.read_bytes())
            except FileNotFoundError as exception:
                raise ValueError(f"Proposal key file not found: {proposal_key_path}") from exception
            except Exception as exception:
                raise ValueError(
                    f"Failed to load proposal key for validator {validator_index}: {exception}"
                ) from exception

            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(validator_index),
                    attestation_secret_key=attestation_secret_key,
                    proposal_secret_key=proposal_secret_key,
                )
            )

        return registry
