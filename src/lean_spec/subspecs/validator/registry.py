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
       hash_function: Poseidon2
       num_validators: 3
       validators:
       - index: 0
         pubkey_hex: 0xe2a03c...
         privkey_file: validator_0_sk.ssz
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator

from lean_spec.subspecs.xmss import SecretKey
from lean_spec.types import Uint64

# Type alias for node-to-validator mapping from validators.yaml
NodeValidatorMapping = dict[str, list[int]]
"""Mapping from node identifier to list of validator indices."""


class ValidatorManifestEntry(BaseModel):
    """Single validator entry from the manifest file."""

    index: int
    """Validator index in the registry."""

    pubkey_hex: str
    """Public key as hex string with 0x prefix."""

    privkey_file: str
    """Filename of the private key file (e.g., validator_0_sk.ssz)."""

    @field_validator("pubkey_hex", mode="before")
    @classmethod
    def parse_pubkey_hex(cls, v: str | int) -> str:
        """
        Convert integer to hex string if needed.

        YAML parsers may interpret 0x-prefixed values as integers.
        """
        if isinstance(v, int):
            # Convert to 0x-prefixed hex string, padded to 52 bytes (104 chars).
            return f"0x{v:0104x}"
        return v


class ValidatorManifest(BaseModel):
    """
    Key metadata from validator-keys-manifest.yaml.

    Contains cryptographic scheme info and validator key paths.
    This format matches ream's manifest structure.
    """

    key_scheme: str
    """Signature scheme identifier (e.g., SIGTopLevelTargetSumLifetime32Dim64Base8)."""

    hash_function: str
    """Hash function used (e.g., Poseidon2)."""

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

    The file maps node identifiers to lists of validator indices:

        ream_0:
        - 0
        - 1
        zeam_0:
        - 2

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

    Holds both the index and the secret key needed for signing.
    """

    index: Uint64
    """Validator index in the registry."""

    secret_key: SecretKey
    """XMSS secret key for signing."""


@dataclass(slots=True)
class ValidatorRegistry:
    """
    Registry of validator keys controlled by this node.

    The registry holds secret keys for validators assigned to this node.
    It provides lookup by validator index for signing operations.
    """

    _validators: dict[Uint64, ValidatorEntry] = field(default_factory=dict)
    """Map from validator index to entry."""

    def add(self, entry: ValidatorEntry) -> None:
        """
        Add a validator entry to the registry.

        Args:
            entry: Validator entry to add.
        """
        self._validators[entry.index] = entry

    def get(self, index: Uint64) -> ValidatorEntry | None:
        """
        Get validator entry by index.

        Args:
            index: Validator index to look up.

        Returns:
            Validator entry if found, None otherwise.
        """
        return self._validators.get(index)

    def has(self, index: Uint64) -> bool:
        """
        Check if we control this validator.

        Args:
            index: Validator index to check.

        Returns:
            True if we have keys for this validator.
        """
        return index in self._validators

    def indices(self) -> list[Uint64]:
        """
        Get all validator indices we control.

        Returns:
            List of validator indices.
        """
        return list(self._validators.keys())

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

        Compatible with ream's YAML format.

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
            entry = manifest_by_index.get(index)
            if entry is None:
                continue

            # Load secret key from SSZ file.
            privkey_path = manifest_dir / entry.privkey_file
            secret_key = SecretKey.decode_bytes(privkey_path.read_bytes())

            registry.add(
                ValidatorEntry(
                    index=Uint64(index),
                    secret_key=secret_key,
                )
            )

        return registry

    @classmethod
    def from_secret_keys(cls, keys: dict[int, SecretKey]) -> ValidatorRegistry:
        """
        Create registry from a dictionary of secret keys.

        Convenience method for testing or programmatic key loading.

        Args:
            keys: Mapping from validator index to secret key.

        Returns:
            Registry populated with provided keys.
        """
        registry = cls()
        for index, secret_key in keys.items():
            registry.add(ValidatorEntry(index=Uint64(index), secret_key=secret_key))
        return registry
