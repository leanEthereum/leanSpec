"""Tests for Validator Registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from lean_spec.subspecs.containers import ValidatorIndex
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import ValidatorEntry, ValidatorManifestEntry


def registry_state(registry: ValidatorRegistry) -> dict[ValidatorIndex, Any]:
    """Extract full registry state as index → secret_key mapping."""
    return {idx: registry.get(idx).secret_key for idx in registry.indices()}  # type: ignore[union-attr]


class TestValidatorEntry:
    """Tests for ValidatorEntry."""

    def test_entry_is_frozen(self) -> None:
        """ValidatorEntry is immutable."""
        mock_key = MagicMock()
        entry = ValidatorEntry(index=ValidatorIndex(0), secret_key=mock_key)

        with pytest.raises(AttributeError):
            entry.index = ValidatorIndex(1)  # type: ignore[misc]


class TestValidatorRegistry:
    """Tests for ValidatorRegistry."""

    def test_empty_registry(self) -> None:
        """New registry has no entries."""
        registry = ValidatorRegistry()

        assert registry_state(registry) == {}
        assert registry.get(ValidatorIndex(99)) is None

    def test_add_single_entry(self) -> None:
        """Single entry can be added and retrieved with correct key."""
        registry = ValidatorRegistry()
        key_42 = MagicMock(name="key_42")
        registry.add(ValidatorEntry(index=ValidatorIndex(42), secret_key=key_42))

        assert registry_state(registry) == {ValidatorIndex(42): key_42}

    def test_add_multiple_entries(self) -> None:
        """Multiple entries maintain correct index-to-key mapping."""
        registry = ValidatorRegistry()
        key_1 = MagicMock(name="key_1")
        key_3 = MagicMock(name="key_3")
        key_4 = MagicMock(name="key_4")

        registry.add(ValidatorEntry(index=ValidatorIndex(3), secret_key=key_3))
        registry.add(ValidatorEntry(index=ValidatorIndex(1), secret_key=key_1))
        registry.add(ValidatorEntry(index=ValidatorIndex(4), secret_key=key_4))

        assert registry_state(registry) == {
            ValidatorIndex(1): key_1,
            ValidatorIndex(3): key_3,
            ValidatorIndex(4): key_4,
        }

    def test_from_secret_keys(self) -> None:
        """Registry from dict preserves exact index-to-key mapping."""
        key_0 = MagicMock(name="key_0")
        key_2 = MagicMock(name="key_2")

        registry = ValidatorRegistry.from_secret_keys({0: key_0, 2: key_2})

        assert registry_state(registry) == {ValidatorIndex(0): key_0, ValidatorIndex(2): key_2}


class TestValidatorRegistryFromYaml:
    """Tests for YAML loading."""

    def test_from_yaml_loads_assigned_validators(self, tmp_path: Path) -> None:
        """Registry loads only validators assigned to the specified node."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 1], "node_1": [2]}))

        manifest_file = tmp_path / "validator-keys-manifest.yaml"
        manifest_file.write_text(
            yaml.dump(
                {
                    "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
                    "hash_function": "Poseidon2",
                    "encoding": "TargetSum",
                    "lifetime": 32,
                    "log_num_active_epochs": 5,
                    "num_active_epochs": 32,
                    "num_validators": 3,
                    "validators": [
                        {"index": 0, "pubkey_hex": "0x" + "00" * 52, "privkey_file": "key_0.ssz"},
                        {"index": 1, "pubkey_hex": "0x" + "01" * 52, "privkey_file": "key_1.ssz"},
                        {"index": 2, "pubkey_hex": "0x" + "02" * 52, "privkey_file": "key_2.ssz"},
                    ],
                }
            )
        )

        (tmp_path / "key_0.ssz").write_bytes(b"key0")
        (tmp_path / "key_1.ssz").write_bytes(b"key1")

        # Use side_effect to return different keys for each call
        key_0 = MagicMock(name="key_0")
        key_1 = MagicMock(name="key_1")
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            side_effect=[key_0, key_1],
        ):
            registry = ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

        assert registry_state(registry) == {ValidatorIndex(0): key_0, ValidatorIndex(1): key_1}

    def test_from_yaml_unknown_node_returns_empty(self, tmp_path: Path) -> None:
        """Unknown node ID returns empty registry."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "validator-keys-manifest.yaml"
        manifest_file.write_text(
            yaml.dump(
                {
                    "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
                    "hash_function": "Poseidon2",
                    "encoding": "TargetSum",
                    "lifetime": 32,
                    "log_num_active_epochs": 5,
                    "num_active_epochs": 32,
                    "num_validators": 0,
                    "validators": [],
                }
            )
        )

        registry = ValidatorRegistry.from_yaml(
            node_id="unknown_node",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert registry_state(registry) == {}

    def test_from_yaml_skips_missing_manifest_entries(self, tmp_path: Path) -> None:
        """Validator indices not in manifest are skipped."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 99]}))

        manifest_file = tmp_path / "validator-keys-manifest.yaml"
        manifest_file.write_text(
            yaml.dump(
                {
                    "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
                    "hash_function": "Poseidon2",
                    "encoding": "TargetSum",
                    "lifetime": 32,
                    "log_num_active_epochs": 5,
                    "num_active_epochs": 32,
                    "num_validators": 1,
                    "validators": [
                        {"index": 0, "pubkey_hex": "0x" + "00" * 52, "privkey_file": "key_0.ssz"},
                    ],
                }
            )
        )

        (tmp_path / "key_0.ssz").write_bytes(b"key0")

        key_0 = MagicMock(name="key_0")
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            return_value=key_0,
        ):
            registry = ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

        # Only index 0 loaded (99 not in manifest)
        assert registry_state(registry) == {ValidatorIndex(0): key_0}

    def test_from_yaml_empty_file_returns_empty(self, tmp_path: Path) -> None:
        """Empty validators.yaml returns empty registry."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text("")

        manifest_file = tmp_path / "validator-keys-manifest.yaml"
        manifest_file.write_text(
            yaml.dump(
                {
                    "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
                    "hash_function": "Poseidon2",
                    "encoding": "TargetSum",
                    "lifetime": 32,
                    "log_num_active_epochs": 5,
                    "num_active_epochs": 32,
                    "num_validators": 0,
                    "validators": [],
                }
            )
        )

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert registry_state(registry) == {}

    def test_from_yaml_missing_key_file_raises(self, tmp_path: Path) -> None:
        """Missing private key file raises ValueError."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "validator-keys-manifest.yaml"
        manifest_file.write_text(
            yaml.dump(
                {
                    "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
                    "hash_function": "Poseidon2",
                    "encoding": "TargetSum",
                    "lifetime": 32,
                    "log_num_active_epochs": 5,
                    "num_active_epochs": 32,
                    "num_validators": 1,
                    "validators": [
                        {"index": 0, "pubkey_hex": "0x" + "00" * 52, "privkey_file": "missing.ssz"},
                    ],
                }
            )
        )

        with pytest.raises(ValueError, match="Private key file not found"):
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

    def test_from_yaml_invalid_key_file_raises(self, tmp_path: Path) -> None:
        """Invalid key file raises ValueError."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "validator-keys-manifest.yaml"
        manifest_file.write_text(
            yaml.dump(
                {
                    "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
                    "hash_function": "Poseidon2",
                    "encoding": "TargetSum",
                    "lifetime": 32,
                    "log_num_active_epochs": 5,
                    "num_active_epochs": 32,
                    "num_validators": 1,
                    "validators": [
                        {"index": 0, "pubkey_hex": "0x" + "00" * 52, "privkey_file": "invalid.ssz"},
                    ],
                }
            )
        )

        (tmp_path / "invalid.ssz").write_bytes(b"not valid ssz")

        with pytest.raises(ValueError, match="Failed to load private key"):
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )


class TestValidatorManifestEntry:
    """Tests for ValidatorManifestEntry pubkey parsing."""

    def test_parse_pubkey_hex_string_passthrough(self) -> None:
        """String pubkey_hex passes through unchanged."""
        entry = ValidatorManifestEntry(
            index=0,
            pubkey_hex="0x" + "ab" * 52,
            privkey_file="key.ssz",
        )
        assert entry.pubkey_hex == "0x" + "ab" * 52

    def test_parse_pubkey_hex_integer_conversion(self) -> None:
        """Integer pubkey_hex converts to padded hex string."""
        entry = ValidatorManifestEntry(
            index=0,
            pubkey_hex=0x123,  # type: ignore[arg-type]
            privkey_file="key.ssz",
        )
        # Padded to 104 hex characters (52 bytes)
        assert entry.pubkey_hex == "0x" + "0" * 101 + "123"

    def test_parse_pubkey_hex_zero(self) -> None:
        """Zero integer converts to all-zeros hex string."""
        entry = ValidatorManifestEntry(
            index=0,
            pubkey_hex=0,  # type: ignore[arg-type]
            privkey_file="key.ssz",
        )
        assert entry.pubkey_hex == "0x" + "0" * 104
