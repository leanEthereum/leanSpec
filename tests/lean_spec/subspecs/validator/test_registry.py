"""Tests for Validator Registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from lean_spec.subspecs.containers import ValidatorIndex
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import (
    ValidatorEntry,
    ValidatorManifest,
    ValidatorManifestEntry,
    load_node_validator_mapping,
)


def registry_state(registry: ValidatorRegistry) -> dict[ValidatorIndex, tuple[Any, Any]]:
    """Extract full registry state as index → (att_sk, prop_sk) mapping."""
    return {
        idx: (
            registry.get(idx).attestation_secret_key,  # type: ignore[union-attr]
            registry.get(idx).proposal_secret_key,  # type: ignore[union-attr]
        )
        for idx in registry.indices()
    }


def _minimal_manifest_dict(
    *,
    num_validators: int = 0,
    validators: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a minimal valid manifest dict, optionally with validators."""
    return {
        "key_scheme": "SIGTopLevelTargetSumLifetime32Dim64Base8",
        "hash_function": "Poseidon2",
        "encoding": "TargetSum",
        "lifetime": 32,
        "log_num_active_epochs": 5,
        "num_active_epochs": 32,
        "num_validators": num_validators,
        "validators": validators or [],
    }


def _manifest_entry_dict(index: int, suffix: str = "") -> dict[str, Any]:
    """Return a manifest entry dict for a validator at the given index."""
    return {
        "index": index,
        "attestation_pubkey_hex": "0x" + f"{index:02d}" * 52,
        "proposal_pubkey_hex": "0x" + f"{index:02d}" * 52,
        "attestation_privkey_file": f"att_key_{index}{suffix}.ssz",
        "proposal_privkey_file": f"prop_key_{index}{suffix}.ssz",
    }


class TestValidatorEntry:
    """Tests for ValidatorEntry frozen dataclass."""

    def test_construction_stores_all_fields(self) -> None:
        """All three fields are accessible after construction."""
        att_key = MagicMock(name="att_key")
        prop_key = MagicMock(name="prop_key")
        entry = ValidatorEntry(
            index=ValidatorIndex(7),
            attestation_secret_key=att_key,
            proposal_secret_key=prop_key,
        )

        assert entry.index == ValidatorIndex(7)
        assert entry.attestation_secret_key is att_key
        assert entry.proposal_secret_key is prop_key

    def test_attestation_and_proposal_keys_are_independent(self) -> None:
        """Attestation and proposal keys can be distinct objects."""
        att_key = MagicMock(name="att")
        prop_key = MagicMock(name="prop")
        entry = ValidatorEntry(
            index=ValidatorIndex(0),
            attestation_secret_key=att_key,
            proposal_secret_key=prop_key,
        )

        assert entry.attestation_secret_key is not entry.proposal_secret_key

    def test_entry_is_frozen(self) -> None:
        """ValidatorEntry rejects attribute assignment after construction."""
        mock_key = MagicMock()
        entry = ValidatorEntry(
            index=ValidatorIndex(0),
            attestation_secret_key=mock_key,
            proposal_secret_key=mock_key,
        )

        with pytest.raises(AttributeError):
            entry.index = ValidatorIndex(1)  # type: ignore[misc]


class TestValidatorManifestEntry:
    """Tests for ValidatorManifestEntry Pydantic model."""

    def test_construction_stores_all_fields(self) -> None:
        """All fields are stored and accessible after construction."""
        entry = ValidatorManifestEntry(
            index=3,
            attestation_pubkey_hex="0x" + "aa" * 52,
            proposal_pubkey_hex="0x" + "bb" * 52,
            attestation_privkey_file="att.ssz",
            proposal_privkey_file="prop.ssz",
        )

        assert entry.index == 3
        assert entry.attestation_pubkey_hex == "0x" + "aa" * 52
        assert entry.proposal_pubkey_hex == "0x" + "bb" * 52
        assert entry.attestation_privkey_file == "att.ssz"
        assert entry.proposal_privkey_file == "prop.ssz"

    def test_string_pubkey_hex_passthrough(self) -> None:
        """Hex string pubkeys are returned unchanged."""
        entry = ValidatorManifestEntry(
            index=0,
            attestation_pubkey_hex="0x" + "ab" * 52,
            proposal_pubkey_hex="0x" + "cd" * 52,
            attestation_privkey_file="att.ssz",
            proposal_privkey_file="prop.ssz",
        )

        assert entry.attestation_pubkey_hex == "0x" + "ab" * 52
        assert entry.proposal_pubkey_hex == "0x" + "cd" * 52

    def test_integer_pubkey_hex_conversion(self) -> None:
        """Integer pubkeys are zero-padded to 52-byte (104-char) hex strings."""
        entry = ValidatorManifestEntry(
            index=0,
            attestation_pubkey_hex=0x123,  # type: ignore[arg-type]
            proposal_pubkey_hex=0x456,  # type: ignore[arg-type]
            attestation_privkey_file="att.ssz",
            proposal_privkey_file="prop.ssz",
        )

        assert entry.attestation_pubkey_hex == "0x" + "0" * 101 + "123"
        assert entry.proposal_pubkey_hex == "0x" + "0" * 101 + "456"

    def test_zero_integer_pubkey_hex(self) -> None:
        """Zero integer produces an all-zeros hex string."""
        entry = ValidatorManifestEntry(
            index=0,
            attestation_pubkey_hex=0,  # type: ignore[arg-type]
            proposal_pubkey_hex=0,  # type: ignore[arg-type]
            attestation_privkey_file="att.ssz",
            proposal_privkey_file="prop.ssz",
        )

        assert entry.attestation_pubkey_hex == "0x" + "0" * 104
        assert entry.proposal_pubkey_hex == "0x" + "0" * 104

    def test_large_integer_pubkey_hex_fits_in_104_chars(self) -> None:
        """Large integers are still padded to exactly 104 hex chars."""
        large = int("ff" * 52, 16)
        entry = ValidatorManifestEntry(
            index=0,
            attestation_pubkey_hex=large,  # type: ignore[arg-type]
            proposal_pubkey_hex=large,  # type: ignore[arg-type]
            attestation_privkey_file="att.ssz",
            proposal_privkey_file="prop.ssz",
        )

        assert entry.attestation_pubkey_hex == "0x" + "ff" * 52
        assert len(entry.attestation_pubkey_hex) == 2 + 104  # "0x" + 104 hex chars


class TestValidatorManifest:
    """Tests for ValidatorManifest Pydantic model and from_yaml_file()."""

    def test_from_yaml_file_loads_metadata(self, tmp_path: Path) -> None:
        """All top-level metadata fields are parsed correctly."""
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(_minimal_manifest_dict()))

        manifest = ValidatorManifest.from_yaml_file(manifest_file)

        assert manifest.key_scheme == "SIGTopLevelTargetSumLifetime32Dim64Base8"
        assert manifest.hash_function == "Poseidon2"
        assert manifest.encoding == "TargetSum"
        assert manifest.lifetime == 32
        assert manifest.log_num_active_epochs == 5
        assert manifest.num_active_epochs == 32
        assert manifest.num_validators == 0
        assert manifest.validators == []

    def test_from_yaml_file_parses_validators_list(self, tmp_path: Path) -> None:
        """Nested validators list is parsed into ValidatorManifestEntry objects."""
        entries = [_manifest_entry_dict(0), _manifest_entry_dict(1)]
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(
            yaml.dump(_minimal_manifest_dict(num_validators=2, validators=entries))
        )

        manifest = ValidatorManifest.from_yaml_file(manifest_file)

        assert len(manifest.validators) == 2
        assert all(isinstance(e, ValidatorManifestEntry) for e in manifest.validators)
        assert manifest.validators[0].index == 0
        assert manifest.validators[1].index == 1

    def test_from_yaml_file_entry_fields_preserved(self, tmp_path: Path) -> None:
        """All fields of a ValidatorManifestEntry are preserved when loaded."""
        entry = {
            "index": 5,
            "attestation_pubkey_hex": "0x" + "5a" * 52,
            "proposal_pubkey_hex": "0x" + "5b" * 52,
            "attestation_privkey_file": "att_5.ssz",
            "proposal_privkey_file": "prop_5.ssz",
        }
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(
            yaml.dump(_minimal_manifest_dict(num_validators=1, validators=[entry]))
        )

        manifest = ValidatorManifest.from_yaml_file(manifest_file)

        v = manifest.validators[0]
        assert v.index == 5
        assert v.attestation_pubkey_hex == "0x" + "5a" * 52
        assert v.proposal_pubkey_hex == "0x" + "5b" * 52
        assert v.attestation_privkey_file == "att_5.ssz"
        assert v.proposal_privkey_file == "prop_5.ssz"


class TestLoadNodeValidatorMapping:
    """Tests for load_node_validator_mapping()."""

    def test_normal_loading_multiple_nodes(self, tmp_path: Path) -> None:
        """Multiple node entries are loaded into the correct structure."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 1], "node_1": [2, 3], "node_2": [4]}))

        mapping = load_node_validator_mapping(validators_file)

        assert mapping == {"node_0": [0, 1], "node_1": [2, 3], "node_2": [4]}

    def test_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        """An empty YAML file (parses to None) returns an empty dict."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text("")

        mapping = load_node_validator_mapping(validators_file)

        assert mapping == {}

    def test_single_node_multiple_indices(self, tmp_path: Path) -> None:
        """A single node with several indices is loaded correctly."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"lean_spec_0": [0, 1, 2, 3]}))

        mapping = load_node_validator_mapping(validators_file)

        assert mapping == {"lean_spec_0": [0, 1, 2, 3]}

    def test_single_node_single_index(self, tmp_path: Path) -> None:
        """A single node with exactly one index is loaded correctly."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_a": [7]}))

        mapping = load_node_validator_mapping(validators_file)

        assert mapping == {"node_a": [7]}


class TestValidatorRegistry:
    """Tests for ValidatorRegistry dataclass."""

    def test_empty_registry_has_no_entries(self) -> None:
        """Newly created registry contains no validators."""
        registry = ValidatorRegistry()

        assert len(registry) == 0
        assert registry.get(ValidatorIndex(0)) is None
        assert registry.primary_index() is None

    def test_add_single_entry_and_retrieve(self) -> None:
        """An entry added by add() is retrievable by get()."""
        registry = ValidatorRegistry()
        key = MagicMock(name="key_42")
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(42),
                attestation_secret_key=key,
                proposal_secret_key=key,
            )
        )

        retrieved = registry.get(ValidatorIndex(42))
        assert retrieved is not None
        assert retrieved.index == ValidatorIndex(42)
        assert retrieved.attestation_secret_key is key

    def test_get_miss_returns_none(self) -> None:
        """get() returns None for an index that was never added."""
        registry = ValidatorRegistry()
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(0),
                attestation_secret_key=MagicMock(),
                proposal_secret_key=MagicMock(),
            )
        )

        assert registry.get(ValidatorIndex(99)) is None

    def test_add_multiple_entries(self) -> None:
        """Multiple entries are stored with correct index-to-key mapping."""
        registry = ValidatorRegistry()
        key_1, key_3, key_4 = MagicMock(), MagicMock(), MagicMock()

        for idx, key in [(3, key_3), (1, key_1), (4, key_4)]:
            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(idx),
                    attestation_secret_key=key,
                    proposal_secret_key=key,
                )
            )

        assert registry_state(registry) == {
            ValidatorIndex(1): (key_1, key_1),
            ValidatorIndex(3): (key_3, key_3),
            ValidatorIndex(4): (key_4, key_4),
        }

    def test_contains_known_index(self) -> None:
        """__contains__ returns True for a registered validator index."""
        registry = ValidatorRegistry()
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(5),
                attestation_secret_key=MagicMock(),
                proposal_secret_key=MagicMock(),
            )
        )

        assert ValidatorIndex(5) in registry

    def test_contains_unknown_index(self) -> None:
        """__contains__ returns False for an index that was never added."""
        registry = ValidatorRegistry()

        assert ValidatorIndex(99) not in registry

    def test_len_after_adds(self) -> None:
        """__len__ reflects the number of entries added."""
        registry = ValidatorRegistry()
        assert len(registry) == 0

        for i in range(4):
            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(i),
                    attestation_secret_key=MagicMock(),
                    proposal_secret_key=MagicMock(),
                )
            )

        assert len(registry) == 4

    def test_indices_returns_all_registered_indices(self) -> None:
        """indices() returns a ValidatorIndices containing every registered index."""
        registry = ValidatorRegistry()
        for i in [2, 5, 8]:
            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(i),
                    attestation_secret_key=MagicMock(),
                    proposal_secret_key=MagicMock(),
                )
            )

        result = registry.indices()

        assert set(result) == {ValidatorIndex(2), ValidatorIndex(5), ValidatorIndex(8)}

    def test_primary_index_empty_registry(self) -> None:
        """primary_index() returns None for an empty registry."""
        assert ValidatorRegistry().primary_index() is None

    def test_primary_index_single_entry(self) -> None:
        """primary_index() returns the only entry's index."""
        registry = ValidatorRegistry()
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(5),
                attestation_secret_key=MagicMock(),
                proposal_secret_key=MagicMock(),
            )
        )

        assert registry.primary_index() == ValidatorIndex(5)

    def test_primary_index_is_first_inserted(self) -> None:
        """primary_index() returns the index of the first inserted entry."""
        registry = ValidatorRegistry()
        for i in [3, 1, 7]:
            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(i),
                    attestation_secret_key=MagicMock(),
                    proposal_secret_key=MagicMock(),
                )
            )

        assert registry.primary_index() == ValidatorIndex(3)

    def test_from_secret_keys(self) -> None:
        """from_secret_keys() populates the registry from a dict of key pairs."""
        key_0_att, key_0_prop = MagicMock(), MagicMock()
        key_2_att, key_2_prop = MagicMock(), MagicMock()

        registry = ValidatorRegistry.from_secret_keys(
            {
                ValidatorIndex(0): (key_0_att, key_0_prop),
                ValidatorIndex(2): (key_2_att, key_2_prop),
            }
        )

        assert registry_state(registry) == {
            ValidatorIndex(0): (key_0_att, key_0_prop),
            ValidatorIndex(2): (key_2_att, key_2_prop),
        }


def _write_manifest(path: Path, validators: list[dict[str, Any]]) -> None:
    """Write a minimal manifest YAML file at path."""
    path.write_text(
        yaml.dump(_minimal_manifest_dict(num_validators=len(validators), validators=validators))
    )


def _write_key_files(directory: Path, indices: list[int]) -> None:
    """Write dummy SSZ key file stubs for the given validator indices."""
    for i in indices:
        (directory / f"att_key_{i}.ssz").write_bytes(b"att" + bytes([i]))
        (directory / f"prop_key_{i}.ssz").write_bytes(b"prop" + bytes([i]))


class TestValidatorRegistryFromYaml:
    """Integration tests for ValidatorRegistry.from_yaml()."""

    def test_happy_path_loads_assigned_validators(self, tmp_path: Path) -> None:
        """Registry loads keys only for validators assigned to the specified node."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 1], "node_1": [2]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(
            manifest_file,
            [_manifest_entry_dict(0), _manifest_entry_dict(1), _manifest_entry_dict(2)],
        )
        _write_key_files(tmp_path, [0, 1])

        att_0, prop_0, att_1, prop_1 = (
            MagicMock(name=n) for n in ["att_0", "prop_0", "att_1", "prop_1"]
        )

        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            side_effect=[att_0, prop_0, att_1, prop_1],
        ):
            registry = ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

        assert registry_state(registry) == {
            ValidatorIndex(0): (att_0, prop_0),
            ValidatorIndex(1): (att_1, prop_1),
        }

    def test_unknown_node_returns_empty_registry(self, tmp_path: Path) -> None:
        """An unrecognised node ID produces an empty registry without error."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [])

        registry = ValidatorRegistry.from_yaml(
            node_id="ghost_node",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert registry_state(registry) == {}
        assert len(registry) == 0

    def test_empty_validators_file_returns_empty_registry(self, tmp_path: Path) -> None:
        """An empty validators.yaml produces an empty registry."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text("")

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert registry_state(registry) == {}

    def test_missing_manifest_entry_logs_warning_and_skips(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Validator indices present in validators.yaml but absent from manifest are skipped."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 99]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])
        _write_key_files(tmp_path, [0])

        att_0, prop_0 = MagicMock(), MagicMock()
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            side_effect=[att_0, prop_0],
        ):
            registry = ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

        # Index 99 is silently skipped; index 0 is loaded normally.
        assert registry_state(registry) == {ValidatorIndex(0): (att_0, prop_0)}
        assert "99" in caplog.text

    def test_missing_attestation_key_file_raises(self, tmp_path: Path) -> None:
        """Missing attestation SSZ file raises ValueError with a clear message."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])
        # Deliberately omit key files.

        with pytest.raises(ValueError, match="key file not found"):
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

    def test_missing_proposal_key_file_raises(self, tmp_path: Path) -> None:
        """Missing proposal SSZ file raises ValueError after the attestation key loads."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])

        # Provide attestation key but not proposal key.
        (tmp_path / "att_key_0.ssz").write_bytes(b"att0")

        att_0 = MagicMock()
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            side_effect=[att_0, FileNotFoundError("no prop key")],
        ):
            with pytest.raises(ValueError, match="key file not found"):
                ValidatorRegistry.from_yaml(
                    node_id="node_0",
                    validators_path=validators_file,
                    manifest_path=manifest_file,
                )

    def test_corrupt_attestation_key_file_raises(self, tmp_path: Path) -> None:
        """A corrupt attestation SSZ file raises ValueError with a clear message."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])
        (tmp_path / "att_key_0.ssz").write_bytes(b"not valid ssz")
        (tmp_path / "prop_key_0.ssz").write_bytes(b"prop0")

        with pytest.raises(ValueError, match="Failed to load attestation key"):
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

    def test_corrupt_proposal_key_file_raises(self, tmp_path: Path) -> None:
        """A corrupt proposal SSZ file raises ValueError after the attestation key loads."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])
        (tmp_path / "att_key_0.ssz").write_bytes(b"att0")
        (tmp_path / "prop_key_0.ssz").write_bytes(b"not valid ssz")

        att_0 = MagicMock()
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            side_effect=[att_0, Exception("decode failed")],
        ):
            with pytest.raises(ValueError, match="Failed to load proposal key"):
                ValidatorRegistry.from_yaml(
                    node_id="node_0",
                    validators_path=validators_file,
                    manifest_path=manifest_file,
                )

    def test_only_assigned_node_keys_are_loaded(self, tmp_path: Path) -> None:
        """Keys for validators belonging to other nodes are never touched."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0], "node_1": [1, 2]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(
            manifest_file,
            [_manifest_entry_dict(0), _manifest_entry_dict(1), _manifest_entry_dict(2)],
        )
        _write_key_files(tmp_path, [0])  # Only node_0's key files exist.

        att_0, prop_0 = MagicMock(), MagicMock()
        with patch(
            "lean_spec.subspecs.xmss.SecretKey.decode_bytes",
            side_effect=[att_0, prop_0],
        ):
            registry = ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

        # Only validator 0 is in the registry; node_1's validators are untouched.
        assert registry_state(registry) == {ValidatorIndex(0): (att_0, prop_0)}
        assert ValidatorIndex(1) not in registry
        assert ValidatorIndex(2) not in registry
