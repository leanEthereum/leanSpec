"""Tests for Validator Registry."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from consensus_testing.keys import XmssKeyManager
from pydantic import ValidationError

from lean_spec.forks.lstar.containers import ValidatorIndex
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import (
    ValidatorEntry,
    ValidatorManifest,
    ValidatorManifestEntry,
    load_node_validator_mapping,
)
from lean_spec.types import Bytes52
from lean_spec.types.exceptions import SSZValueError


def registry_state(registry: ValidatorRegistry) -> dict[ValidatorIndex, tuple[object, object]]:
    """Extract full registry state as index → (att_sk, prop_sk) mapping."""
    result: dict[ValidatorIndex, tuple[object, object]] = {}
    for idx in registry.indices():
        entry = registry.get(idx)
        assert entry is not None, f"Registry contains index {idx} but get() returned None"
        result[idx] = (entry.attestation_secret_key, entry.proposal_secret_key)
    return result


@pytest.fixture
def km() -> XmssKeyManager:
    """Key manager for registry tests."""
    return XmssKeyManager.shared(max_slot=Slot(10))


def _minimal_manifest_dict(
    *,
    num_validators: int = 0,
    validators: list[dict[str, object]] | None = None,
) -> dict[str, object]:
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


def _manifest_entry_dict(index: int, suffix: str = "") -> dict[str, object]:
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

    def test_construction_stores_all_fields(self, km: XmssKeyManager) -> None:
        """All three fields are accessible after construction."""
        kp = km[ValidatorIndex(7)]
        entry = ValidatorEntry(
            index=ValidatorIndex(7),
            attestation_secret_key=kp.attestation_secret,
            proposal_secret_key=kp.proposal_secret,
        )

        assert entry == ValidatorEntry(
            index=ValidatorIndex(7),
            attestation_secret_key=kp.attestation_secret,
            proposal_secret_key=kp.proposal_secret,
        )


class TestValidatorManifestEntry:
    """Tests for ValidatorManifestEntry Pydantic model."""

    def test_construction_stores_all_fields(self) -> None:
        """All fields are stored and accessible after construction."""
        entry = ValidatorManifestEntry(
            index=ValidatorIndex(3),
            attestation_pubkey_hex=Bytes52("0x" + "aa" * 52),
            proposal_pubkey_hex=Bytes52("0x" + "bb" * 52),
            attestation_privkey_file="att.ssz",
            proposal_privkey_file="prop.ssz",
        )

        assert entry == ValidatorManifestEntry(
            index=ValidatorIndex(3),
            attestation_pubkey_hex=Bytes52("0x" + "aa" * 52),
            proposal_pubkey_hex=Bytes52("0x" + "bb" * 52),
            attestation_privkey_file="att.ssz",
            proposal_privkey_file="prop.ssz",
        )

    def test_integer_pubkey_rejected(self) -> None:
        """Integer pubkeys are rejected — only valid 52-byte hex strings accepted."""
        with pytest.raises((TypeError, ValidationError)):
            ValidatorManifestEntry(
                index=ValidatorIndex(0),
                attestation_pubkey_hex=0x123,  # type: ignore[arg-type]
                proposal_pubkey_hex=Bytes52("0x" + "aa" * 52),
                attestation_privkey_file="att.ssz",
                proposal_privkey_file="prop.ssz",
            )

    def test_wrong_length_pubkey_rejected(self) -> None:
        """Hex strings that don't decode to exactly 52 bytes are rejected."""
        with pytest.raises((SSZValueError, ValidationError)):
            ValidatorManifestEntry(
                index=ValidatorIndex(0),
                attestation_pubkey_hex=Bytes52("0x" + "aa" * 10),
                proposal_pubkey_hex=Bytes52("0x" + "bb" * 52),
                attestation_privkey_file="att.ssz",
                proposal_privkey_file="prop.ssz",
            )


class TestValidatorManifest:
    """Tests for ValidatorManifest Pydantic model and YAML loading."""

    def test_from_yaml_file_loads_metadata(self, tmp_path: Path) -> None:
        """All top-level metadata fields are parsed correctly."""
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(_minimal_manifest_dict()))

        manifest = ValidatorManifest.from_yaml_file(manifest_file)

        assert manifest == ValidatorManifest(
            key_scheme="SIGTopLevelTargetSumLifetime32Dim64Base8",
            hash_function="Poseidon2",
            encoding="TargetSum",
            lifetime=32,
            log_num_active_epochs=5,
            num_active_epochs=32,
            num_validators=0,
            validators=[],
        )

    def test_from_yaml_file_parses_validators_list(self, tmp_path: Path) -> None:
        """Nested validators list is parsed into ValidatorManifestEntry objects."""
        entries = [_manifest_entry_dict(0), _manifest_entry_dict(1)]
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(
            yaml.dump(_minimal_manifest_dict(num_validators=2, validators=entries))
        )

        manifest = ValidatorManifest.from_yaml_file(manifest_file)

        assert manifest.validators == [
            ValidatorManifestEntry(
                index=ValidatorIndex(0),
                attestation_pubkey_hex=Bytes52("0x" + "00" * 52),
                proposal_pubkey_hex=Bytes52("0x" + "00" * 52),
                attestation_privkey_file="att_key_0.ssz",
                proposal_privkey_file="prop_key_0.ssz",
            ),
            ValidatorManifestEntry(
                index=ValidatorIndex(1),
                attestation_pubkey_hex=Bytes52("0x" + "01" * 52),
                proposal_pubkey_hex=Bytes52("0x" + "01" * 52),
                attestation_privkey_file="att_key_1.ssz",
                proposal_privkey_file="prop_key_1.ssz",
            ),
        ]


class TestLoadNodeValidatorMapping:
    """Tests for loading node-to-validator index mapping from YAML."""

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


class TestValidatorRegistry:
    """Tests for ValidatorRegistry dataclass."""

    def _entry(self, km: XmssKeyManager, idx: int) -> ValidatorEntry:
        """Create a ValidatorEntry with real keys for the given index."""
        vid = ValidatorIndex(idx)
        kp = km[vid]
        return ValidatorEntry(
            index=vid,
            attestation_secret_key=kp.attestation_secret,
            proposal_secret_key=kp.proposal_secret,
        )

    def test_empty_registry_has_no_entries(self) -> None:
        """Newly created registry contains no validators."""
        registry = ValidatorRegistry()

        assert registry_state(registry) == {}
        assert registry.primary_index() is None

    def test_add_single_entry_and_retrieve(self, km: XmssKeyManager) -> None:
        """A single entry is stored and retrievable by index."""
        registry = ValidatorRegistry()
        entry = self._entry(km, 0)
        registry.add(entry)

        assert registry.get(ValidatorIndex(0)) == entry

    def test_get_miss_returns_none(self, km: XmssKeyManager) -> None:
        """get() returns None for an index that was never added."""
        registry = ValidatorRegistry()
        registry.add(self._entry(km, 0))

        assert registry.get(ValidatorIndex(99)) is None

    def test_add_multiple_entries(self, km: XmssKeyManager) -> None:
        """Multiple entries are stored with correct index-to-key mapping."""
        registry = ValidatorRegistry()
        entries = {idx: self._entry(km, idx) for idx in [3, 1, 4]}
        for entry in entries.values():
            registry.add(entry)

        assert registry_state(registry) == {
            ValidatorIndex(1): (
                entries[1].attestation_secret_key,
                entries[1].proposal_secret_key,
            ),
            ValidatorIndex(3): (
                entries[3].attestation_secret_key,
                entries[3].proposal_secret_key,
            ),
            ValidatorIndex(4): (
                entries[4].attestation_secret_key,
                entries[4].proposal_secret_key,
            ),
        }

    def test_contains_known_index(self, km: XmssKeyManager) -> None:
        """__contains__ returns True for a registered validator index."""
        registry = ValidatorRegistry()
        registry.add(self._entry(km, 5))

        assert ValidatorIndex(5) in registry

    def test_contains_unknown_index(self) -> None:
        """__contains__ returns False for an index that was never added."""
        registry = ValidatorRegistry()

        assert ValidatorIndex(99) not in registry

    def test_len_after_adds(self, km: XmssKeyManager) -> None:
        """__len__ reflects the number of entries added."""
        registry = ValidatorRegistry()
        assert len(registry) == 0

        for i in range(4):
            registry.add(self._entry(km, i))

        assert len(registry) == 4

    def test_indices_returns_all_registered_indices(self, km: XmssKeyManager) -> None:
        """All registered indices are returned as a collection."""
        registry = ValidatorRegistry()
        for i in [2, 5, 7]:
            registry.add(self._entry(km, i))

        result = registry.indices()

        assert set(result) == {ValidatorIndex(2), ValidatorIndex(5), ValidatorIndex(7)}

    def test_primary_index_empty_registry(self) -> None:
        """Primary index is None for an empty registry."""
        assert ValidatorRegistry().primary_index() is None

    def test_primary_index_single_entry(self, km: XmssKeyManager) -> None:
        """Primary index is the only entry's index."""
        registry = ValidatorRegistry()
        registry.add(self._entry(km, 5))

        assert registry.primary_index() == ValidatorIndex(5)

    def test_primary_index_is_first_inserted(self, km: XmssKeyManager) -> None:
        """Primary index is the first inserted entry (insertion order)."""
        registry = ValidatorRegistry()
        for i in [3, 1, 7]:
            registry.add(self._entry(km, i))

        assert registry.primary_index() == ValidatorIndex(3)

    def test_add_overwrites_existing_entry(self, km: XmssKeyManager) -> None:
        """add() with an existing index replaces the entry, preserving registry size."""
        registry = ValidatorRegistry()
        old_entry = self._entry(km, 5)
        # Create a different entry for the same index using different key pairs.
        kp_att = km[ValidatorIndex(6)]
        kp_prop = km[ValidatorIndex(7)]
        new_entry = ValidatorEntry(
            index=ValidatorIndex(5),
            attestation_secret_key=kp_att.attestation_secret,
            proposal_secret_key=kp_prop.proposal_secret,
        )

        registry.add(old_entry)
        registry.add(new_entry)

        assert len(registry) == 1
        assert registry_state(registry) == {
            ValidatorIndex(5): (kp_att.attestation_secret, kp_prop.proposal_secret)
        }


def _write_manifest(path: Path, validators: list[dict[str, object]]) -> None:
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
    """Integration tests for the full YAML loading pipeline (files on disk -> registry)."""

    def _write_real_key_files(
        self, km: XmssKeyManager, directory: Path, indices: list[int]
    ) -> None:
        """Write real SSZ-encoded XMSS key files for the given validator indices."""
        for i in indices:
            vid = ValidatorIndex(i)
            kp = km[vid]
            (directory / f"att_key_{i}.ssz").write_bytes(kp.attestation_secret.encode_bytes())
            (directory / f"prop_key_{i}.ssz").write_bytes(kp.proposal_secret.encode_bytes())

    def test_happy_path_loads_assigned_validators(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """Registry loads keys only for validators assigned to the specified node."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 1], "node_1": [2]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(
            manifest_file,
            [_manifest_entry_dict(0), _manifest_entry_dict(1), _manifest_entry_dict(2)],
        )
        self._write_real_key_files(km, tmp_path, [0, 1])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert set(registry.indices()) == {ValidatorIndex(0), ValidatorIndex(1)}
        assert len(registry) == 2

        # Loaded keys should match the originals from the key manager.
        for i in [0, 1]:
            vid = ValidatorIndex(i)
            entry = registry.get(vid)
            assert entry is not None
            expected_att = km[vid].attestation_secret.encode_bytes()
            expected_prop = km[vid].proposal_secret.encode_bytes()
            assert entry.attestation_secret_key.encode_bytes() == expected_att
            assert entry.proposal_secret_key.encode_bytes() == expected_prop

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
        self, tmp_path: Path, km: XmssKeyManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Validator indices present in validators.yaml but absent from manifest are skipped."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0, 99]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])
        self._write_real_key_files(km, tmp_path, [0])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert set(registry.indices()) == {ValidatorIndex(0)}
        assert "99" in caplog.text

    def test_missing_attestation_key_file_raises(self, tmp_path: Path) -> None:
        """Missing attestation SSZ file raises ValueError with a clear message."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])

        with pytest.raises(ValueError, match="key file not found"):
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

    def test_missing_proposal_key_file_raises(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """Missing proposal SSZ file raises ValueError after the attestation key loads."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])

        # Write only attestation key, not proposal key.
        kp = km[ValidatorIndex(0)]
        (tmp_path / "att_key_0.ssz").write_bytes(kp.attestation_secret.encode_bytes())

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

    def test_corrupt_proposal_key_file_raises(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """A corrupt proposal SSZ file raises ValueError after the attestation key loads."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(manifest_file, [_manifest_entry_dict(0)])

        # Write real attestation key but corrupt proposal key.
        kp = km[ValidatorIndex(0)]
        (tmp_path / "att_key_0.ssz").write_bytes(kp.attestation_secret.encode_bytes())
        (tmp_path / "prop_key_0.ssz").write_bytes(b"not valid ssz")

        with pytest.raises(ValueError, match="Failed to load proposal key"):
            ValidatorRegistry.from_yaml(
                node_id="node_0",
                validators_path=validators_file,
                manifest_path=manifest_file,
            )

    def test_only_assigned_node_keys_are_loaded(self, tmp_path: Path, km: XmssKeyManager) -> None:
        """Keys for validators belonging to other nodes are never touched."""
        validators_file = tmp_path / "validators.yaml"
        validators_file.write_text(yaml.dump({"node_0": [0], "node_1": [1, 2]}))

        manifest_file = tmp_path / "manifest.yaml"
        _write_manifest(
            manifest_file,
            [_manifest_entry_dict(0), _manifest_entry_dict(1), _manifest_entry_dict(2)],
        )
        self._write_real_key_files(km, tmp_path, [0])

        registry = ValidatorRegistry.from_yaml(
            node_id="node_0",
            validators_path=validators_file,
            manifest_path=manifest_file,
        )

        assert set(registry.indices()) == {ValidatorIndex(0)}
        assert ValidatorIndex(1) not in registry
        assert ValidatorIndex(2) not in registry
