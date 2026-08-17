"""Tests for protection against spending one validator key twice in a slot."""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from consensus_testing import MockNetworkRequester
from consensus_testing.keys import XmssKeyManager
from lean_spec.node.chain.clock import SlotClock
from lean_spec.node.storage import SQLiteDatabase
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.node.sync.peer_manager import PeerManager
from lean_spec.node.sync.service import SyncService
from lean_spec.node.validator import (
    SigningProtection,
    SigningProtectionError,
    ValidatorRegistry,
    ValidatorService,
)
from lean_spec.node.validator.registry import ValidatorEntry
from lean_spec.node.validator.service import AttestationPublisher
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import State, Store
from lean_spec.spec.forks.lstar.containers import Block, SignedAttestation
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32, Uint64

_VALIDATOR = ValidatorIndex(0)


@pytest.fixture
def database_path() -> Generator[Path, None, None]:
    """Path to a SQLite file that outlives a single database instance."""
    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory) / "node.sqlite"


def _open_database(path: Path) -> SQLiteDatabase:
    """Open the node database at a path, creating it on first use."""
    return SQLiteDatabase(path, State, Block)


def _make_registry(key_manager: XmssKeyManager, *indices: int) -> ValidatorRegistry:
    """Build a registry holding real XMSS keys for the given validators."""
    registry = ValidatorRegistry()
    for index in indices:
        validator_index = ValidatorIndex(index)
        keypairs = key_manager[validator_index]
        registry.add(
            ValidatorEntry(
                index=validator_index,
                attestation_secret_key=keypairs.attestation_keypair.secret_key,
                proposal_secret_key=keypairs.proposal_keypair.secret_key,
            )
        )
    return registry


def _make_service(
    store: Store,
    key_manager: XmssKeyManager,
    database: SQLiteDatabase | None = None,
    *indices: int,
    on_attestation: AttestationPublisher | None = None,
) -> ValidatorService:
    """Build a validator service, optionally backed by a database."""
    sync_service = SyncService(
        store=store,
        peer_manager=PeerManager(),
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0)),
        network=MockNetworkRequester(),
        database=database,
    )
    return ValidatorService(
        sync_service=sync_service,
        clock=SlotClock(genesis_time=Uint64(0)),
        registry=_make_registry(key_manager, *(indices or (0,))),
        spec=LstarSpec(),
        on_attestation=on_attestation,
    )


def _make_block(store: Store, slot: int) -> Block:
    """Build a block at a slot, descending from the store head."""
    return Block(
        slot=Slot(slot),
        proposer_index=_VALIDATOR,
        parent_root=store.head,
        state_root=store.head,
        body=store.blocks[store.head].body,
    )


class TestReserve:
    """Unit tests for the slot claim itself."""

    def test_should_allow_first_signature_when_key_is_unused(self) -> None:
        """A key that never signed can claim any slot."""
        protection = SigningProtection()

        protection.reserve(_VALIDATOR, "attestation", Slot(3))

        assert protection.last_signed_slot(_VALIDATOR, "attestation") == Slot(3)

    def test_should_reject_second_signature_when_slot_already_signed(self) -> None:
        """Claiming the same slot twice raises rather than reusing the key."""
        protection = SigningProtection()
        protection.reserve(_VALIDATOR, "attestation", Slot(3))

        with pytest.raises(SigningProtectionError, match="would reuse a one-time key"):
            protection.reserve(_VALIDATOR, "attestation", Slot(3))

    def test_should_reject_signature_when_slot_moves_backwards(self) -> None:
        """A backward clock step cannot re-open an already spent slot."""
        protection = SigningProtection()
        protection.reserve(_VALIDATOR, "attestation", Slot(7))

        with pytest.raises(SigningProtectionError):
            protection.reserve(_VALIDATOR, "attestation", Slot(6))

    def test_should_allow_signature_when_slot_advances(self) -> None:
        """Later slots claim their own one-time key."""
        protection = SigningProtection()
        protection.reserve(_VALIDATOR, "attestation", Slot(3))

        protection.reserve(_VALIDATOR, "attestation", Slot(4))

        assert protection.last_signed_slot(_VALIDATOR, "attestation") == Slot(4)

    def test_should_track_roles_separately(self) -> None:
        """A proposal and an attestation in one slot use separate keys."""
        protection = SigningProtection()

        protection.reserve(_VALIDATOR, "proposal", Slot(3))
        protection.reserve(_VALIDATOR, "attestation", Slot(3))

        assert protection.last_signed_slot(_VALIDATOR, "proposal") == Slot(3)
        assert protection.last_signed_slot(_VALIDATOR, "attestation") == Slot(3)

    def test_should_track_validators_separately(self) -> None:
        """One validator's spent slot leaves another validator's key free."""
        protection = SigningProtection()
        other_validator = ValidatorIndex(1)

        protection.reserve(_VALIDATOR, "attestation", Slot(3))
        protection.reserve(other_validator, "attestation", Slot(3))

        assert protection.last_signed_slot(other_validator, "attestation") == Slot(3)

    def test_should_report_not_durable_when_no_database_is_configured(self) -> None:
        """Records kept in the process do not survive a restart."""
        assert SigningProtection().is_durable is False


class TestDatabaseBackedReserve:
    """Records held in the node database."""

    def test_should_report_durable_when_database_is_configured(self, database_path: Path) -> None:
        """A configured database makes the records survive a restart."""
        with _open_database(database_path) as database:
            assert SigningProtection(database=database).is_durable is True

    def test_should_commit_the_claim_before_returning(self, database_path: Path) -> None:
        """The record is committed on its own, not left for a later batch."""
        with _open_database(database_path) as database:
            SigningProtection(database=database).reserve(_VALIDATOR, "attestation", Slot(3))

        # A fresh connection sees the row only if the write already committed.
        with _open_database(database_path) as reopened:
            assert reopened.get_last_signed_slot(_VALIDATOR, "attestation") == Slot(3)

    def test_should_reject_slot_reserved_by_an_earlier_database_instance(
        self, database_path: Path
    ) -> None:
        """The claim outlives the process that made it."""
        with _open_database(database_path) as first:
            SigningProtection(database=first).reserve(_VALIDATOR, "attestation", Slot(3))

        with _open_database(database_path) as second:
            with pytest.raises(SigningProtectionError):
                SigningProtection(database=second).reserve(_VALIDATOR, "attestation", Slot(3))


class TestServiceSigning:
    """The guard as it applies at the service's signing boundary."""

    def test_should_adopt_the_node_database(
        self, keyed_store: Store, key_manager: XmssKeyManager, database_path: Path
    ) -> None:
        """A service whose sync layer persists gets durable protection."""
        with _open_database(database_path) as database:
            service = _make_service(keyed_store, key_manager, database)

            assert service.signing_protection.is_durable is True

    def test_should_stay_in_memory_without_a_node_database(
        self, keyed_store: Store, key_manager: XmssKeyManager
    ) -> None:
        """A service without persistence keeps process-local records."""
        service = _make_service(keyed_store, key_manager)

        assert service.signing_protection.is_durable is False

    def test_should_sign_a_block_once_per_slot(
        self, keyed_store: Store, key_manager: XmssKeyManager
    ) -> None:
        """The first proposal for a slot signs and records the slot."""
        service = _make_service(keyed_store, key_manager)
        block = _make_block(keyed_store, slot=1)

        service._sign_block(block, _VALIDATOR, [])

        assert service.signing_protection.last_signed_slot(_VALIDATOR, "proposal") == Slot(1)

    def test_should_refuse_a_second_block_for_a_signed_slot(
        self, keyed_store: Store, key_manager: XmssKeyManager
    ) -> None:
        """Re-proposing a slot with a different block is refused, not signed."""
        service = _make_service(keyed_store, key_manager)
        service._sign_block(_make_block(keyed_store, slot=1), _VALIDATOR, [])

        # A different state root gives a different block root, so a second
        # signature here would open the slot's one-time key.
        divergent_block = _make_block(keyed_store, slot=1)
        divergent_block = Block(
            slot=divergent_block.slot,
            proposer_index=divergent_block.proposer_index,
            parent_root=divergent_block.parent_root,
            state_root=Bytes32(b"\x01" * 32),
            body=divergent_block.body,
        )

        with pytest.raises(SigningProtectionError):
            service._sign_block(divergent_block, _VALIDATOR, [])

    def test_should_refuse_a_slot_signed_before_a_restart(
        self, keyed_store: Store, key_manager: XmssKeyManager, database_path: Path
    ) -> None:
        """A crash and restart inside a slot cannot sign that slot again.

        This is the case an in-memory guard misses: the replacement service has
        no memory of the first signature and only the database record stops it.
        """
        # Before the crash: propose at slot 1 with persistence enabled.
        with _open_database(database_path) as database:
            service = _make_service(keyed_store, key_manager, database)
            service._sign_block(_make_block(keyed_store, slot=1), _VALIDATOR, [])

        # After the restart: a new service, a new database handle, the same slot.
        with _open_database(database_path) as reopened:
            restarted = _make_service(keyed_store, key_manager, reopened)
            assert restarted.signing_protection.last_signed_slot(_VALIDATOR, "proposal") == Slot(1)

            with pytest.raises(SigningProtectionError):
                restarted._sign_block(_make_block(keyed_store, slot=1), _VALIDATOR, [])


class TestDutySkipsOnRefusal:
    """A refused signature skips the duty instead of failing the duty loop."""

    async def test_should_skip_only_the_validator_whose_key_is_spent(
        self, keyed_store: Store, key_manager: XmssKeyManager
    ) -> None:
        """One spent attestation key must not silence the other validators."""
        published: list[SignedAttestation] = []

        async def capture(attestation: SignedAttestation) -> None:
            published.append(attestation)

        service = _make_service(keyed_store, key_manager, None, 0, 1, on_attestation=capture)
        service.signing_protection.reserve(_VALIDATOR, "attestation", Slot(0))

        await service._produce_attestations(Slot(0))

        assert [int(attestation.validator_index) for attestation in published] == [1]

    async def test_should_skip_block_production_when_proposal_key_is_spent(
        self, keyed_store: Store, key_manager: XmssKeyManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A spent proposal key skips the proposal rather than raising into the duty loop."""
        service = _make_service(keyed_store, key_manager)
        service.signing_protection.reserve(_VALIDATOR, "proposal", Slot(8))

        with caplog.at_level(logging.WARNING):
            await service._maybe_produce_block(Slot(8))

        assert "would reuse a one-time key" in caplog.text
        assert service.blocks_produced == 0
