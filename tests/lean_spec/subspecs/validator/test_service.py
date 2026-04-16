"""Tests for Validator Service."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.chain.config import MILLISECONDS_PER_INTERVAL
from lean_spec.subspecs.containers import (
    AttestationData,
    Block,
    SignedAttestation,
    SignedBlock,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.subspecs.sync.service import SyncService
from lean_spec.subspecs.validator import ValidatorRegistry, ValidatorService
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import (
    TEST_VALIDATOR_ID,
    MockNetworkRequester,
    make_aggregated_proof,
    make_signed_block,
    make_store,
)

# Patch target for the XMSS scheme reference inside service.py.
_SCHEME = "lean_spec.subspecs.validator.service.TARGET_SIGNATURE_SCHEME"

_INTERVAL_SECONDS = int(MILLISECONDS_PER_INTERVAL) / 1000


def _interval_time(slot: int, interval: int) -> float:
    """Return seconds since genesis for a specific slot and interval."""
    total = slot * 5 + interval
    return total * _INTERVAL_SECONDS


def _make_registry(key_manager: XmssKeyManager, *indices: int) -> ValidatorRegistry:
    """Build a ValidatorRegistry with real XMSS keys for the given indices."""
    registry = ValidatorRegistry()
    for i in indices:
        vid = ValidatorIndex(i)
        kp = key_manager[vid]
        registry.add(
            ValidatorEntry(
                index=vid,
                attestation_secret_key=kp.attestation_secret,
                proposal_secret_key=kp.proposal_secret,
            )
        )
    return registry


def _make_entry(key_manager: XmssKeyManager, index: int = 0) -> ValidatorEntry:
    """Return a ValidatorEntry with real XMSS keys."""
    vid = ValidatorIndex(index)
    kp = key_manager[vid]
    return ValidatorEntry(
        index=vid,
        attestation_secret_key=kp.attestation_secret,
        proposal_secret_key=kp.proposal_secret,
    )


@pytest.fixture
def sync_service(keyed_store: Store) -> SyncService:
    """Sync service backed by a store with real XMSS keys."""
    return SyncService(
        store=keyed_store,
        peer_manager=PeerManager(),
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0)),
        network=MockNetworkRequester(),
    )


@pytest.fixture
def real_registry(key_manager: XmssKeyManager) -> ValidatorRegistry:
    """Registry with real XMSS keys for all 8 validators."""
    return _make_registry(key_manager, *range(8))


class TestSignBlock:
    """Unit tests for block signing with real XMSS keys and signature verification."""

    def _setup(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
        *,
        slot: int = 1,
    ) -> tuple[ValidatorService, Block]:
        registry = _make_registry(key_manager, 0)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        block = Block(
            slot=Slot(slot),
            proposer_index=ValidatorIndex(0),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )
        return service, block

    def test_wraps_the_input_block(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """The returned signed block contains the exact block object that was passed in."""
        service, block = self._setup(sync_service, key_manager)

        result = service._sign_block(block, ValidatorIndex(0), [])

        assert result.block is block

    def test_proposer_signature_is_cryptographically_valid(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """The proposer signature verifies with the proposer's public key."""
        service, block = self._setup(sync_service, key_manager)

        result = service._sign_block(block, ValidatorIndex(0), [])

        public_key = key_manager[ValidatorIndex(0)].proposal_public
        is_valid = TARGET_SIGNATURE_SCHEME.verify(
            pk=public_key,
            slot=block.slot,
            message=hash_tree_root(block),
            sig=result.signature.proposer_signature,
        )
        assert is_valid

    def test_signs_block_root_with_proposal_key(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Block signing uses the proposal key and the signature covers the block root."""
        service, block = self._setup(sync_service, key_manager, slot=2)

        result = service._sign_block(block, ValidatorIndex(0), [])

        # Signature must verify against the proposal public key (not attestation key).
        proposal_pk = key_manager[ValidatorIndex(0)].proposal_public
        assert TARGET_SIGNATURE_SCHEME.verify(
            pk=proposal_pk,
            slot=Slot(2),
            message=hash_tree_root(block),
            sig=result.signature.proposer_signature,
        )

    def test_attestation_signatures_included(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Aggregated attestation proofs passed in are present in the returned signature."""
        service, block = self._setup(sync_service, key_manager)
        attestation_data = sync_service.store.produce_attestation_data(Slot(1))
        agg_proof = make_aggregated_proof(key_manager, [ValidatorIndex(0)], attestation_data)

        result = service._sign_block(block, ValidatorIndex(0), [agg_proof])

        assert agg_proof in list(result.signature.attestation_signatures)

    def test_missing_validator_raises_value_error(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Signing a block with an unregistered validator index raises ValueError."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )
        block = Block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(42),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )

        with pytest.raises(ValueError, match="No secret key for validator 42"):
            service._sign_block(block, ValidatorIndex(42), [])


class TestSignAttestation:
    """Unit tests for attestation signing with real XMSS keys."""

    def _setup(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
        index: int = 0,
    ) -> tuple[ValidatorService, AttestationData]:
        registry = _make_registry(key_manager, index)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))
        return service, att_data

    def test_fields_populated_correctly(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """The signed attestation contains the correct validator ID, data, and a valid signature."""
        service, att_data = self._setup(sync_service, key_manager, index=3)

        result = service._sign_attestation(att_data, ValidatorIndex(3))

        assert result.validator_id == ValidatorIndex(3)
        assert result.data is att_data

        public_key = key_manager[ValidatorIndex(3)].attestation_public
        assert TARGET_SIGNATURE_SCHEME.verify(
            pk=public_key,
            slot=att_data.slot,
            message=hash_tree_root(att_data),
            sig=result.signature,
        )

    def test_uses_attestation_key_not_proposal_key(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Attestation signature verifies with the attestation public key, not the proposal key."""
        service, att_data = self._setup(sync_service, key_manager)

        result = service._sign_attestation(att_data, ValidatorIndex(0))

        attestation_pk = key_manager[ValidatorIndex(0)].attestation_public
        assert TARGET_SIGNATURE_SCHEME.verify(
            pk=attestation_pk,
            slot=att_data.slot,
            message=hash_tree_root(att_data),
            sig=result.signature,
        )

    def test_missing_validator_raises_value_error(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Signing an attestation with an unregistered validator index raises ValueError."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))

        with pytest.raises(ValueError, match="No secret key for validator 99"):
            service._sign_attestation(att_data, ValidatorIndex(99))


class TestSignWithKey:
    """
    Unit tests for the XMSS key advancement and signing logic.

    The scheme is patched to test the advancement loop mechanics in isolation.
    Real XMSS keys are used so object identity checks work correctly.
    """

    def _setup(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
        index: int = 0,
    ) -> tuple[ValidatorService, ValidatorRegistry, ValidatorEntry, object, object]:
        entry = _make_entry(key_manager, index)
        att_key = entry.attestation_secret_key
        prop_key = entry.proposal_secret_key
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        return service, registry, entry, att_key, prop_key

    def test_no_advancement_when_slot_already_prepared(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """No key advancement when the slot is already within the prepared interval."""
        service, _, entry, att_key, _ = self._setup(sync_service, key_manager)
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.return_value = [3]
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(3), MagicMock(), "attestation_secret_key")

        scheme.advance_preparation.assert_not_called()
        scheme.sign.assert_called_once_with(att_key, Slot(3), scheme.sign.call_args[0][2])

    def test_key_advanced_once_until_slot_in_interval(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Key advances exactly once when one step covers the target slot."""
        service, _, entry, att_key, _ = self._setup(sync_service, key_manager)
        advanced = MagicMock(name="advanced_key")
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [5]
            scheme.advance_preparation.return_value = advanced
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(5), MagicMock(), "attestation_secret_key")

        scheme.advance_preparation.assert_called_once_with(att_key)
        scheme.sign.assert_called_once_with(advanced, Slot(5), scheme.sign.call_args[0][2])

    def test_key_advanced_multiple_times_until_prepared(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Key advancement loops until the target slot falls within the interval."""
        service, _, entry, att_key, _ = self._setup(sync_service, key_manager)
        key_v1 = MagicMock(name="key_v1")
        key_v2 = MagicMock(name="key_v2")
        key_v3 = MagicMock(name="key_v3")
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [7] if key is key_v3 else []
            scheme.advance_preparation.side_effect = [key_v1, key_v2, key_v3]
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(7), MagicMock(), "attestation_secret_key")

        assert scheme.advance_preparation.call_count == 3
        scheme.sign.assert_called_once_with(key_v3, Slot(7), scheme.sign.call_args[0][2])

    def test_updated_entry_persisted_in_registry(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """After signing, the registry holds an entry with the advanced key."""
        service, registry, entry, att_key, _ = self._setup(sync_service, key_manager)
        advanced = MagicMock(name="advanced_att")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [4]
            scheme.advance_preparation.return_value = advanced
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(4), MagicMock(), "attestation_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.attestation_secret_key is advanced

    def test_attestation_key_updated_proposal_key_unchanged(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Signing with the attestation key updates only that key; proposal key is untouched."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service, key_manager)
        advanced_att = MagicMock(name="new_att")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [1]
            scheme.advance_preparation.return_value = advanced_att
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(1), MagicMock(), "attestation_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.attestation_secret_key is advanced_att
        assert stored.proposal_secret_key is prop_key

    def test_proposal_key_updated_attestation_key_unchanged(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Signing with the proposal key updates only that key; attestation key is untouched."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service, key_manager)
        advanced_prop = MagicMock(name="new_prop")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is prop_key else [1]
            scheme.advance_preparation.return_value = advanced_prop
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(1), MagicMock(), "proposal_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.proposal_secret_key is advanced_prop
        assert stored.attestation_secret_key is att_key

    def test_returns_updated_entry_and_signature(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """Return value is (updated ValidatorEntry, Signature) — both fields correct."""
        service, _, entry, att_key, _ = self._setup(sync_service, key_manager)
        advanced = MagicMock(name="adv")
        mock_sig = MagicMock(name="ret_sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [2]
            scheme.advance_preparation.return_value = advanced
            scheme.sign.return_value = mock_sig

            ret_entry, ret_sig = service._sign_with_key(
                entry, Slot(2), MagicMock(), "attestation_secret_key"
            )

        assert ret_sig is mock_sig
        assert ret_entry.attestation_secret_key is advanced


class TestValidatorServiceBasic:
    """Basic tests for lifecycle properties."""

    def test_service_starts_stopped(
        self,
        sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """A new service is not running and has zero counters."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
        )

        assert not service.is_running
        assert service.blocks_produced == 0
        assert service.attestations_produced == 0

    def test_stop_sets_running_to_false(
        self,
        sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """Stopping the service sets the running flag to False."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
        )

        service._running = True
        service.stop()
        assert not service.is_running


class TestMaybeProduceBlock:
    """Unit tests for block production edge cases using real Store."""

    async def test_non_proposer_does_not_produce(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        """No block is produced when the validator is not the proposer for the slot."""
        # With 8 validators, proposer for slot 5 is validator 5 (5 % 8 = 5).
        # Register only validator 0, so it should not produce at slot 5.
        registry = _make_registry(key_manager, 0)
        blocks: list[SignedBlock] = []

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
            on_block=lambda b: blocks.append(b),  # type: ignore[arg-type, return-value]
        )

        await service._maybe_produce_block(Slot(5))

        assert blocks == []

    async def test_assertion_error_is_logged_and_skipped(
        self,
        sync_service: SyncService,
        real_registry: ValidatorRegistry,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Store AssertionError during block production is caught; no block emitted."""
        blocks: list[SignedBlock] = []

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=lambda b: blocks.append(b),  # type: ignore[arg-type, return-value]
        )

        with patch.object(
            Store, "produce_block_with_signatures", side_effect=AssertionError("mismatch")
        ):
            # Slot 0: proposer is validator 0 (0 % 8 = 0), which is in the registry.
            await service._maybe_produce_block(Slot(0))

        assert blocks == []


class TestValidatorServiceDuties:
    """Tests for duty execution edge cases."""

    async def test_no_block_when_not_proposer(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        """No block produced when we're not the scheduled proposer."""
        blocks_received: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_received.append(block)

        # With 8 validators, proposer for slot 2 is validator 2.
        # Register only validator 2, so slots 0 and 1 should produce nothing.
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_make_registry(key_manager, 2),
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(0))
        await service._maybe_produce_block(Slot(1))

        assert blocks_received == []

    async def test_empty_registry_skips_attestations(
        self,
        sync_service: SyncService,
    ) -> None:
        """Empty registry produces no attestations."""
        attestations_received: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_received.append(attestation)

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(0))

        assert attestations_received == []
        assert service.attestations_produced == 0


class TestProduceAttestationsAdvanced:
    """Unit tests for the block-wait polling loop and local attestation processing."""

    async def test_block_wait_polls_up_to_eight_times_when_no_block_arrives(
        self, sync_service: SyncService
    ) -> None:
        """
        If no block for the target slot ever arrives, the wait loop runs exactly 8 times
        with 0.05-second sleeps, then gives up and continues to attest anyway.
        """
        target_slot = Slot(99)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        sleep_durations: list[float] = []

        async def mock_sleep(duration: float) -> None:
            sleep_durations.append(duration)

        with patch("asyncio.sleep", new=mock_sleep):
            await service._produce_attestations(target_slot)

        assert len(sleep_durations) == 8
        assert all(d == pytest.approx(0.05) for d in sleep_durations)

    async def test_block_wait_exits_early_when_block_arrives(
        self, sync_service: SyncService
    ) -> None:
        """The polling loop breaks as soon as it detects a block for the target slot."""
        target_slot = Slot(1)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        # The store initially has only the genesis block (slot 0).
        # Inject a block at the target slot during the third sleep.
        sleep_calls = [0]

        async def mock_sleep(duration: float) -> None:
            sleep_calls[0] += 1
            if sleep_calls[0] == 3:
                sb = make_signed_block(
                    slot=target_slot,
                    proposer_index=ValidatorIndex(0),
                    parent_root=Bytes32.zero(),
                    state_root=Bytes32.zero(),
                )
                root = hash_tree_root(sb.block)
                sync_service.store = sync_service.store.model_copy(
                    update={"blocks": {**sync_service.store.blocks, root: sb.block}}
                )

        with patch("asyncio.sleep", new=mock_sleep):
            await service._produce_attestations(target_slot)

        assert sleep_calls[0] == 3

    async def test_attestation_processed_locally(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        """
        Each produced attestation is validated by the store's gossip handler,
        ensuring the full signing and validation pipeline works end-to-end.
        """
        target_slot = Slot(1)
        published: list[SignedAttestation] = []

        async def capture_att(att: SignedAttestation) -> None:
            published.append(att)

        registry = _make_registry(key_manager, 0)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
            on_attestation=capture_att,
        )

        store_before = sync_service.store
        await service._produce_attestations(target_slot)

        # Attestation was published.
        assert len(published) == 1
        assert published[0].validator_id == ValidatorIndex(0)

        # Store was updated by on_gossip_attestation (new instance).
        assert sync_service.store is not store_before

    async def test_gossip_handler_exception_logged_and_attestation_still_published(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """
        If local gossip processing raises, the exception is logged and the attestation
        is still published so the network receives it.
        """
        target_slot = Slot(1)
        published: list[SignedAttestation] = []

        async def capture_att(att: SignedAttestation) -> None:
            published.append(att)

        registry = _make_registry(key_manager, 0)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
            on_attestation=capture_att,
        )

        with (
            caplog.at_level("DEBUG"),
            patch.object(Store, "on_gossip_attestation", side_effect=RuntimeError("store error")),
        ):
            await service._produce_attestations(target_slot)

        assert len(published) == 1
        assert "on_gossip_attestation failed" in caplog.text


class TestValidatorServiceRun:
    """Tests for the main run loop using real SlotClock."""

    async def test_run_loop_can_be_stopped(
        self,
        sync_service: SyncService,
    ) -> None:
        """The main loop exits when the service is stopped."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        call_count = 0

        async def stop_on_second_call(_duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                service.stop()

        with patch("asyncio.sleep", new=stop_on_second_call):
            await service.run()

        assert not service.is_running

    async def test_interval_0_triggers_block_production(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """At interval 0, the main loop triggers block production for the current slot."""
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: _interval_time(0, 0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_make_registry(key_manager, 0),
        )

        block_slots: list[Slot] = []

        async def mock_produce(self_inner, slot: Slot) -> None:
            block_slots.append(slot)
            service.stop()

        with patch.object(ValidatorService, "_maybe_produce_block", mock_produce):
            await service.run()

        assert block_slots == [Slot(0)]

    async def test_interval_1_triggers_attestation(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """At interval >= 1, the main loop triggers attestation production."""
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: _interval_time(0, 1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_make_registry(key_manager, 0),
        )

        attest_slots: list[Slot] = []

        async def mock_attest(self_inner, slot: Slot) -> None:
            attest_slots.append(slot)
            service.stop()

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        assert attest_slots == [Slot(0)]

    async def test_empty_registry_skips_all_duties(self, sync_service: SyncService) -> None:
        """With an empty registry, the loop skips all duties without calling production."""
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: _interval_time(0, 0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=ValidatorRegistry(),
        )

        sleep_calls = [0]

        async def stop_after_two_sleeps(_duration: float) -> None:
            sleep_calls[0] += 1
            if sleep_calls[0] >= 2:
                service.stop()

        block_calls: list[Slot] = []
        attest_calls: list[Slot] = []

        with (
            patch("asyncio.sleep", new=stop_after_two_sleeps),
            patch.object(
                ValidatorService,
                "_maybe_produce_block",
                lambda self, s: block_calls.append(s),
            ),
            patch.object(
                ValidatorService,
                "_produce_attestations",
                lambda self, s: attest_calls.append(s),
            ),
        ):
            await service.run()

        assert block_calls == []
        assert attest_calls == []

    async def test_duplicate_prevention_same_slot_not_attested_twice(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """A slot already in the attested set does not trigger attestation production again."""
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: _interval_time(5, 1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_make_registry(key_manager, 0),
        )
        service._attested_slots = {Slot(5)}  # already attested

        async def stop_on_sleep(_duration: float) -> None:
            service.stop()

        attest_calls: list[Slot] = []

        async def mock_attest(self_inner, slot: Slot) -> None:
            attest_calls.append(slot)

        with (
            patch("asyncio.sleep", new=stop_on_sleep),
            patch.object(ValidatorService, "_produce_attestations", mock_attest),
        ):
            await service.run()

        assert attest_calls == []

    async def test_slot_pruning_removes_old_slots(
        self, sync_service: SyncService, key_manager: XmssKeyManager
    ) -> None:
        """
        After attesting at slot N, old slots are pruned to bound memory.

        At slot 10: prune_threshold = max(0, 10 - 4) = 6.
        Slots 0-5 (all < 6) must be removed; slot 10 must be present.
        """
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: _interval_time(10, 1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_make_registry(key_manager, 0),
        )
        service._attested_slots = {Slot(i) for i in range(6)}  # slots 0-5

        async def mock_attest(self_inner, slot: Slot) -> None:
            service.stop()

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        for old_slot in range(6):
            assert Slot(old_slot) not in service._attested_slots
        assert Slot(10) in service._attested_slots


class TestProposerGossipAttestation:
    """Tests verifying that all validators (including proposers) produce gossip attestations."""

    @pytest.mark.parametrize(
        ("num_validators", "slot"),
        [
            (2, Slot(0)),  # 2 validators, proposer is validator 0
            (3, Slot(2)),  # 3 validators, proposer is validator 2
        ],
    )
    async def test_all_validators_attest_including_proposer(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
        num_validators: int,
        slot: Slot,
    ) -> None:
        """
        All validators produce gossip attestations, including the proposer.

        With dual keys, the proposer signs the block envelope with the proposal
        key and gossips a separate attestation with the attestation key.
        """
        registry = _make_registry(key_manager, *range(num_validators))
        attestation_validator_ids: list[ValidatorIndex] = []

        async def capture_attestation(att: SignedAttestation) -> None:
            attestation_validator_ids.append(att.validator_id)

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(slot)

        expected = {ValidatorIndex(i) for i in range(num_validators)}
        assert set(attestation_validator_ids) == expected
        assert service.attestations_produced == num_validators


class TestValidatorServiceIntegration:
    """
    Integration tests using real cryptographic keys and signature verification.

    These tests verify the full signing flow end-to-end without mocking.
    All signatures are cryptographically valid and verifiable.
    """

    @pytest.fixture
    def key_manager(self) -> XmssKeyManager:
        """Key manager with pre-generated test keys."""
        return XmssKeyManager.shared(max_slot=Slot(10))

    @pytest.fixture
    def real_store(self, key_manager: XmssKeyManager) -> Store:
        """Forkchoice store with validators using real public keys."""
        return make_store(num_validators=6, key_manager=key_manager, validator_id=TEST_VALIDATOR_ID)

    @pytest.fixture
    def real_sync_service(self, real_store: Store) -> SyncService:
        """Sync service initialized with the real store."""
        return SyncService(
            store=real_store,
            peer_manager=PeerManager(),
            block_cache=BlockCache(),
            clock=SlotClock(genesis_time=Uint64(0)),
            network=MockNetworkRequester(),
        )

    @pytest.fixture
    def real_registry(self, key_manager: XmssKeyManager) -> ValidatorRegistry:
        """Registry populated with real secret keys from key manager."""
        registry = ValidatorRegistry()
        for i in range(6):
            validator_index = ValidatorIndex(i)
            kp = key_manager[validator_index]
            registry.add(
                ValidatorEntry(
                    index=validator_index,
                    attestation_secret_key=kp.attestation_secret,
                    proposal_secret_key=kp.proposal_secret,
                )
            )
        return registry

    async def test_produce_real_block_with_valid_signature(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Produce a block and verify the proposer signature is cryptographically valid.

        The signature must pass verification using the proposer's public key.
        """
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        # Slot 1: proposer is validator 1 (1 % 6 == 1)
        await service._maybe_produce_block(Slot(1))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        assert signed_block.block.slot == Slot(1)
        assert signed_block.block.proposer_index == ValidatorIndex(1)

        proposer_index = signed_block.block.proposer_index
        block_root = hash_tree_root(signed_block.block)
        proposer_public_key = key_manager[proposer_index].proposal_public

        is_valid = TARGET_SIGNATURE_SCHEME.verify(
            pk=proposer_public_key,
            slot=signed_block.block.slot,
            message=block_root,
            sig=signed_block.signature.proposer_signature,
        )
        assert is_valid, "Proposer signature failed verification"

    async def test_produce_real_attestation_with_valid_signature(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Produce attestations and verify each signature is cryptographically valid.

        All validators produce attestations with valid XMSS signatures.
        """
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))

        assert len(attestations_produced) == 6

        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager[validator_id].attestation_public
            message_bytes = hash_tree_root(signed_att.data)

            is_valid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=signed_att.data.slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert is_valid, f"Attestation signature for validator {validator_id} failed"

    async def test_attestation_data_references_correct_checkpoints(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify attestation data contains correct head, target, and source checkpoints.

        The attestation must reference:
        - head: the current chain head
        - target: the attestation target based on forkchoice
        - source: the latest justified checkpoint
        """
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))

        store = real_sync_service.store
        expected_head_root = store.head
        expected_source = store.latest_justified

        for signed_att in attestations_produced:
            data = signed_att.data
            assert data.head.root == expected_head_root
            assert data.source == expected_source
            assert data.slot == Slot(1)

    async def test_proposer_signature_in_block(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """Verify the proposer's signature over the block root is cryptographically valid."""
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(2))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        proposer_index = signed_block.block.proposer_index
        block_root = hash_tree_root(signed_block.block)
        public_key = key_manager[proposer_index].proposal_public

        is_valid = TARGET_SIGNATURE_SCHEME.verify(
            pk=public_key,
            slot=signed_block.block.slot,
            message=block_root,
            sig=signed_block.signature.proposer_signature,
        )
        assert is_valid

    async def test_block_includes_pending_attestations(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify attestations from the pool are included in produced blocks.

        When the store has pending attestations, the proposer should aggregate
        and include them in the block body.
        """
        store = real_sync_service.store
        attestation_data = store.produce_attestation_data(Slot(0))
        data_root = hash_tree_root(attestation_data)

        participants = [ValidatorIndex(3), ValidatorIndex(4)]
        public_keys = []
        signatures = []

        for vid in participants:
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signatures.append(sig)
            public_keys.append(key_manager[vid].attestation_public)

        xmss_participants = ValidatorIndices(data=participants).to_aggregation_bits()
        proof = AggregatedSignatureProof.aggregate(
            xmss_participants=xmss_participants,
            children=[],
            raw_xmss=list(zip(public_keys, signatures, strict=True)),
            message=data_root,
            slot=attestation_data.slot,
        )

        updated_store = store.model_copy(
            update={"latest_known_aggregated_payloads": {attestation_data: {proof}}}
        )
        real_sync_service.store = updated_store

        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(1))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        body_attestations = signed_block.block.body.attestations
        assert len(body_attestations) > 0

        attestation_signatures = signed_block.signature.attestation_signatures
        assert len(attestation_signatures) == len(body_attestations)

    async def test_multiple_slots_produce_different_attestations(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """Attestations produced at different slots have distinct slot values."""
        attestations_by_slot: dict[Slot, list[SignedAttestation]] = {
            Slot(1): [],
            Slot(2): [],
        }

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_by_slot[attestation.data.slot].append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))
        await service._produce_attestations(Slot(2))

        assert len(attestations_by_slot[Slot(1)]) > 0
        assert len(attestations_by_slot[Slot(2)]) > 0

        for att in attestations_by_slot[Slot(1)]:
            assert att.data.slot == Slot(1)
        for att in attestations_by_slot[Slot(2)]:
            assert att.data.slot == Slot(2)

    async def test_proposer_also_gossips_attestation(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        The proposer produces a block at interval 0 and a gossip attestation at interval 1.

        Both intervals use independent keys, so there is no OTS conflict.
        """
        blocks_produced: list[SignedBlock] = []
        attestations_produced: list[SignedAttestation] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
            on_attestation=capture_attestation,
        )

        slot = Slot(3)
        proposer_index = ValidatorIndex(3)  # 3 % 6 == 3

        await service._maybe_produce_block(slot)
        await service._produce_attestations(slot)

        assert len(blocks_produced) == 1
        assert blocks_produced[0].block.proposer_index == proposer_index

        attestation_validator_ids = {att.validator_id for att in attestations_produced}
        expected_attesters = {ValidatorIndex(i) for i in range(6)}
        assert attestation_validator_ids == expected_attesters

    async def test_block_state_root_is_valid(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        The produced block has a valid state root matching the post-state hash.
        """
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(4))

        assert len(blocks_produced) == 1
        produced_block = blocks_produced[0].block

        assert produced_block.state_root != Bytes32.zero()

        store = real_sync_service.store
        block_hash = hash_tree_root(produced_block)
        assert block_hash in store.blocks
        assert block_hash in store.states

        stored_state = store.states[block_hash]
        computed_state_root = hash_tree_root(stored_state)
        assert produced_block.state_root == computed_state_root

    async def test_signature_uses_correct_slot(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """Signatures verify with the signing slot but fail with any other slot."""
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        test_slot = Slot(5)

        await service._produce_attestations(test_slot)

        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager[validator_id].attestation_public
            message_bytes = hash_tree_root(signed_att.data)

            is_valid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=test_slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert is_valid, f"Slot {test_slot} signature failed for validator {validator_id}"

            wrong_slot = test_slot + Slot(1)
            is_invalid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=wrong_slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert not is_invalid, "Signature should not verify with the wrong slot"
