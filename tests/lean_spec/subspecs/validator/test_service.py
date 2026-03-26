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
from lean_spec.subspecs.containers.attestation import AggregationBits
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
from tests.lean_spec.helpers import TEST_VALIDATOR_ID, MockNetworkRequester, make_store


@pytest.fixture
def sync_service(base_store: Store) -> SyncService:
    """Sync service with store."""
    return SyncService(
        store=base_store,
        peer_manager=PeerManager(),
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0)),
        network=MockNetworkRequester(),
    )


@pytest.fixture
def mock_registry() -> ValidatorRegistry:
    """Registry with mock keys for validators 0 and 1."""
    registry = ValidatorRegistry()
    for i in [0, 1]:
        mock_key = MagicMock()
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(i),
                attestation_secret_key=mock_key,
                proposal_secret_key=mock_key,
            )
        )
    return registry


class TestValidatorServiceBasic:
    """Basic tests for ValidatorService."""

    def test_service_starts_stopped(
        self,
        sync_service: SyncService,
        mock_registry: ValidatorRegistry,
    ) -> None:
        """Service is not running before start."""
        clock = SlotClock(genesis_time=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=mock_registry,
        )

        assert not service.is_running
        assert service.blocks_produced == 0
        assert service.attestations_produced == 0

    def test_stop_service(
        self,
        sync_service: SyncService,
        mock_registry: ValidatorRegistry,
    ) -> None:
        """stop() sets running flag to False."""
        clock = SlotClock(genesis_time=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=mock_registry,
        )

        service._running = True
        service.stop()
        assert not service.is_running


class TestValidatorServiceDuties:
    """Tests for duty execution."""

    async def test_no_block_when_not_proposer(
        self,
        sync_service: SyncService,
    ) -> None:
        """No block produced when we're not the proposer."""
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with validator 2 only
        registry = ValidatorRegistry()
        mock_key = MagicMock()
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(2),
                attestation_secret_key=mock_key,
                proposal_secret_key=mock_key,
            )
        )

        blocks_received: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_received.append(block)

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
            on_block=capture_block,
        )

        # Slot 0 proposer is validator 0, slot 1 is validator 1
        # Validator 2 is proposer for slot 2
        await service._maybe_produce_block(Slot(0))
        await service._maybe_produce_block(Slot(1))

        assert len(blocks_received) == 0

    async def test_empty_registry_skips_duties(
        self,
        sync_service: SyncService,
    ) -> None:
        """Empty registry skips all duty execution."""
        clock = SlotClock(genesis_time=Uint64(0))
        registry = ValidatorRegistry()

        attestations_received: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_received.append(attestation)

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(0))

        assert len(attestations_received) == 0
        assert service.attestations_produced == 0


class TestValidatorServiceRun:
    """Tests for the main run loop."""

    async def test_run_loop_can_be_stopped(
        self,
        sync_service: SyncService,
    ) -> None:
        """run() loop exits when stop() is called."""
        clock = SlotClock(genesis_time=Uint64(0))

        # Use empty registry to avoid attestation production
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
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


class TestIntervalSleep:
    """Tests for interval sleep calculation."""

    async def test_sleep_until_next_interval_mid_interval(
        self,
        sync_service: SyncService,
    ) -> None:
        """Sleep duration is calculated correctly mid-interval."""
        genesis = Uint64(1000)
        interval_seconds = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        # Half way into first interval
        current_time = float(genesis) + interval_seconds / 2

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        captured_duration: float | None = None

        async def capture_sleep(duration: float) -> None:
            nonlocal captured_duration
            captured_duration = duration

        with patch("asyncio.sleep", new=capture_sleep):
            await service.clock.sleep_until_next_interval()

        # Should sleep until next interval boundary
        expected = interval_seconds / 2
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.01

    async def test_sleep_before_genesis(
        self,
        sync_service: SyncService,
    ) -> None:
        """Sleeps until genesis when current time is before genesis."""
        genesis = Uint64(1000)
        current_time = 900.0  # 100 seconds before genesis

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        captured_duration: float | None = None

        async def capture_sleep(duration: float) -> None:
            nonlocal captured_duration
            captured_duration = duration

        with patch("asyncio.sleep", new=capture_sleep):
            await service.clock.sleep_until_next_interval()

        # Should sleep until genesis
        expected = float(genesis) - current_time  # 100 seconds
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001


class TestProposerGossipAttestation:
    """Tests for proposer gossip attestation at interval 1."""

    async def test_proposer_also_attests_at_interval_1(
        self,
        sync_service: SyncService,
    ) -> None:
        """Proposer produces a gossip attestation alongside all other validators.

        With dual keys, the proposer signs the block envelope with the proposal
        key and gossips a separate attestation with the attestation key.
        Both validators 0 and 1 should produce attestations.
        """
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with validators 0 and 1.
        registry = ValidatorRegistry()
        for i in [0, 1]:
            mock_key = MagicMock()
            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(i),
                    attestation_secret_key=mock_key,
                    proposal_secret_key=mock_key,
                )
            )

        # Track which validators had _sign_attestation called.
        signed_validator_ids: list[ValidatorIndex] = []

        def mock_sign_attestation(
            self: ValidatorService,  # noqa: ARG001
            attestation_data: object,  # noqa: ARG001
            validator_index: ValidatorIndex,
        ) -> SignedAttestation:
            signed_validator_ids.append(validator_index)
            return MagicMock(spec=SignedAttestation, validator_id=validator_index)

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        # Slot 0: validator 0 is proposer (0 % 3 == 0).
        # Both validators should produce gossip attestations.
        with patch.object(
            ValidatorService,
            "_sign_attestation",
            mock_sign_attestation,
        ):
            await service._produce_attestations(Slot(0))

        assert sorted(signed_validator_ids) == [ValidatorIndex(0), ValidatorIndex(1)]
        assert service.attestations_produced == 2

    async def test_all_validators_attest_including_proposer(
        self,
        sync_service: SyncService,
    ) -> None:
        """All validators produce gossip attestations, including the proposer.

        At slot 2, validator 2 is the proposer (2 % 3 == 2).
        All three validators (0, 1, 2) should produce gossip attestations
        since the proposer uses a separate attestation key.
        """
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with validators 0, 1, and 2.
        registry = ValidatorRegistry()
        for i in [0, 1, 2]:
            mock_key = MagicMock()
            registry.add(
                ValidatorEntry(
                    index=ValidatorIndex(i),
                    attestation_secret_key=mock_key,
                    proposal_secret_key=mock_key,
                )
            )

        # Track which validators had _sign_attestation called.
        signed_validator_ids: list[ValidatorIndex] = []

        def mock_sign_attestation(
            self: ValidatorService,  # noqa: ARG001
            attestation_data: object,  # noqa: ARG001
            validator_index: ValidatorIndex,
        ) -> SignedAttestation:
            signed_validator_ids.append(validator_index)
            return MagicMock(spec=SignedAttestation, validator_id=validator_index)

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        # Slot 2: validator 2 is proposer (2 % 3 == 2).
        # All validators should attest.
        with patch.object(
            ValidatorService,
            "_sign_attestation",
            mock_sign_attestation,
        ):
            await service._produce_attestations(Slot(2))

        assert len(signed_validator_ids) == 3
        assert set(signed_validator_ids) == {
            ValidatorIndex(0),
            ValidatorIndex(1),
            ValidatorIndex(2),
        }
        assert service.attestations_produced == 3


class TestSigningMissingValidator:
    """Tests for signing methods when validator is not in registry."""

    def test_sign_block_missing_validator(
        self,
        sync_service: SyncService,
    ) -> None:
        """_sign_block raises ValueError when validator is not in registry."""
        clock = SlotClock(genesis_time=Uint64(0))

        # Empty registry - no validators
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        # Create a minimal block
        block = Block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(99),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )

        with pytest.raises(ValueError, match="No secret key for validator 99"):
            service._sign_block(block, ValidatorIndex(99), [])

    def test_sign_attestation_missing_validator(
        self,
        sync_service: SyncService,
    ) -> None:
        """_sign_attestation raises ValueError when validator is not in registry."""
        clock = SlotClock(genesis_time=Uint64(0))

        # Empty registry - no validators
        registry = ValidatorRegistry()

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
        )

        # Produce attestation data
        attestation_data = sync_service.store.produce_attestation_data(Slot(1))

        with pytest.raises(ValueError, match="No secret key for validator 99"):
            service._sign_attestation(attestation_data, ValidatorIndex(99))


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
        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
        )

        # Slot 1: proposer is validator 1 (1 % 6 == 1)
        await service._maybe_produce_block(Slot(1))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        # Verify block structure
        assert signed_block.block.slot == Slot(1)
        assert signed_block.block.proposer_index == ValidatorIndex(1)

        # Verify proposer signature is cryptographically valid
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
        Produce an attestation and verify its signature is cryptographically valid.

        Non-proposer validators produce attestations with valid XMSS signatures.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        # Slot 1: all 6 validators should attest (including proposer 1)
        await service._produce_attestations(Slot(1))

        assert len(attestations_produced) == 6

        # Verify each attestation signature
        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager[validator_id].attestation_public
            message_bytes = signed_att.data.data_root_bytes()

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
        clock = SlotClock(genesis_time=Uint64(0))
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))

        store = real_sync_service.store
        expected_head_root = store.head
        expected_source = store.latest_justified

        for signed_att in attestations_produced:
            data = signed_att.data

            # Verify head checkpoint references the store's head
            assert data.head.root == expected_head_root

            # Verify source checkpoint matches store's latest justified
            assert data.source == expected_source

            # Verify slot is correct
            assert data.slot == Slot(1)

    async def test_proposer_signature_in_block(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify the proposer's signature over the block root is valid.

        The proposer signs the block root with the proposal key at interval 0.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
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
        # Add attestations to the store's attestation pool
        store = real_sync_service.store
        attestation_data = store.produce_attestation_data(Slot(0))
        data_root = attestation_data.data_root_bytes()

        attestation_map: dict[ValidatorIndex, AttestationData] = {}
        signatures = []
        participants = [ValidatorIndex(3), ValidatorIndex(4)]
        public_keys = []

        for vid in participants:
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signatures.append(sig)
            public_keys.append(key_manager[vid].attestation_public)
            attestation_map[vid] = attestation_data

        xmss_participants = AggregationBits.from_validator_indices(
            ValidatorIndices(data=participants)
        )
        raw_xmss = list(zip(public_keys, signatures, strict=True))
        proof = AggregatedSignatureProof.aggregate(
            xmss_participants=xmss_participants,
            children=[],
            raw_xmss=raw_xmss,
            message=data_root,
            slot=attestation_data.slot,
        )

        aggregated_payloads = {attestation_data: {proof}}

        # Update store with aggregated payloads
        updated_store = store.model_copy(
            update={
                "latest_known_aggregated_payloads": aggregated_payloads,
            }
        )
        real_sync_service.store = updated_store

        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
        )

        # Slot 1: proposer is validator 1
        await service._maybe_produce_block(Slot(1))

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        # Block should contain the pending attestations
        body_attestations = signed_block.block.body.attestations
        assert len(body_attestations) > 0

        # Verify the attestation signatures are included and valid
        attestation_signatures = signed_block.signature.attestation_signatures
        assert len(attestation_signatures) == len(body_attestations)

    async def test_multiple_slots_produce_different_attestations(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify attestations produced at different slots have distinct slot values.

        Each attestation's data should reflect the slot at which it was produced.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        attestations_by_slot: dict[Slot, list[SignedAttestation]] = {
            Slot(1): [],
            Slot(2): [],
        }

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_by_slot[attestation.data.slot].append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        await service._produce_attestations(Slot(1))
        await service._produce_attestations(Slot(2))

        # Both slots should have attestations
        assert len(attestations_by_slot[Slot(1)]) > 0
        assert len(attestations_by_slot[Slot(2)]) > 0

        # Attestations at each slot should have the correct slot value
        for att in attestations_by_slot[Slot(1)]:
            assert att.data.slot == Slot(1)
        for att in attestations_by_slot[Slot(2)]:
            assert att.data.slot == Slot(2)

    async def test_proposer_also_gossips_attestation(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify proposer also produces a gossip attestation at interval 1.

        The proposer signs the block envelope with the proposal key at interval 0.
        At interval 1, the proposer also gossips with the attestation key.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlock] = []
        attestations_produced: list[SignedAttestation] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
            on_attestation=capture_attestation,
        )

        slot = Slot(3)
        proposer_index = ValidatorIndex(3)  # 3 % 6 == 3

        # Interval 0: block production
        await service._maybe_produce_block(slot)
        # Interval 1: attestation production
        await service._produce_attestations(slot)

        # One block should be produced
        assert len(blocks_produced) == 1
        assert blocks_produced[0].block.proposer_index == proposer_index

        # ALL validators should have attested (including proposer)
        attestation_validator_ids = {att.validator_id for att in attestations_produced}
        expected_attesters = {ValidatorIndex(i) for i in range(6)}
        assert attestation_validator_ids == expected_attesters

    async def test_block_state_root_is_valid(
        self,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify the produced block has a valid state root.

        The state root in the block should match the hash of the post-state
        after applying the block to the parent state.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlock] = []

        async def capture_block(block: SignedBlock) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
        )

        await service._maybe_produce_block(Slot(4))

        assert len(blocks_produced) == 1
        produced_block = blocks_produced[0].block

        # The state root should not be zero (it was computed)
        assert produced_block.state_root != Bytes32.zero()

        # The block should have been stored in sync service
        store = real_sync_service.store
        block_hash = hash_tree_root(produced_block)
        assert block_hash in store.blocks
        assert block_hash in store.states

        # Verify state root matches stored state
        stored_state = store.states[block_hash]
        computed_state_root = hash_tree_root(stored_state)
        assert produced_block.state_root == computed_state_root

    async def test_signature_uses_correct_slot(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify signatures use the correct slot as the XMSS slot parameter.

        XMSS is stateful and uses slots for one-time signature keys.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        attestations_produced: list[SignedAttestation] = []

        async def capture_attestation(attestation: SignedAttestation) -> None:
            attestations_produced.append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        test_slot = Slot(5)

        await service._produce_attestations(test_slot)

        # Verify each signature was created with the correct slot
        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager[validator_id].attestation_public
            message_bytes = signed_att.data.data_root_bytes()

            # Verification must use the same slot that was used for signing
            is_valid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=test_slot,  # Must match the signing slot
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert is_valid, f"Signature for validator {validator_id} at slot {test_slot} failed"

            # Verify with wrong slot should fail
            wrong_slot = test_slot + Slot(1)
            is_invalid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=wrong_slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert not is_invalid, "Signature should fail with wrong slot"
