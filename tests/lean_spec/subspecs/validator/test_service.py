"""Tests for Validator Service."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from consensus_testing.keys import XmssKeyManager, get_shared_key_manager

from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.containers import (
    AttestationData,
    Block,
    BlockBody,
    SignedAttestation,
    SignedBlockWithAttestation,
    State,
    Validator,
    ValidatorIndex,
)
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.backfill_sync import NetworkRequester
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.subspecs.sync.service import SyncService
from lean_spec.subspecs.validator import ValidatorRegistry, ValidatorService
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME
from lean_spec.subspecs.xmss.aggregation import SignatureKey
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.types import Bytes32, Bytes52, Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID


class MockNetworkRequester(NetworkRequester):
    """Mock network requester for testing."""

    async def request_block_by_root(
        self,
        peer_id: str,  # noqa: ARG002
        root: bytes,  # noqa: ARG002
    ) -> SignedBlockWithAttestation | None:
        """Return None - no blocks available."""
        return None


@pytest.fixture
def store(genesis_state: State, genesis_block: Block) -> Store:
    """Forkchoice store initialized with genesis."""
    return Store.get_forkchoice_store(
        genesis_state,
        genesis_block,
        validator_id=TEST_VALIDATOR_ID,
    )


@pytest.fixture
def sync_service(store: Store) -> SyncService:
    """Sync service with store."""
    return SyncService(
        store=store,
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
        registry.add(ValidatorEntry(index=ValidatorIndex(i), secret_key=mock_key))
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

    def test_no_block_when_not_proposer(
        self,
        sync_service: SyncService,
    ) -> None:
        """No block produced when we're not the proposer."""
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with validator 2 only
        registry = ValidatorRegistry()
        mock_key = MagicMock()
        registry.add(ValidatorEntry(index=ValidatorIndex(2), secret_key=mock_key))

        blocks_received: list[SignedBlockWithAttestation] = []

        async def capture_block(block: SignedBlockWithAttestation) -> None:
            blocks_received.append(block)

        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=registry,
            on_block=capture_block,
        )

        async def check_no_blocks() -> None:
            # Slot 0 proposer is validator 0, slot 1 is validator 1
            # Validator 2 is proposer for slot 2
            await service._maybe_produce_block(Slot(0))
            await service._maybe_produce_block(Slot(1))

        asyncio.run(check_no_blocks())

        assert len(blocks_received) == 0

    def test_empty_registry_skips_duties(
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

        async def produce() -> None:
            await service._produce_attestations(Slot(0))

        asyncio.run(produce())

        assert len(attestations_received) == 0
        assert service.attestations_produced == 0


class TestValidatorServiceRun:
    """Tests for the main run loop."""

    def test_run_loop_can_be_stopped(
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

        async def run_briefly() -> None:
            with patch("asyncio.sleep", new=stop_on_second_call):
                await service.run()

        asyncio.run(run_briefly())
        assert not service.is_running


class TestIntervalSleep:
    """Tests for interval sleep calculation."""

    def test_sleep_until_next_interval_mid_interval(
        self,
        sync_service: SyncService,
    ) -> None:
        """Sleep duration is calculated correctly mid-interval."""
        genesis = Uint64(1000)
        current_time = 1000.5  # 0.5 seconds into first interval

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

        async def check_sleep() -> None:
            with patch("asyncio.sleep", new=capture_sleep):
                await service._sleep_until_next_interval()

        asyncio.run(check_sleep())

        # Should sleep until next interval boundary (1001.0)
        expected = 1001.0 - current_time  # 0.5 seconds
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001

    def test_sleep_before_genesis(
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

        async def check_sleep() -> None:
            with patch("asyncio.sleep", new=capture_sleep):
                await service._sleep_until_next_interval()

        asyncio.run(check_sleep())

        # Should sleep until genesis
        expected = float(genesis) - current_time  # 100 seconds
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001


class TestProposerSkipping:
    """Tests for proposer skipping during attestation production."""

    def test_proposer_skipped_in_attestation_production(
        self,
        sync_service: SyncService,
    ) -> None:
        """Proposer is skipped when producing attestations at interval 1.

        At slot 0, validator 0 is the proposer (0 % 3 == 0).
        When controlling validators 0 and 1, only validator 1 should produce an attestation
        since validator 0 already attested within their block.
        """
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with validators 0 and 1.
        registry = ValidatorRegistry()
        for i in [0, 1]:
            mock_key = MagicMock()
            registry.add(ValidatorEntry(index=ValidatorIndex(i), secret_key=mock_key))

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

        async def produce() -> None:
            # Slot 0: validator 0 is proposer (0 % 3 == 0).
            with patch.object(
                ValidatorService,
                "_sign_attestation",
                mock_sign_attestation,
            ):
                await service._produce_attestations(Slot(0))

        asyncio.run(produce())

        # Only validator 1 should have signed an attestation.
        assert len(signed_validator_ids) == 1
        assert signed_validator_ids[0] == ValidatorIndex(1)
        assert service.attestations_produced == 1

    def test_non_proposer_still_attests(
        self,
        sync_service: SyncService,
    ) -> None:
        """Non-proposer validators still produce attestations.

        At slot 1, validator 1 is the proposer (1 % 3 == 1).
        Validator 0 is not the proposer so should produce an attestation.
        """
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with only validator 0.
        registry = ValidatorRegistry()
        mock_key = MagicMock()
        registry.add(ValidatorEntry(index=ValidatorIndex(0), secret_key=mock_key))

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

        async def produce() -> None:
            # Slot 1: validator 1 is proposer (1 % 3 == 1).
            # Validator 0 is not proposer, should attest.
            with patch.object(
                ValidatorService,
                "_sign_attestation",
                mock_sign_attestation,
            ):
                await service._produce_attestations(Slot(1))

        asyncio.run(produce())

        # Validator 0 should have signed an attestation.
        assert len(signed_validator_ids) == 1
        assert signed_validator_ids[0] == ValidatorIndex(0)
        assert service.attestations_produced == 1

    def test_multiple_validators_only_non_proposers_attest(
        self,
        sync_service: SyncService,
    ) -> None:
        """With multiple validators, only non-proposers produce attestations.

        At slot 2, validator 2 is the proposer (2 % 3 == 2).
        Controlling validators 0, 1, and 2, only validators 0 and 1 should attest.
        """
        clock = SlotClock(genesis_time=Uint64(0))

        # Registry with validators 0, 1, and 2.
        registry = ValidatorRegistry()
        for i in [0, 1, 2]:
            mock_key = MagicMock()
            registry.add(ValidatorEntry(index=ValidatorIndex(i), secret_key=mock_key))

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

        async def produce() -> None:
            # Slot 2: validator 2 is proposer (2 % 3 == 2).
            with patch.object(
                ValidatorService,
                "_sign_attestation",
                mock_sign_attestation,
            ):
                await service._produce_attestations(Slot(2))

        asyncio.run(produce())

        # Validators 0 and 1 should have signed attestations.
        assert len(signed_validator_ids) == 2
        assert set(signed_validator_ids) == {ValidatorIndex(0), ValidatorIndex(1)}
        assert service.attestations_produced == 2

        # Verify validator 2 (proposer) did not sign.
        assert ValidatorIndex(2) not in signed_validator_ids


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
        return get_shared_key_manager(max_slot=Slot(10))

    @pytest.fixture
    def real_store(self, key_manager: XmssKeyManager) -> Store:
        """Forkchoice store with validators using real public keys."""
        validators = Validators(
            data=[
                Validator(
                    pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                    index=ValidatorIndex(i),
                )
                for i in range(6)
            ]
        )
        genesis_state = State.generate_genesis(genesis_time=Uint64(0), validators=validators)
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )
        return Store.get_forkchoice_store(
            genesis_state,
            genesis_block,
            validator_id=TEST_VALIDATOR_ID,
        )

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
            secret_key = key_manager[validator_index].secret
            registry.add(ValidatorEntry(index=validator_index, secret_key=secret_key))
        return registry

    def test_produce_real_block_with_valid_signature(
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
        blocks_produced: list[SignedBlockWithAttestation] = []

        async def capture_block(block: SignedBlockWithAttestation) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
        )

        async def produce_block() -> None:
            # Slot 1: proposer is validator 1 (1 % 6 == 1)
            await service._maybe_produce_block(Slot(1))

        asyncio.run(produce_block())

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        # Verify block structure
        assert signed_block.message.block.slot == Slot(1)
        assert signed_block.message.block.proposer_index == ValidatorIndex(1)

        # Verify proposer signature is cryptographically valid
        proposer_index = signed_block.message.block.proposer_index
        proposer_public_key = key_manager.get_public_key(proposer_index)
        proposer_attestation_data = signed_block.message.proposer_attestation.data
        message_bytes = proposer_attestation_data.data_root_bytes()

        is_valid = TARGET_SIGNATURE_SCHEME.verify(
            pk=proposer_public_key,
            epoch=signed_block.message.block.slot,
            message=message_bytes,
            sig=signed_block.signature.proposer_signature,
        )
        assert is_valid, "Proposer signature failed verification"

    def test_produce_real_attestation_with_valid_signature(
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

        async def produce_attestations() -> None:
            # Slot 1: proposer is validator 1, so validators 0, 2, 3, 4, 5 should attest
            await service._produce_attestations(Slot(1))

        asyncio.run(produce_attestations())

        # 5 validators should have attested (all except proposer 1)
        assert len(attestations_produced) == 5

        # Verify each attestation signature
        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager.get_public_key(validator_id)
            message_bytes = signed_att.message.data_root_bytes()

            is_valid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                epoch=signed_att.message.slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert is_valid, f"Attestation signature for validator {validator_id} failed"

    def test_attestation_data_references_correct_checkpoints(
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

        async def produce_attestations() -> None:
            await service._produce_attestations(Slot(1))

        asyncio.run(produce_attestations())

        store = real_sync_service.store
        expected_head_root = store.head
        expected_source = store.latest_justified

        for signed_att in attestations_produced:
            data = signed_att.message

            # Verify head checkpoint references the store's head
            assert data.head.root == expected_head_root

            # Verify source checkpoint matches store's latest justified
            assert data.source == expected_source

            # Verify slot is correct
            assert data.slot == Slot(1)

    def test_proposer_attestation_bundled_in_block(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify the proposer's attestation is correctly embedded in the block.

        The proposer attests at interval 0, and their attestation is bundled
        inside the signed block with attestation wrapper.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlockWithAttestation] = []

        async def capture_block(block: SignedBlockWithAttestation) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
        )

        async def produce_block() -> None:
            await service._maybe_produce_block(Slot(2))

        asyncio.run(produce_block())

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        # Proposer attestation should be included
        proposer_attestation = signed_block.message.proposer_attestation

        # Verify proposer attestation matches block proposer
        proposer_index = signed_block.message.block.proposer_index
        assert proposer_attestation.validator_id == proposer_index

        # Verify proposer attestation slot matches block slot
        assert proposer_attestation.data.slot == signed_block.message.block.slot

        # Verify proposer attestation signature is valid
        public_key = key_manager.get_public_key(proposer_index)
        message_bytes = proposer_attestation.data.data_root_bytes()

        is_valid = TARGET_SIGNATURE_SCHEME.verify(
            pk=public_key,
            epoch=signed_block.message.block.slot,
            message=message_bytes,
            sig=signed_block.signature.proposer_signature,
        )
        assert is_valid

    def test_block_includes_pending_attestations(
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

        # Simulate gossip attestations from validators 3 and 4
        attestation_map: dict[ValidatorIndex, AttestationData] = {}
        gossip_sigs: dict[SignatureKey, Signature] = {}

        for validator_id in (ValidatorIndex(3), ValidatorIndex(4)):
            attestation_map[validator_id] = attestation_data
            gossip_sigs[SignatureKey(validator_id, data_root)] = key_manager.sign_attestation_data(
                validator_id, attestation_data
            )

        # Update store with pending attestations
        updated_store = store.model_copy(
            update={
                "latest_known_attestations": attestation_map,
                "gossip_signatures": gossip_sigs,
            }
        )
        real_sync_service.store = updated_store

        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlockWithAttestation] = []

        async def capture_block(block: SignedBlockWithAttestation) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
        )

        async def produce_block() -> None:
            # Slot 1: proposer is validator 1
            await service._maybe_produce_block(Slot(1))

        asyncio.run(produce_block())

        assert len(blocks_produced) == 1
        signed_block = blocks_produced[0]

        # Block should contain the pending attestations
        body_attestations = signed_block.message.block.body.attestations
        assert len(body_attestations) > 0

        # Verify the attestation signatures are included and valid
        attestation_signatures = signed_block.signature.attestation_signatures
        assert len(attestation_signatures) == len(body_attestations)

    def test_multiple_slots_produce_different_attestations(
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
            attestations_by_slot[attestation.message.slot].append(attestation)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_attestation=capture_attestation,
        )

        async def produce_attestations() -> None:
            await service._produce_attestations(Slot(1))
            await service._produce_attestations(Slot(2))

        asyncio.run(produce_attestations())

        # Both slots should have attestations
        assert len(attestations_by_slot[Slot(1)]) > 0
        assert len(attestations_by_slot[Slot(2)]) > 0

        # Attestations at each slot should have the correct slot value
        for att in attestations_by_slot[Slot(1)]:
            assert att.message.slot == Slot(1)
        for att in attestations_by_slot[Slot(2)]:
            assert att.message.slot == Slot(2)

    def test_proposer_does_not_double_attest(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify proposer does not produce a separate attestation after producing a block.

        The proposer's attestation is bundled in the block at interval 0.
        At interval 1, the proposer should be skipped to prevent double-attestation.
        """
        clock = SlotClock(genesis_time=Uint64(0))
        blocks_produced: list[SignedBlockWithAttestation] = []
        attestations_produced: list[SignedAttestation] = []

        async def capture_block(block: SignedBlockWithAttestation) -> None:
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

        async def simulate_full_slot() -> None:
            # Interval 0: block production
            await service._maybe_produce_block(slot)
            # Interval 1: attestation production
            await service._produce_attestations(slot)

        asyncio.run(simulate_full_slot())

        # One block should be produced
        assert len(blocks_produced) == 1
        assert blocks_produced[0].message.block.proposer_index == proposer_index

        # Proposer should NOT appear in attestations_produced
        attestation_validator_ids = {att.validator_id for att in attestations_produced}
        assert proposer_index not in attestation_validator_ids

        # All other validators should have attested
        expected_attesters = {ValidatorIndex(i) for i in range(6) if i != int(proposer_index)}
        assert attestation_validator_ids == expected_attesters

    def test_block_state_root_is_valid(
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
        blocks_produced: list[SignedBlockWithAttestation] = []

        async def capture_block(block: SignedBlockWithAttestation) -> None:
            blocks_produced.append(block)

        service = ValidatorService(
            sync_service=real_sync_service,
            clock=clock,
            registry=real_registry,
            on_block=capture_block,
        )

        async def produce_block() -> None:
            await service._maybe_produce_block(Slot(4))

        asyncio.run(produce_block())

        assert len(blocks_produced) == 1
        produced_block = blocks_produced[0].message.block

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

    def test_signature_uses_correct_slot_as_epoch(
        self,
        key_manager: XmssKeyManager,
        real_sync_service: SyncService,
        real_registry: ValidatorRegistry,
    ) -> None:
        """
        Verify signatures use the correct slot as the XMSS epoch parameter.

        XMSS is stateful and uses epochs for one-time signature keys.
        The slot number serves as the epoch in the lean protocol.
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

        async def produce_attestations() -> None:
            await service._produce_attestations(test_slot)

        asyncio.run(produce_attestations())

        # Verify each signature was created with the correct epoch (slot)
        for signed_att in attestations_produced:
            validator_id = signed_att.validator_id
            public_key = key_manager.get_public_key(validator_id)
            message_bytes = signed_att.message.data_root_bytes()

            # Verification must use the same epoch that was used for signing
            is_valid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                epoch=test_slot,  # Must match the signing slot
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert is_valid, f"Signature for validator {validator_id} at slot {test_slot} failed"

            # Verify with wrong epoch should fail
            wrong_epoch = test_slot + Slot(1)
            is_invalid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                epoch=wrong_epoch,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert not is_invalid, "Signature should fail with wrong epoch"
