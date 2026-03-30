"""Tests for Validator Service.


Testing strategy
----------------
ValidatorService drives block proposal and attestation at each slot interval:

  Interval 0  - _maybe_produce_block (if scheduled)
  Interval ≥1 - _produce_attestations (all validators, including proposer)

Unit tests isolate each method by mocking external dependencies.
Integration tests use real XMSS keys to verify cryptographic correctness.

Key areas and why they matter
------------------------------
_sign_with_key
  XMSS is stateful: each OTS key can be used exactly once per slot window.
  Bugs here either exhaust keys early (too many advancements) or produce
  invalid signatures (key not advanced). The updated key must also be
  persisted back to the registry so the next signing call sees fresh state.

_maybe_produce_block
  Must gate on the proposer schedule, tolerate AssertionError from the
  store, and return early when no head state is available.

_produce_attestations
  Polls for the current slot's block before attesting (avoid stale head),
  processes attestations locally (gossipsub doesn't self-deliver), and must
  never double-attest for the same slot.

run()
  Routes to block vs. attestation duties based on the interval number,
  prunes _attested_slots to bound memory, and sleeps when the current
  interval is already handled.
"""

from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

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
from lean_spec.subspecs.xmss.constants import TARGET_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import (
    Fp,
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Randomness,
)
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID, MockNetworkRequester, make_store

# Patch target for the XMSS scheme reference inside service.py.
_SCHEME = "lean_spec.subspecs.validator.service.TARGET_SIGNATURE_SCHEME"


def _entry(index: int = 0) -> tuple[ValidatorEntry, MagicMock, MagicMock]:
    """Return (ValidatorEntry, att_key, prop_key) with distinct named mock keys."""
    att_key = MagicMock(name=f"att_{index}")
    prop_key = MagicMock(name=f"prop_{index}")
    return (
        ValidatorEntry(
            index=ValidatorIndex(index),
            attestation_secret_key=att_key,
            proposal_secret_key=prop_key,
        ),
        att_key,
        prop_key,
    )


def _registry(*indices: int) -> ValidatorRegistry:
    """Build a ValidatorRegistry with mock keys for the given indices."""
    reg = ValidatorRegistry()
    for i in indices:
        mk = MagicMock(name=f"key_{i}")
        reg.add(
            ValidatorEntry(
                index=ValidatorIndex(i),
                attestation_secret_key=mk,
                proposal_secret_key=mk,
            )
        )
    return reg


def _zero_sig() -> Signature:
    """
    Construct a structurally valid "zero" XMSS Signature for testing.

    This fills all required fields with zero-valued data so the object
    passes validation and can be used in unit tests. It is NOT a
    cryptographically valid signature and should never be used for
    real verification.
    """

    def zero_digest() -> HashDigestVector:
        return HashDigestVector(data=[Fp(0) for _ in range(TARGET_CONFIG.HASH_LEN_FE)])

    rho = Randomness(data=[Fp(0) for _ in range(TARGET_CONFIG.RAND_LEN_FE)])

    hashes = HashDigestList(data=[zero_digest()])

    path = HashTreeOpening(siblings=HashDigestList(data=[zero_digest()]))

    return Signature(
        path=path,
        rho=rho,
        hashes=hashes,
    )


def _mock_store(
    *,
    slot_for_block: Slot | None = None,
    head_state: object | None = None,
    validator_id: object | None = None,
) -> MagicMock:
    """
    Return a MagicMock store for unit tests.

    head_state=None causes _produce_attestations / _maybe_produce_block to
    return early, which is useful when the test only targets earlier code paths.
    """
    store = MagicMock()
    store.head = MagicMock(name="head_root")
    store.validator_id = validator_id
    store.update_head.return_value = store
    store.on_gossip_attestation.return_value = store
    store.produce_attestation_data.return_value = MagicMock(spec=AttestationData)

    if slot_for_block is not None:
        mock_block = MagicMock()
        mock_block.slot = slot_for_block
        store.blocks = {"b": mock_block}
    else:
        store.blocks = {}

    store.states = MagicMock()
    store.states.get.return_value = head_state

    return store


def _monotonic_clock(*, slot: Slot | None = None, interval: Uint64 | None = None) -> MagicMock:
    """
    Clock whose total_intervals() increments on every call.

    Use when the test drives the loop by calling service.stop() inside a mock,
    because a monotonically increasing counter means already_handled never fires
    accidentally (the loop always moves forward).
    """
    if slot is None:
        slot = Slot(0)
    if interval is None:
        interval = Uint64(0)

    clock = MagicMock(spec=SlotClock)
    _n: list[int] = [0]

    def _total() -> int:
        _n[0] += 1
        return _n[0]

    clock.total_intervals.side_effect = _total
    clock.current_slot.return_value = slot
    clock.current_interval.return_value = interval
    clock.sleep_until_next_interval = AsyncMock()
    return clock


def _fixed_clock(*, slot: Optional[Slot] = None, interval: Optional[Uint64] = None) -> MagicMock:
    slot = slot or Slot(0)
    interval = interval or Uint64(0)
    """
    Clock whose total_intervals() always returns the same value (1).

    Use when the test needs already_handled to fire on the second iteration,
    which triggers sleep_until_next_interval — useful for duplicate-prevention
    and slot-pruning tests where we stop via the sleep mock.
    """
    clock = MagicMock(spec=SlotClock)
    clock.total_intervals.return_value = 1
    clock.current_slot.return_value = slot
    clock.current_interval.return_value = interval
    clock.sleep_until_next_interval = AsyncMock()
    return clock


@pytest.fixture
def sync_service(base_store: Store) -> SyncService:
    """Sync service backed by the shared base store."""
    return SyncService(
        store=base_store,
        peer_manager=PeerManager(),
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0)),
        network=MockNetworkRequester(),
    )


# @pytest.fixture
# def mock_registry() -> ValidatorRegistry:
#     """Registry with mock keys for validators 0 and 1."""
#     registry = ValidatorRegistry()
#     for i in [0, 1]:
#         mock_key = MagicMock()
#         registry.add(
#             ValidatorEntry(
#                 index=ValidatorIndex(i),
#                 attestation_secret_key=mock_key,
#                 proposal_secret_key=mock_key,
#             )
#         )
#     return registry


@pytest.fixture
def mock_registry() -> ValidatorRegistry:
    """Registry with mock keys for validators 0 and 1."""
    return _registry(0, 1)


# _sign_block — unit tests


class TestSignBlock:
    """
    Unit tests for ValidatorService._sign_block().

    _sign_with_key is patched throughout so these tests cover only field
    population and key-type selection, not XMSS advancement logic.
    """

    def test_returns_signed_block_wrapping_the_input_block(self, sync_service: SyncService) -> None:
        """The returned SignedBlock.block is the exact block object that was passed in."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        block = Block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )
        zero_sig = _zero_sig()

        with patch.object(
            ValidatorService,
            "_sign_with_key",
            lambda self, e, slot, msg, kf: (e, zero_sig),
        ):
            result = service._sign_block(block, ValidatorIndex(0), [])

        assert isinstance(result, SignedBlock)
        assert result.block is block

    def test_proposer_signature_is_the_signature_from_sign_with_key(
        self, sync_service: SyncService
    ) -> None:
        """signature.proposer_signature is exactly what _sign_with_key returned."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        block = Block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )
        zero_sig = _zero_sig()

        with patch.object(
            ValidatorService,
            "_sign_with_key",
            lambda self, e, slot, msg, kf: (e, zero_sig),
        ):
            result = service._sign_block(block, ValidatorIndex(0), [])

        assert result.signature.proposer_signature == zero_sig

    def test_sign_with_key_receives_proposal_key_and_block_root(
        self, sync_service: SyncService
    ) -> None:
        """_sign_block passes proposal_secret_key and hash_tree_root(block) to _sign_with_key."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        block = Block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )
        zero_sig = _zero_sig()
        captured: list[tuple] = []

        def capture(self, e, slot, message, key_field):
            captured.append((slot, message, key_field))
            return (e, zero_sig)

        with patch.object(ValidatorService, "_sign_with_key", capture):
            service._sign_block(block, ValidatorIndex(0), [])

        assert len(captured) == 1
        slot, message, key_field = captured[0]
        assert slot == Slot(2)
        assert message == hash_tree_root(block)
        assert key_field == "proposal_secret_key"

    def test_attestation_signatures_wrapped_in_block_signatures(
        self, sync_service: SyncService
    ) -> None:
        """Aggregated attestation proofs passed in are present in the returned signature."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        block = Block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=sync_service.store.head,
            state_root=sync_service.store.head,
            body=sync_service.store.blocks[sync_service.store.head].body,
        )
        zero_sig = _zero_sig()
        agg_proof = MagicMock(spec=AggregatedSignatureProof)

        with patch.object(
            ValidatorService,
            "_sign_with_key",
            lambda self, e, slot, msg, kf: (e, zero_sig),
        ):
            result = service._sign_block(block, ValidatorIndex(0), [agg_proof])

        assert agg_proof in list(result.signature.attestation_signatures)

    def test_missing_validator_raises_value_error(self, sync_service: SyncService) -> None:
        """_sign_block raises ValueError when the index is not in the registry."""
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


# _sign_attestation — unit tests


class TestSignAttestation:
    """
    Unit tests for ValidatorService._sign_attestation().

    _sign_with_key is patched so tests cover only field population and
    key-type selection.
    """

    def test_returns_signed_attestation(self, sync_service: SyncService) -> None:
        """_sign_attestation returns a SignedAttestation instance."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))
        zero_sig = _zero_sig()

        with patch.object(
            ValidatorService, "_sign_with_key", lambda self, e, slot, msg, kf: (e, zero_sig)
        ):
            result = service._sign_attestation(att_data, ValidatorIndex(0))

        assert isinstance(result, SignedAttestation)

    def test_validator_id_field_matches_argument(self, sync_service: SyncService) -> None:
        """result.validator_id equals the validator_index that was passed in."""
        entry, _, _ = _entry(3)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))
        zero_sig = _zero_sig()

        with patch.object(
            ValidatorService, "_sign_with_key", lambda self, e, slot, msg, kf: (e, zero_sig)
        ):
            result = service._sign_attestation(att_data, ValidatorIndex(3))

        assert result.validator_id == ValidatorIndex(3)

    def test_data_field_is_the_attestation_data_passed_in(self, sync_service: SyncService) -> None:
        """result.data is the exact AttestationData object that was passed in."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))
        zero_sig = _zero_sig()

        with patch.object(
            ValidatorService, "_sign_with_key", lambda self, e, slot, msg, kf: (e, zero_sig)
        ):
            result = service._sign_attestation(att_data, ValidatorIndex(0))

        assert result.data is att_data

    def test_signature_field_is_exactly_what_sign_with_key_returned(
        self, sync_service: SyncService
    ) -> None:
        """result.signature is the exact object returned by _sign_with_key."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))
        zero_sig = _zero_sig()

        with patch.object(
            ValidatorService, "_sign_with_key", lambda self, e, slot, msg, kf: (e, zero_sig)
        ):
            result = service._sign_attestation(att_data, ValidatorIndex(0))

        assert result.signature is zero_sig

    def test_sign_with_key_receives_attestation_key_not_proposal_key(
        self, sync_service: SyncService
    ) -> None:
        """_sign_attestation selects attestation_secret_key, never proposal_secret_key."""
        entry, _, _ = _entry(0)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))
        zero_sig = _zero_sig()
        captured: list[str] = []

        def capture(self, e, slot, message, key_field):
            captured.append(key_field)
            return (e, zero_sig)

        with patch.object(ValidatorService, "_sign_with_key", capture):
            service._sign_attestation(att_data, ValidatorIndex(0))

        assert captured == ["attestation_secret_key"]

    def test_missing_validator_raises_value_error(self, sync_service: SyncService) -> None:
        """_sign_attestation raises ValueError when the index is not in the registry."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )
        att_data = sync_service.store.produce_attestation_data(Slot(1))

        with pytest.raises(ValueError, match="No secret key for validator 99"):
            service._sign_attestation(att_data, ValidatorIndex(99))


# _sign_with_key — unit tests


class TestSignWithKey:
    """
    Unit tests for ValidatorService._sign_with_key().

    The XMSS scheme is fully mocked (via _SCHEME) so these tests run without
    real key material and focus entirely on advancement logic, registry
    persistence, and key-field isolation.

    Why each case matters
    ----------------------
    no_advancement  Slot already covered → must not burn a key unnecessarily.
    one_advancement One advance gets the key into range → fast common case.
    multi_advance   Key is far behind slot → loop must keep advancing.
    registry_update After signing, registry.get(index) must see the new key.
    att_only        attestation key updated, proposal key completely unchanged.
    prop_only       proposal key updated, attestation key completely unchanged.
    return_value    Caller receives (updated_entry, signature) — both matter.
    """

    def _setup(
        self, sync_service: SyncService, index: int = 0
    ) -> tuple[ValidatorService, ValidatorRegistry, ValidatorEntry, MagicMock, MagicMock]:
        entry, att_key, prop_key = _entry(index)
        registry = ValidatorRegistry()
        registry.add(entry)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=registry,
        )
        return service, registry, entry, att_key, prop_key

    def test_no_advancement_when_slot_already_prepared(self, sync_service: SyncService) -> None:
        """advance_preparation is never called when the slot is already in the interval."""
        service, _, entry, att_key, _ = self._setup(sync_service)
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.return_value = [3]  # slot 3 already covered
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(3), MagicMock(), "attestation_secret_key")

        scheme.advance_preparation.assert_not_called()
        scheme.sign.assert_called_once_with(att_key, Slot(3), scheme.sign.call_args[0][2])

    def test_key_advanced_once_until_slot_in_interval(self, sync_service: SyncService) -> None:
        """advance_preparation is called exactly once when one step covers the slot."""
        service, _, entry, att_key, _ = self._setup(sync_service)
        advanced = MagicMock(name="advanced_key")
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            # Original key: slot 5 not ready.  Advanced key: slot 5 ready.
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [5]
            scheme.advance_preparation.return_value = advanced
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(5), MagicMock(), "attestation_secret_key")

        scheme.advance_preparation.assert_called_once_with(att_key)
        scheme.sign.assert_called_once_with(advanced, Slot(5), scheme.sign.call_args[0][2])

    def test_key_advanced_multiple_times_until_prepared(self, sync_service: SyncService) -> None:
        """advance_preparation loops until the target slot falls within the interval."""
        service, _, entry, att_key, _ = self._setup(sync_service)
        key_v1 = MagicMock(name="key_v1")
        key_v2 = MagicMock(name="key_v2")
        key_v3 = MagicMock(name="key_v3")  # Only v3 covers slot 7
        mock_sig = MagicMock(name="sig")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [7] if key is key_v3 else []
            scheme.advance_preparation.side_effect = [key_v1, key_v2, key_v3]
            scheme.sign.return_value = mock_sig

            service._sign_with_key(entry, Slot(7), MagicMock(), "attestation_secret_key")

        assert scheme.advance_preparation.call_count == 3
        scheme.sign.assert_called_once_with(key_v3, Slot(7), scheme.sign.call_args[0][2])

    def test_updated_entry_persisted_in_registry(self, sync_service: SyncService) -> None:
        """After signing, registry.get(index) holds an entry with the advanced key."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service)
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
        self, sync_service: SyncService
    ) -> None:
        """key_field='attestation_secret_key' updates only the attestation key."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service)
        advanced_att = MagicMock(name="new_att")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is att_key else [1]
            scheme.advance_preparation.return_value = advanced_att
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(1), MagicMock(), "attestation_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.attestation_secret_key is advanced_att
        assert stored.proposal_secret_key is prop_key  # untouched

    def test_proposal_key_updated_attestation_key_unchanged(
        self, sync_service: SyncService
    ) -> None:
        """key_field='proposal_secret_key' updates only the proposal key."""
        service, registry, entry, att_key, prop_key = self._setup(sync_service)
        advanced_prop = MagicMock(name="new_prop")

        with patch(_SCHEME) as scheme:
            scheme.get_prepared_interval.side_effect = lambda key: [] if key is prop_key else [1]
            scheme.advance_preparation.return_value = advanced_prop
            scheme.sign.return_value = MagicMock()

            service._sign_with_key(entry, Slot(1), MagicMock(), "proposal_secret_key")

        stored = registry.get(ValidatorIndex(0))
        assert stored is not None
        assert stored.proposal_secret_key is advanced_prop
        assert stored.attestation_secret_key is att_key  # untouched

    def test_returns_updated_entry_and_signature(self, sync_service: SyncService) -> None:
        """Return value is (updated ValidatorEntry, Signature) — both fields correct."""
        service, _, entry, att_key, _ = self._setup(sync_service)
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
    """Basic tests for ValidatorService lifecycle properties."""

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


# _maybe_produce_block — additional unit tests


class TestMaybeProduceBlock:
    """Unit tests for _maybe_produce_block() edge cases."""

    async def test_no_head_state_returns_early_without_producing(
        self, sync_service: SyncService
    ) -> None:
        """When store.states.get(head) is None, no block is produced and no error is raised."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
        )
        sync_service.store = _mock_store(head_state=None)

        blocks: list[SignedBlock] = []

        async def capture(block: SignedBlock) -> None:
            blocks.append(block)

        service.on_block = capture
        await service._maybe_produce_block(Slot(0))

        assert len(blocks) == 0

    async def test_assertion_error_from_store_is_logged_and_skipped(
        self, sync_service: SyncService, caplog: pytest.LogCaptureFixture
    ) -> None:
        """AssertionError from produce_block_with_signatures is caught; no block emitted."""
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
        )

        # Build a store that has a head state but raises on block production
        mock_head_state = MagicMock()
        mock_head_state.validators = [MagicMock()]  # 1 validator
        store = _mock_store(head_state=mock_head_state)
        store.produce_block_with_signatures.side_effect = AssertionError("proposer mismatch")
        sync_service.store = store

        blocks: list[SignedBlock] = []

        async def capture(block: SignedBlock) -> None:
            blocks.append(block)

        service.on_block = capture

        # Force our validator to appear as the proposer so the except branch is reached
        with patch.object(ValidatorIndex, "is_proposer_for", return_value=True):
            await service._maybe_produce_block(Slot(0))

        assert len(blocks) == 0


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


# _produce_attestations — block-wait loop and local processing


class TestProduceAttestationsAdvanced:
    """
    Unit tests for the block-wait polling loop and on_gossip_attestation call.

    Gossipsub does not self-deliver, so each attestation must be processed
    locally before publishing.  The wait loop exists because the current
    slot's block may not have arrived yet when interval 1 fires.
    """

    async def test_block_wait_polls_up_to_eight_times_when_no_block_arrives(
        self, sync_service: SyncService
    ) -> None:
        """
        If no block for the target slot ever arrives, the wait loop runs exactly 8 times
        with 0.05-second sleeps, then gives up and continues to attest anyway.
        """
        # The base store has a genesis block at slot 0; there is nothing at slot 99.
        target_slot = Slot(99)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),  # empty → no signing needed
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
        target_slot = Slot(77)
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
        )

        # Store starts with no block at target_slot; arrives on the 3rd sleep.
        sync_service.store = _mock_store(head_state=None)  # no head_state → early return after wait
        with_block = _mock_store(slot_for_block=target_slot, head_state=None)

        sleep_calls = [0]

        async def mock_sleep(duration: float) -> None:
            sleep_calls[0] += 1
            if sleep_calls[0] == 3:
                sync_service.store = with_block

        with patch("asyncio.sleep", new=mock_sleep):
            await service._produce_attestations(target_slot)

        # Should stop after 3 polls, not all 8
        assert sleep_calls[0] == 3

    async def test_attestation_processed_locally_via_on_gossip_attestation(
        self, sync_service: SyncService
    ) -> None:
        """
        Each produced attestation is passed to store.on_gossip_attestation before
        being published, ensuring the aggregator node counts its own validator's vote.
        """
        target_slot = Slot(1)
        mock_att = MagicMock(spec=SignedAttestation, name="att")

        mock_head_state = MagicMock()
        store = _mock_store(slot_for_block=target_slot, head_state=mock_head_state)
        store.validator_id = None  # keeps is_aggregator_role False (short-circuits)
        sync_service.store = store

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
        )

        with patch.object(ValidatorService, "_sign_attestation", lambda self, *a, **kw: mock_att):
            await service._produce_attestations(target_slot)

        store.on_gossip_attestation.assert_called_once_with(
            signed_attestation=mock_att,
            is_aggregator=False,
        )

    async def test_exception_in_on_gossip_attestation_does_not_prevent_publish(
        self, sync_service: SyncService
    ) -> None:
        """
        If on_gossip_attestation raises, the exception is swallowed and the attestation
        is still published via on_attestation so the network receives it.
        """
        target_slot = Slot(1)
        mock_att = MagicMock(spec=SignedAttestation, name="att")

        mock_head_state = MagicMock()
        store = _mock_store(slot_for_block=target_slot, head_state=mock_head_state)
        store.validator_id = None
        store.on_gossip_attestation.side_effect = RuntimeError("store error")
        sync_service.store = store

        published: list[SignedAttestation] = []

        async def capture_att(att: SignedAttestation) -> None:
            published.append(att)

        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=_registry(0),
            on_attestation=capture_att,
        )

        with patch.object(ValidatorService, "_sign_attestation", lambda self, data, vid: mock_att):
            await service._produce_attestations(target_slot)  # must not raise

        assert len(published) == 1
        assert published[0] is mock_att


# run() — main loop ( added new routing / duplicate / pruning tests)


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

    async def test_interval_0_triggers_block_production(self, sync_service: SyncService) -> None:
        """
        At interval 0, run() calls _maybe_produce_block for the current slot.

        Uses a monotonically increasing clock so already_handled never fires
        before service.stop() is called inside the mock.
        """
        clock = _monotonic_clock(slot=Slot(0), interval=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )

        block_slots: list[Slot] = []

        async def mock_produce(self_inner, slot: Slot) -> None:
            block_slots.append(slot)
            service.stop()  # exit after the first block check fires

        with patch.object(ValidatorService, "_maybe_produce_block", mock_produce):
            await service.run()

        assert block_slots == [Slot(0)]

    async def test_interval_1_triggers_attestation(self, sync_service: SyncService) -> None:
        """At interval >= 1, run() calls _produce_attestations for the current slot."""
        clock = _monotonic_clock(slot=Slot(0), interval=Uint64(1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )

        attest_slots: list[Slot] = []

        async def mock_attest(self_inner, slot: Slot) -> None:
            attest_slots.append(slot)
            service.stop()

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        assert attest_slots == [Slot(0)]

    async def test_empty_registry_skips_all_duties(self, sync_service: SyncService) -> None:
        """
        With an empty registry, run() loops via the continue branch without
        ever calling _maybe_produce_block or _produce_attestations.
        """
        clock = _fixed_clock(slot=Slot(0), interval=Uint64(0))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=ValidatorRegistry(),  # empty
        )

        sleep_calls = [0]

        async def stop_after_two_sleeps() -> None:
            sleep_calls[0] += 1
            if sleep_calls[0] >= 2:
                service.stop()

        clock.sleep_until_next_interval = AsyncMock(side_effect=stop_after_two_sleeps)

        block_calls: list[Slot] = []
        attest_calls: list[Slot] = []

        with (
            patch.object(
                ValidatorService,
                "_maybe_produce_block",
                AsyncMock(side_effect=lambda self, s: block_calls.append(s)),
            ),
            patch.object(
                ValidatorService,
                "_produce_attestations",
                AsyncMock(side_effect=lambda self, s: attest_calls.append(s)),
            ),
        ):
            await service.run()

        assert block_calls == []
        assert attest_calls == []

    async def test_duplicate_prevention_same_slot_not_attested_twice(
        self, sync_service: SyncService
    ) -> None:
        """
        _produce_attestations is never called for a slot already in _attested_slots.

        The fixed clock makes already_handled fire on the second pass, which
        triggers sleep_until_next_interval.  The sleep mock then stops the service.
        """
        clock = _fixed_clock(slot=Slot(5), interval=Uint64(1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )
        service._attested_slots = {Slot(5)}  # already attested

        async def stop_on_sleep() -> None:
            service.stop()

        clock.sleep_until_next_interval = AsyncMock(side_effect=stop_on_sleep)

        attest_calls: list[Slot] = []

        async def mock_attest(self_inner, slot: Slot) -> None:
            attest_calls.append(slot)

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        assert attest_calls == []

    async def test_slot_pruning_removes_slots_older_than_threshold(
        self, sync_service: SyncService
    ) -> None:
        """
        After attesting at slot N, _attested_slots is pruned to keep only
        slots >= max(0, N - 4), preventing unbounded memory growth.

        At slot 10: prune_threshold = max(0, 10 - 4) = 6.
        Slots 0-5 (all < 6) must be removed; slot 10 must be present.
        """
        clock = _monotonic_clock(slot=Slot(10), interval=Uint64(1))
        service = ValidatorService(
            sync_service=sync_service,
            clock=clock,
            registry=_registry(0),
        )
        # Pre-fill with old slots that should all be pruned
        service._attested_slots = {Slot(i) for i in range(6)}  # slots 0-5

        async def mock_attest(self_inner, slot: Slot) -> None:
            service.stop()  # stop after the first attestation — pruning runs after this returns

        with patch.object(ValidatorService, "_produce_attestations", mock_attest):
            await service.run()

        # Slots 0-5 must be gone (< prune_threshold 6)
        for old_slot in range(6):
            assert Slot(old_slot) not in service._attested_slots
        # Slot 10 was just added
        assert Slot(10) in service._attested_slots


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
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
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
        service = ValidatorService(
            sync_service=sync_service,
            clock=SlotClock(genesis_time=Uint64(0)),
            registry=ValidatorRegistry(),
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
        """Signatures verify with the signing slot but fail with any other slot."""
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
            assert is_valid, f"Slot {test_slot} signature failed for validator {validator_id}"

            # Verify with wrong slot should fail
            wrong_slot = test_slot + Slot(1)
            is_invalid = TARGET_SIGNATURE_SCHEME.verify(
                pk=public_key,
                slot=wrong_slot,
                message=message_bytes,
                sig=signed_att.signature,
            )
            assert not is_invalid, "Signature should not verify with the wrong slot"
