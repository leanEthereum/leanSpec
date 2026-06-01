"""Tests for attestation signature aggregation and block building."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.node.chain.config import MAX_ATTESTATIONS_DATA
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex, ValidatorIndices
from lean_spec.spec.forks.lstar import AttestationSignatureEntry
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    JustifiedSlots,
    SingleMessageAggregate,
    State,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec, _Tier
from lean_spec.spec.ssz import Boolean, Bytes32
from tests.lean_spec.helpers import (
    make_aggregated_proof,
    make_attestation_data_simple,
    make_bytes32,
    make_keyed_genesis_state,
    make_store,
)


def _build_empty_chain(
    spec: LstarSpec,
    key_manager: XmssKeyManager,
    num_validators: int,
    num_blocks: int,
) -> tuple[State, list[Bytes32]]:
    """Build genesis -> block_1 -> ... -> block_{num_blocks} with empty bodies.

    Returns the head state and a list of block roots indexed by slot, where
    index 0 is the genesis root and index k is the root of the slot-k block.
    """
    state = make_keyed_genesis_state(num_validators, key_manager)
    roots: list[Bytes32] = [
        hash_tree_root(
            state.latest_block_header.model_copy(update={"state_root": hash_tree_root(state)})
        )
    ]
    for slot in range(1, num_blocks + 1):
        block = Block(
            slot=Slot(slot),
            proposer_index=ValidatorIndex(slot % num_validators),
            parent_root=roots[-1],
            state_root=Bytes32.zero(),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )
        state = spec.process_block(spec.process_slots(state, Slot(slot)), block)
        roots.append(
            hash_tree_root(
                state.latest_block_header.model_copy(update={"state_root": hash_tree_root(state)})
            )
        )
    return state, roots


def test_aggregated_signatures_prefers_full_gossip_payload(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    store = make_store(num_validators=2, key_manager=container_key_manager)
    head_state = store.states[store.head]
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    attestation_data = make_attestation_data_simple(
        Slot(2), make_bytes32(3), make_bytes32(4), source=source
    )
    attestation_signatures = {
        attestation_data: {
            AttestationSignatureEntry(
                ValidatorIndex(i),
                container_key_manager.sign_attestation_data(ValidatorIndex(i), attestation_data),
            )
            for i in range(2)
        }
    }

    store.attestation_signatures = attestation_signatures
    _, results = spec.aggregate(store)

    assert len(results) == 1
    assert set(results[0].proof.participants.to_validator_indices()) == {
        ValidatorIndex(0),
        ValidatorIndex(1),
    }

    public_keys = [
        head_state.validators[ValidatorIndex(i)].get_attestation_public_key() for i in range(2)
    ]
    results[0].proof.verify(
        public_keys=public_keys,
        message=hash_tree_root(attestation_data),
        slot=attestation_data.slot,
    )


def test_build_block_collects_valid_available_attestations(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    state = make_keyed_genesis_state(2, container_key_manager)
    state.latest_block_header.state_root = hash_tree_root(state)
    parent_root = hash_tree_root(state.latest_block_header)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    target = Checkpoint(root=parent_root, slot=Slot(0))
    attestation_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=target,
        source=source,
    )
    data_root = hash_tree_root(attestation_data)

    proof = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], attestation_data)
    aggregated_payloads = {attestation_data: {proof}}

    block, post_state, aggregated_atts, aggregated_proofs = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads=aggregated_payloads,
    )

    assert post_state.latest_block_header.slot == Slot(1)
    assert list(block.body.attestations.data) == aggregated_atts
    assert len(aggregated_proofs) == 1
    assert aggregated_proofs[0].participants.to_validator_indices() == ValidatorIndices(
        data=[ValidatorIndex(0)]
    )
    assert block.body.attestations.data[0].aggregation_bits.to_validator_indices() == (
        ValidatorIndices(data=[ValidatorIndex(0)])
    )

    aggregated_proofs[0].verify(
        public_keys=[container_key_manager[ValidatorIndex(0)].attestation_keypair.public_key],
        message=data_root,
        slot=attestation_data.slot,
    )


def test_build_block_skips_attestations_without_signatures(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    state = make_keyed_genesis_state(1, container_key_manager)
    state.latest_block_header.state_root = hash_tree_root(state)
    parent_root = hash_tree_root(state.latest_block_header)

    block, post_state, aggregated_atts, aggregated_proofs = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={},
    )

    assert post_state.latest_block_header.slot == Slot(1)
    assert aggregated_atts == []
    assert aggregated_proofs == []
    assert list(block.body.attestations.data) == []


def test_aggregate_with_empty_attestation_signatures(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Empty attestations list should return empty results."""
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = spec.aggregate(store)

    assert results == []


def test_aggregated_signatures_with_multiple_data_groups(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Multiple attestation data groups should be processed independently."""
    store = make_store(num_validators=4, key_manager=container_key_manager)
    source = Checkpoint(root=make_bytes32(22), slot=Slot(0))
    attestation_data1 = make_attestation_data_simple(
        Slot(9), make_bytes32(23), make_bytes32(24), source=source
    )
    attestation_data2 = make_attestation_data_simple(
        Slot(10), make_bytes32(25), make_bytes32(26), source=source
    )

    attestation_signatures = {
        attestation_data1: {
            AttestationSignatureEntry(
                ValidatorIndex(0),
                container_key_manager.sign_attestation_data(ValidatorIndex(0), attestation_data1),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(1),
                container_key_manager.sign_attestation_data(ValidatorIndex(1), attestation_data1),
            ),
        },
        attestation_data2: {
            AttestationSignatureEntry(
                ValidatorIndex(2),
                container_key_manager.sign_attestation_data(ValidatorIndex(2), attestation_data2),
            ),
            AttestationSignatureEntry(
                ValidatorIndex(3),
                container_key_manager.sign_attestation_data(ValidatorIndex(3), attestation_data2),
            ),
        },
    }

    store.attestation_signatures = attestation_signatures
    _, results = spec.aggregate(store)

    assert len(results) == 2

    for signed_attestation in results:
        participants = signed_attestation.proof.participants.to_validator_indices()
        public_keys = [
            container_key_manager[validator_index].attestation_keypair.public_key
            for validator_index in participants
        ]
        signed_attestation.proof.verify(
            public_keys=public_keys,
            message=hash_tree_root(signed_attestation.data),
            slot=signed_attestation.data.slot,
        )


def test_build_block_state_root_valid_when_signatures_split(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """
    Verify state root validity when attestations split across signature sources.

    Signatures arrive through two channels in the protocol:

    1. Gossip network - individual validator signatures propagated in real-time
    2. Aggregated proofs - batched signatures from block payloads

    When both sources cover the same attestation data, they cannot always merge.
    Each source may cover different validator subsets.
    The aggregation process must split them into separate attestations.

    This creates a critical constraint: the block's state root must reflect
    the final attestation structure, not a preliminary grouping.

    Test scenario:

    - Three validators attest to identical data
    - One signature arrives via gossip (validator 0)
    - Two signatures arrive via aggregated proof (validators 1, 2)
    - Result: two attestations in the block, not one
    - The state transition must succeed with correct state root
    """
    num_validators = 4
    pre_state = make_keyed_genesis_state(num_validators, container_key_manager)

    pre_state.latest_block_header.state_root = hash_tree_root(pre_state)
    parent_root = hash_tree_root(pre_state.latest_block_header)

    source = Checkpoint(root=parent_root, slot=Slot(0))
    target = Checkpoint(root=parent_root, slot=Slot(0))

    attestation_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=target,
        source=source,
    )

    proof_0 = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], attestation_data)

    fallback_proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1), ValidatorIndex(2)], attestation_data
    )
    aggregated_payloads = {attestation_data: {proof_0, fallback_proof}}

    block, _, aggregated_atts, _ = spec.build_block(
        pre_state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads=aggregated_payloads,
    )

    assert len(aggregated_atts) == 1, "Expected compaction into 1 attestation"

    covered = set(aggregated_atts[0].aggregation_bits.to_validator_indices())
    assert covered == {ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)}, (
        "Compacted attestation should cover all three validators"
    )

    result_state = spec.state_transition(pre_state, block)

    assert result_state.slot == Slot(1)
    assert result_state.latest_block_header.slot == Slot(1)
    assert result_state.latest_block_header.proposer_index == ValidatorIndex(1)
    assert result_state.latest_block_header.parent_root == parent_root
    assert block.state_root == hash_tree_root(result_state)
    assert len(block.body.attestations.data) == 1
    assert len(result_state.validators.data) == num_validators


def test_build_block_skips_other_chain_source(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Only attestation data whose source matches the current chain is included."""
    state = make_keyed_genesis_state(2, container_key_manager)
    state.latest_block_header.state_root = hash_tree_root(state)
    parent_root = hash_tree_root(state.latest_block_header)
    correct_source = Checkpoint(root=parent_root, slot=Slot(0))
    wrong_source = Checkpoint(root=make_bytes32(99), slot=Slot(0))

    attestation_data_good = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=correct_source,
    )
    attestation_data_bad = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=wrong_source,
    )

    proof_good = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(0)], attestation_data_good
    )
    proof_bad = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1)], attestation_data_bad
    )

    _, _, aggregated_atts, _ = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={
            attestation_data_good: {proof_good},
            attestation_data_bad: {proof_bad},
        },
    )

    assert len(aggregated_atts) == 1
    assert aggregated_atts[0].data == attestation_data_good


def test_build_block_skips_unknown_head_root(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Attestation data with head root not in known_block_roots is excluded."""
    state = make_keyed_genesis_state(2, container_key_manager)
    state.latest_block_header.state_root = hash_tree_root(state)
    parent_root = hash_tree_root(state.latest_block_header)
    source = Checkpoint(root=parent_root, slot=Slot(0))
    unknown_root = make_bytes32(200)

    attestation_data_known = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=parent_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=source,
    )
    attestation_data_unknown = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=unknown_root, slot=Slot(0)),
        target=Checkpoint(root=parent_root, slot=Slot(0)),
        source=source,
    )

    proof_known = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(0)], attestation_data_known
    )
    proof_unknown = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(1)], attestation_data_unknown
    )

    _, _, aggregated_atts, _ = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={
            attestation_data_known: {proof_known},
            attestation_data_unknown: {proof_unknown},
        },
    )

    assert len(aggregated_atts) == 1
    assert aggregated_atts[0].data == attestation_data_known


def test_aggregate_with_no_signatures(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """
    Test edge case where the store has no attestation signatures or payloads.

    Returns empty results (no attestations can be aggregated without signatures).
    """
    store = make_store(num_validators=2, key_manager=container_key_manager)
    _, results = spec.aggregate(store)

    assert results == []


def test_build_running_votes_empty_for_fresh_genesis(
    container_key_manager: XmssKeyManager,
) -> None:
    state = make_keyed_genesis_state(3, container_key_manager)
    assert LstarSpec._build_running_votes(state) == {}


def test_build_block_fixed_point_closes_justified_divergence(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """
    Fixed-point loop advances justification when pool attestations are available.

    Simulates the justified divergence scenario:

    - State has latest_justified at genesis (slot 0)
    - Pool contains attestations from 3/4 validators targeting slot 1
    - The fixed-point loop must include them and advance justification

    This is the mechanism that closes the gap when the store's justified
    checkpoint has advanced from a minority fork but the head chain lags.
    """
    num_validators = 4
    state_0 = make_keyed_genesis_state(num_validators, container_key_manager)

    # Build a two-block chain: genesis -> block_1 (slot 1) -> block_2 (slot 2).
    #
    # After block_1, the state marks genesis as justified (first post-genesis
    # block triggers the trust anchor). After block_2, justified is still
    # genesis — no attestations have been processed yet.

    # Compute genesis root (needed as parent for block_1).
    state_0.latest_block_header.state_root = hash_tree_root(state_0)
    genesis_root = hash_tree_root(state_0.latest_block_header)

    block_1 = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=genesis_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    state_1 = spec.process_slots(state_0, Slot(1))
    state_1 = spec.process_block(state_1, block_1)

    # After block_1: justified = (genesis_root, slot=0).
    assert state_1.latest_justified == Checkpoint(root=genesis_root, slot=Slot(0))

    state_1.latest_block_header.state_root = hash_tree_root(state_1)
    block_1_root = hash_tree_root(state_1.latest_block_header)

    block_2 = Block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(2),
        parent_root=block_1_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    state_2 = spec.process_slots(state_1, Slot(2))
    state_2 = spec.process_block(state_2, block_2)

    # Still at genesis justified — no attestations processed.
    assert state_2.latest_justified == Checkpoint(root=genesis_root, slot=Slot(0))

    state_2.latest_block_header.state_root = hash_tree_root(state_2)
    block_2_root = hash_tree_root(state_2.latest_block_header)

    # Create attestations targeting slot 1 from V1+V2+V3.
    #
    # source = genesis justified checkpoint
    # target = block_1 at slot 1
    #
    # These simulate attestations the store received from a minority fork.
    # The head state never processed them, creating the divergence.
    source = Checkpoint(root=genesis_root, slot=Slot(0))
    target = Checkpoint(root=block_1_root, slot=Slot(1))

    attestation_data = AttestationData(
        slot=Slot(3),
        head=target,
        target=target,
        source=source,
    )

    proof = make_aggregated_proof(
        container_key_manager,
        [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        attestation_data,
    )

    # Call build_block with the divergent attestations in the pool.
    #
    # The fixed-point loop should:
    #   Pass 1: current_justified = genesis -> attestations match (source=genesis)
    #           3/4 supermajority -> justifies slot 1
    #   Pass 2: no new entries -> done
    _, post_state, aggregated_atts, _ = spec.build_block(
        state_2,
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=block_2_root,
        known_block_roots={genesis_root, block_1_root, block_2_root},
        aggregated_payloads={attestation_data: {proof}},
    )

    # The block must include the justifying attestations.
    assert len(aggregated_atts) == 1
    assert aggregated_atts[0].data == attestation_data

    # Justification must have advanced: the fixed-point loop closed the gap.
    assert post_state.latest_justified.slot >= Slot(1)
    assert post_state.latest_justified == target


def test_score_entry_genesis_self_vote_is_build_tier(
    container_key_manager: XmssKeyManager,
) -> None:
    # Genesis self-vote: source.slot == target.slot == 0.
    # Even with a supermajority it can never justify or finalize, so it scores BUILD.
    genesis = Checkpoint(root=make_bytes32(7), slot=Slot(0))
    att_data = AttestationData(slot=Slot(1), head=genesis, target=genesis, source=genesis)
    proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(0), ValidatorIndex(1)], att_data
    )

    scored = LstarSpec._score_entry(
        att_data,
        {proof},
        current_votes={},
        projected_finalized_slot=Slot(0),
        validator_count=2,
    )
    assert scored is not None
    score, new_voters = scored
    assert score.tier == _Tier.BUILD
    assert new_voters == {ValidatorIndex(0), ValidatorIndex(1)}


def test_score_entry_returns_none_when_no_new_voters(
    container_key_manager: XmssKeyManager,
) -> None:
    genesis = Checkpoint(root=make_bytes32(7), slot=Slot(0))
    att_data = AttestationData(slot=Slot(1), head=genesis, target=genesis, source=genesis)
    proof = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data)

    # Validator 0 already recorded for this target root: zero new voters.
    scored = LstarSpec._score_entry(
        att_data,
        {proof},
        current_votes={att_data.target.root: {ValidatorIndex(0)}},
        projected_finalized_slot=Slot(0),
        validator_count=2,
    )
    assert scored is None


def test_score_entry_finalize_tier_when_gap_slots_not_justifiable(
    container_key_manager: XmssKeyManager,
) -> None:
    # Source slot 6, target slot 9: slots 7 and 8 are not justifiable after
    # finalized 0 (distances 7 and 8).
    # Source and target are therefore consecutive justified checkpoints, so a
    # supermajority entry finalizes its source.
    source = Checkpoint(root=make_bytes32(1), slot=Slot(6))
    target = Checkpoint(root=make_bytes32(2), slot=Slot(9))
    head = Checkpoint(root=make_bytes32(3), slot=Slot(0))
    att_data = AttestationData(slot=Slot(9), head=head, target=target, source=source)
    proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(i) for i in range(4)], att_data
    )

    scored = LstarSpec._score_entry(
        att_data,
        {proof},
        current_votes={},
        projected_finalized_slot=Slot(0),
        validator_count=4,
    )
    assert scored is not None
    score, _ = scored
    assert score.tier == _Tier.FINALIZE


def test_score_entry_older_source_after_finalization_does_not_raise(
    container_key_manager: XmssKeyManager,
) -> None:
    # Regression: with the finalized boundary advanced to slot 6, a candidate
    # sourced at genesis (slot 0) must be scored without scanning slots at or
    # below the finalized boundary.
    # is_justifiable_after rejects a slot behind the finalized boundary, so an
    # unclamped scan would raise here.
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    target = Checkpoint(root=make_bytes32(2), slot=Slot(9))
    head = Checkpoint(root=make_bytes32(3), slot=Slot(0))
    att_data = AttestationData(slot=Slot(9), head=head, target=target, source=source)
    proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(i) for i in range(4)], att_data
    )

    scored = LstarSpec._score_entry(
        att_data,
        {proof},
        current_votes={},
        projected_finalized_slot=Slot(6),
        validator_count=4,
    )
    assert scored is not None
    score, _ = scored
    # Slot 7 is justifiable after finalized 6 (distance 1), so this justifies
    # rather than finalizes.
    # The regression point is that scoring completes without raising.
    assert score.tier == _Tier.JUSTIFY


def test_score_entry_older_source_with_short_gap_is_not_finalize(
    container_key_manager: XmssKeyManager,
) -> None:
    # Regression for the boundary-regression bug.
    # Source at genesis (slot 0) is behind a projected finalized boundary at
    # slot 5; target at slot 6 leaves an empty gap range (6, 6).
    # An unguarded predicate would let all([]) vacuously hold and misclassify
    # the entry as FINALIZE, after which _select_attestations would assign
    # finalized_slot = 0 and corrupt the projection window.
    # Finalization is monotonic, so this candidate must score as JUSTIFY.
    source = Checkpoint(root=make_bytes32(1), slot=Slot(0))
    target = Checkpoint(root=make_bytes32(2), slot=Slot(6))
    head = Checkpoint(root=make_bytes32(3), slot=Slot(0))
    att_data = AttestationData(slot=Slot(6), head=head, target=target, source=source)
    proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(i) for i in range(4)], att_data
    )

    scored = LstarSpec._score_entry(
        att_data,
        {proof},
        current_votes={},
        projected_finalized_slot=Slot(5),
        validator_count=4,
    )
    assert scored is not None
    score, _ = scored
    assert score.tier == _Tier.JUSTIFY


def test_score_entry_source_at_finalized_boundary_is_not_finalize(
    container_key_manager: XmssKeyManager,
) -> None:
    # Source sits exactly on the projected finalized boundary at slot 6.
    # Target at slot 7 is the next justifiable slot, so the gap range (7, 7) is
    # empty and a supermajority would otherwise look like a finalizing entry.
    # A source at the boundary is already final, so it justifies the newer target
    # but must not re-finalize.
    # This mirrors the state transition, which advances finalization only when the
    # source slot is strictly greater than the finalized slot.
    source = Checkpoint(root=make_bytes32(1), slot=Slot(6))
    target = Checkpoint(root=make_bytes32(2), slot=Slot(7))
    head = Checkpoint(root=make_bytes32(3), slot=Slot(8))
    att_data = AttestationData(slot=Slot(8), head=head, target=target, source=source)
    proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(i) for i in range(4)], att_data
    )

    scored = LstarSpec._score_entry(
        att_data,
        {proof},
        current_votes={},
        projected_finalized_slot=Slot(6),
        validator_count=4,
    )
    assert scored is not None
    score, _ = scored
    assert score.tier == _Tier.JUSTIFY


def test_entry_passes_filters_rejects_unknown_head() -> None:
    chain = [make_bytes32(10), make_bytes32(11)]  # slots 0, 1
    source = Checkpoint(root=chain[0], slot=Slot(0))
    target = Checkpoint(root=chain[1], slot=Slot(1))
    head = Checkpoint(root=make_bytes32(99), slot=Slot(0))  # not in known roots
    att_data = AttestationData(slot=Slot(1), head=head, target=target, source=source)

    assert not LstarSpec._entry_passes_filters(
        att_data,
        known_block_roots=set(),
        extended_historical_block_hashes=chain,
        projected_justified_slots=JustifiedSlots(data=[]),
        projected_finalized_slot=Slot(0),
    )


def test_entry_passes_filters_accepts_valid_gap_closer() -> None:
    chain = [make_bytes32(10), make_bytes32(11), make_bytes32(12)]  # slots 0, 1, 2
    source = Checkpoint(root=chain[0], slot=Slot(0))  # slot 0 is implicitly justified
    target = Checkpoint(root=chain[2], slot=Slot(2))
    head = Checkpoint(root=chain[0], slot=Slot(0))
    att_data = AttestationData(slot=Slot(3), head=head, target=target, source=source)

    assert LstarSpec._entry_passes_filters(
        att_data,
        known_block_roots={chain[0]},
        extended_historical_block_hashes=chain,
        projected_justified_slots=JustifiedSlots(data=[Boolean(False), Boolean(False)]),
        projected_finalized_slot=Slot(0),
    )


def test_build_block_cascades_projected_justification_across_rounds(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    # Round 1 selects A (source slot 0, target slot 1), projecting slot 1
    # justified in-loop. B has source slot 1, which is NOT justified against
    # the initial state; the projection admits B in round 2 so the proposer
    # packs both attestations without re-running the state transition.
    num_validators = 4
    head_state, roots = _build_empty_chain(spec, container_key_manager, num_validators, 2)
    parent_root = roots[2]  # head is the slot-2 block

    all_validators = [ValidatorIndex(i) for i in range(num_validators)]
    att_a = AttestationData(
        slot=Slot(3),
        head=Checkpoint(root=roots[0], slot=Slot(0)),
        target=Checkpoint(root=roots[1], slot=Slot(1)),
        source=Checkpoint(root=roots[0], slot=Slot(0)),
    )
    att_b = AttestationData(
        slot=Slot(3),
        head=Checkpoint(root=roots[0], slot=Slot(0)),
        target=Checkpoint(root=roots[2], slot=Slot(2)),
        source=Checkpoint(root=roots[1], slot=Slot(1)),
    )
    proof_a = make_aggregated_proof(container_key_manager, all_validators, att_a)
    proof_b = make_aggregated_proof(container_key_manager, all_validators, att_b)

    block, post_state, _atts, _sigs = spec.build_block(
        head_state,
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=parent_root,
        known_block_roots={roots[0], roots[1], roots[2]},
        aggregated_payloads={att_a: {proof_a}, att_b: {proof_b}},
    )

    target_slots = {att.data.target.slot for att in block.body.attestations.data}
    assert Slot(1) in target_slots, f"A (target slot 1) missing: {target_slots}"
    assert Slot(2) in target_slots, (
        f"B (target slot 2) missing despite cascading projection: {target_slots}"
    )
    # Both attestations justify their targets; the final STF lands on slot 2.
    assert post_state.latest_justified.slot == Slot(2)


def test_build_block_absorbs_older_but_justified_source(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    # Drive the head's latest_justified to slot 1, then feed a pool attestation
    # whose source is genesis (slot 0, OLDER than latest_justified). The
    # is_slot_justified(source.slot) filter still accepts it (slot 0 is behind
    # the finalized boundary), so it is absorbed and justifies slot 2.
    num_validators = 4
    supermajority = [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)]  # 3/4 >= ceil(8/3)
    head_state, roots = _build_empty_chain(spec, container_key_manager, num_validators, 2)

    # Justify slot 1 on the head chain by processing a slot-3 block whose body
    # carries 3/4 votes for the slot-1 block.
    just_att = AttestationData(
        slot=Slot(3),
        head=Checkpoint(root=roots[1], slot=Slot(1)),
        target=Checkpoint(root=roots[1], slot=Slot(1)),
        source=Checkpoint(root=roots[0], slot=Slot(0)),
    )
    just_proof = make_aggregated_proof(container_key_manager, supermajority, just_att)
    justifying_block = Block(
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=roots[2],
        state_root=Bytes32.zero(),
        body=BlockBody(
            attestations=AggregatedAttestations(
                data=[
                    spec.aggregated_attestation_class(
                        aggregation_bits=just_proof.participants, data=just_att
                    )
                ]
            )
        ),
    )
    head_state = spec.process_block(spec.process_slots(head_state, Slot(3)), justifying_block)
    block_3_root = hash_tree_root(
        head_state.latest_block_header.model_copy(update={"state_root": hash_tree_root(head_state)})
    )
    assert head_state.latest_justified.slot == Slot(1)

    # Pool attestation: source = genesis (older than justified slot 1),
    # target = slot 2. Build a block at slot 4 on the slot-3 head.
    gap_att = AttestationData(
        slot=Slot(4),
        head=Checkpoint(root=roots[0], slot=Slot(0)),
        target=Checkpoint(root=roots[2], slot=Slot(2)),
        source=Checkpoint(root=roots[0], slot=Slot(0)),
    )
    gap_proof = make_aggregated_proof(
        container_key_manager, [ValidatorIndex(i) for i in range(num_validators)], gap_att
    )

    block, post_state, _atts, _sigs = spec.build_block(
        head_state,
        slot=Slot(4),
        proposer_index=ValidatorIndex(0),
        parent_root=block_3_root,
        known_block_roots={roots[0], roots[1], roots[2], block_3_root},
        aggregated_payloads={gap_att: {gap_proof}},
    )

    targets = {att.data.target for att in block.body.attestations.data}
    assert gap_att.target in targets, f"missing gap-closing attestation: {targets}"
    assert post_state.latest_justified.slot == Slot(2)


def test_build_block_caps_attestation_data_entries(
    container_key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    # Nine distinct entries each target a different justifiable slot with a single
    # voter. With 8 validators the supermajority is 6, so no individual entry
    # justifies its target (1/8 < 2/3), and selection stops at MAX_ATTESTATIONS_DATA (8).
    #
    # Justifiable slots after slot 0: 1, 2, 3, 4, 5, 6, 9, 12, 16 (first nine).
    # Build chain to slot 16 so all target roots exist on-chain.
    num_validators = 8
    target_slots = [1, 2, 3, 4, 5, 6, 9, 12, 16]  # 9 slots, all justifiable after slot 0
    head_state, roots = _build_empty_chain(spec, container_key_manager, num_validators, 16)
    parent_root = roots[16]  # head is the slot-16 block

    aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = {}
    for t in target_slots:
        # One voter per entry so no target ever reaches supermajority (1/8 < 2/3).
        att_data = AttestationData(
            slot=Slot(17),  # attestation slot 17, well within max_slot=20
            head=Checkpoint(root=roots[t], slot=Slot(t)),
            target=Checkpoint(root=roots[t], slot=Slot(t)),
            source=Checkpoint(root=roots[0], slot=Slot(0)),
        )
        proof = make_aggregated_proof(container_key_manager, [ValidatorIndex(0)], att_data)
        aggregated_payloads[att_data] = {proof}

    block, _post_state, _atts, _sigs = spec.build_block(
        head_state,
        slot=Slot(17),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={roots[s] for s in range(17)},
        aggregated_payloads=aggregated_payloads,
    )

    distinct_data = {att.data for att in block.body.attestations.data}
    assert len(distinct_data) == int(MAX_ATTESTATIONS_DATA)
