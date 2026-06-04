"""Tests for proposer-side block building in the lstar fork."""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    State,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32
from tests.lean_spec.helpers import make_aggregated_proof, make_keyed_genesis_state


def _seal_header(state: State) -> Bytes32:
    """Write the post-state root into the header and return that header root."""
    # A child block references its parent by the parent header root.
    # That root is only final once the parent post-state root is filled in.
    state.latest_block_header = state.latest_block_header.model_copy(
        update={"state_root": hash_tree_root(state)}
    )
    return hash_tree_root(state.latest_block_header)


def _genesis_with_parent(
    num_validators: int,
    key_manager: XmssKeyManager,
) -> tuple[State, Bytes32]:
    """Build a keyed genesis state and seal its header for use as a parent."""
    state = make_keyed_genesis_state(num_validators, key_manager)
    return state, _seal_header(state)


def _chain_through_slot_two(
    spec: LstarSpec,
    key_manager: XmssKeyManager,
    num_validators: int,
    *,
    justify_slot_one: bool = False,
) -> tuple[State, Bytes32, Bytes32, Bytes32]:
    """Apply a three-block chain and return the slot-two state with its roots.

    The chain runs genesis, then a slot-one block, then a slot-two block.

    Fixture state:

        justified : genesis only, unless slot-one justification is requested
        slot one  : justified by a full vote inside the slot-two body on request

    Returns the slot-two state and the genesis, slot-one, and slot-two roots.
    """
    state, genesis_root = _genesis_with_parent(num_validators, key_manager)

    block_one = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=genesis_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    state = spec.process_block(spec.process_slots(state, Slot(1)), block_one)
    block_one_root = _seal_header(state)

    # The slot-two body stays empty unless a caller needs slot one justified.
    # A full vote for slot one inside the body crosses the supermajority.
    slot_two_body = AggregatedAttestations(data=[])
    if justify_slot_one:
        vote = AttestationData(
            slot=Slot(2),
            head=Checkpoint(root=block_one_root, slot=Slot(1)),
            target=Checkpoint(root=block_one_root, slot=Slot(1)),
            source=Checkpoint(root=genesis_root, slot=Slot(0)),
        )
        voters = [ValidatorIndex(index) for index in range(num_validators)]
        proof = make_aggregated_proof(key_manager, voters, vote)
        slot_two_body = AggregatedAttestations(
            data=[AggregatedAttestation(aggregation_bits=proof.participants, data=vote)]
        )

    block_two = Block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(2),
        parent_root=block_one_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=slot_two_body),
    )
    state = spec.process_block(spec.process_slots(state, Slot(2)), block_two)
    block_two_root = _seal_header(state)

    return state, genesis_root, block_one_root, block_two_root


def test_build_block_with_empty_pool_produces_empty_body(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """An empty candidate pool yields a block with no attestations."""
    # Start from a sealed genesis with a single validator.
    state, parent_root = _genesis_with_parent(1, key_manager)

    # Build on genesis with nothing in the candidate pool.
    block, post_state, attestations, proofs = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={},
    )

    # With no candidates there is nothing to select, so both lists are empty.
    assert attestations == []
    assert proofs == []

    # The produced block is the empty-body block built on top of genesis.
    # Its state root commits to the post-state recomputed below.
    expected_block = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    expected_post_state = spec.process_block(spec.process_slots(state, Slot(1)), expected_block)
    expected_block = expected_block.model_copy(
        update={"state_root": hash_tree_root(expected_post_state)}
    )

    assert block == expected_block
    assert post_state == expected_post_state


def test_build_block_keeps_genesis_self_vote(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """A vote anchored entirely at genesis is carried into the body unchanged.

    - Source and target both sit at slot zero.
    - The state transition discards such a vote for justification.
    - The proposer still keeps it so it propagates and carries fork-choice weight.

    Fixture state:

        validators : 2
        proof      : validator 0 only
    """
    # Start from a sealed genesis with two validators.
    state, parent_root = _genesis_with_parent(2, key_manager)

    # The only checkpoint a fresh chain can reference is genesis at slot zero.
    # A vote here therefore has source and target both at slot zero.
    # That shape is a genesis self-vote.
    anchor = Checkpoint(root=parent_root, slot=Slot(0))
    data = AttestationData(slot=Slot(1), head=anchor, target=anchor, source=anchor)

    # Validator zero signs the vote, giving a single-validator proof.
    proof = make_aggregated_proof(key_manager, [ValidatorIndex(0)], data)

    # Build the slot-one block with this lone self-vote in the pool.
    block, post_state, attestations, proofs = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={data: {proof}},
    )

    # The lone proof is kept verbatim, so the body is one attestation over it.
    # Slot zero is already justified, so this self-vote cannot advance justification.
    # It survives selection only through the genesis self-vote exemption.
    expected_attestation = AggregatedAttestation(aggregation_bits=proof.participants, data=data)
    expected_block = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[expected_attestation])),
    )
    expected_post_state = spec.process_block(spec.process_slots(state, Slot(1)), expected_block)
    expected_block = expected_block.model_copy(
        update={"state_root": hash_tree_root(expected_post_state)}
    )

    assert block == expected_block
    assert post_state == expected_post_state
    assert proofs == [proof]

    # The kept proof still verifies against the signing validator's public key.
    proofs[0].verify(
        public_keys=[key_manager[ValidatorIndex(0)].attestation_keypair.public_key],
        message=hash_tree_root(data),
        slot=data.slot,
    )


def test_build_block_merges_split_proofs_into_one_attestation(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Two proofs for the same data collapse into one attestation over their union.

    - One subset arrives as a gossip-derived proof.
    - A second disjoint subset arrives as a separate proof.
    - The body must carry a single attestation, and its state root must hold.

    Fixture state:

        validators : 4
        proof one  : validator 0
        proof two  : validators 1 and 2
    """
    # Start from a sealed genesis with four validators.
    num_validators = 4
    state, parent_root = _genesis_with_parent(num_validators, key_manager)

    # Every vote on a fresh chain anchors at genesis at slot zero.
    anchor = Checkpoint(root=parent_root, slot=Slot(0))
    data = AttestationData(slot=Slot(1), head=anchor, target=anchor, source=anchor)

    # The same vote arrives as two proofs over disjoint validator sets.
    # One covers validator zero; the other covers validators one and two.
    proof_one = make_aggregated_proof(key_manager, [ValidatorIndex(0)], data)
    proof_two = make_aggregated_proof(key_manager, [ValidatorIndex(1), ValidatorIndex(2)], data)

    # Build with both proofs for the one vote in the pool.
    block, post_state, attestations, _ = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={data: {proof_one, proof_two}},
    )

    # Compaction folds the two proofs into one attestation.
    # The merged proof is freshly aggregated, so the body is checked structurally.
    assert len(block.body.attestations.data) == 1
    assert block.body.attestations.data[0] == attestations[0]
    assert set(attestations[0].aggregation_bits.to_validator_indices()) == {
        ValidatorIndex(0),
        ValidatorIndex(1),
        ValidatorIndex(2),
    }

    # Replaying the full transition independently must reproduce the build output.
    # The recorded state root must commit to that same post-state.
    result_state = spec.state_transition(state, block)
    assert post_state == result_state
    assert block.state_root == hash_tree_root(result_state)
    assert len(result_state.validators.data) == num_validators


def test_build_block_skips_vote_with_unknown_head(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """A vote whose head block the proposer has not seen is excluded."""
    # Start from a sealed genesis with two validators.
    state, parent_root = _genesis_with_parent(2, key_manager)
    anchor = Checkpoint(root=parent_root, slot=Slot(0))

    # A second checkpoint points at a block the proposer never received.
    unseen = Checkpoint(root=Bytes32(b"\xc8" * 32), slot=Slot(0))

    # One vote heads a seen block; the other heads the unseen block.
    known = AttestationData(slot=Slot(1), head=anchor, target=anchor, source=anchor)
    unknown = AttestationData(slot=Slot(1), head=unseen, target=anchor, source=anchor)
    known_proof = make_aggregated_proof(key_manager, [ValidatorIndex(0)], known)
    unknown_proof = make_aggregated_proof(key_manager, [ValidatorIndex(1)], unknown)

    # Offer both votes, but mark only the genesis block as seen.
    block, post_state, attestations, proofs = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={known: {known_proof}, unknown: {unknown_proof}},
    )

    # Only the vote that heads a seen block survives, kept as one verbatim proof.
    expected_attestation = AggregatedAttestation(
        aggregation_bits=known_proof.participants, data=known
    )
    expected_block = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[expected_attestation])),
    )
    expected_post_state = spec.process_block(spec.process_slots(state, Slot(1)), expected_block)
    expected_block = expected_block.model_copy(
        update={"state_root": hash_tree_root(expected_post_state)}
    )

    assert block == expected_block
    assert post_state == expected_post_state
    assert proofs == [known_proof]


def test_build_block_skips_vote_with_source_off_chain(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """A vote whose source root is not on this chain is excluded."""
    # Start from a sealed genesis with two validators.
    state, parent_root = _genesis_with_parent(2, key_manager)
    anchor = Checkpoint(root=parent_root, slot=Slot(0))

    # A second source points at a root that does not sit on this chain.
    foreign = Checkpoint(root=Bytes32(b"\x63" * 32), slot=Slot(0))

    # One vote sources from the genesis root; the other from the foreign root.
    on_chain = AttestationData(slot=Slot(1), head=anchor, target=anchor, source=anchor)
    off_chain = AttestationData(slot=Slot(1), head=anchor, target=anchor, source=foreign)
    on_chain_proof = make_aggregated_proof(key_manager, [ValidatorIndex(0)], on_chain)
    off_chain_proof = make_aggregated_proof(key_manager, [ValidatorIndex(1)], off_chain)

    # Offer both votes against the genesis chain view.
    block, post_state, attestations, proofs = spec.build_block(
        state,
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        known_block_roots={parent_root},
        aggregated_payloads={on_chain: {on_chain_proof}, off_chain: {off_chain_proof}},
    )

    # The chain-match filter drops the off-chain vote, keeping the on-chain one verbatim.
    expected_attestation = AggregatedAttestation(
        aggregation_bits=on_chain_proof.participants, data=on_chain
    )
    expected_block = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(1),
        parent_root=parent_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[expected_attestation])),
    )
    expected_post_state = spec.process_block(spec.process_slots(state, Slot(1)), expected_block)
    expected_block = expected_block.model_copy(
        update={"state_root": hash_tree_root(expected_post_state)}
    )

    assert block == expected_block
    assert post_state == expected_post_state
    assert proofs == [on_chain_proof]


def test_build_block_skips_vote_with_unjustified_source(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """A vote whose source slot is not yet justified is excluded.

    Fixture state:

        chain     : genesis through slot two, empty bodies
        justified : genesis only
        vote      : source at slot one, which is not justified
    """
    # Build a three-block chain with empty bodies, so only genesis is justified.
    state, _, block_one_root, block_two_root = _chain_through_slot_two(spec, key_manager, 4)
    voters = [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)]

    # The head sits at slot two, reached and seen on this chain.
    block_two = Checkpoint(root=block_two_root, slot=Slot(2))

    # The vote builds from slot one, which no body has justified yet.
    data = AttestationData(
        slot=Slot(3),
        head=block_two,
        target=block_two,
        source=Checkpoint(root=block_one_root, slot=Slot(1)),
    )
    proof = make_aggregated_proof(key_manager, voters, data)

    # Offer the vote while building at slot three.
    block, post_state, attestations, proofs = spec.build_block(
        state,
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=block_two_root,
        known_block_roots={block_one_root, block_two_root},
        aggregated_payloads={data: {proof}},
    )

    # A vote may only build from an already-justified source.
    # Slot one is not justified, so the vote is excluded and the body is empty.
    assert attestations == []
    assert proofs == []

    # The produced block is the empty-body block on top of slot two.
    expected_block = Block(
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=block_two_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    expected_post_state = spec.process_block(spec.process_slots(state, Slot(3)), expected_block)
    expected_block = expected_block.model_copy(
        update={"state_root": hash_tree_root(expected_post_state)}
    )

    assert block == expected_block
    assert post_state == expected_post_state


def test_build_block_skips_vote_for_already_justified_target(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """A vote whose target slot is already justified adds nothing and is excluded.

    Fixture state:

        chain     : genesis through slot two
        justified : slot one, fixed before building
        vote      : target at slot one, already justified
    """
    # Build a three-block chain whose slot-two body justifies slot one.
    state, genesis_root, block_one_root, block_two_root = _chain_through_slot_two(
        spec, key_manager, 4, justify_slot_one=True
    )
    voters = [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)]

    # The vote targets slot one, which is already justified.
    block_one = Checkpoint(root=block_one_root, slot=Slot(1))
    data = AttestationData(
        slot=Slot(3),
        head=block_one,
        target=block_one,
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    proof = make_aggregated_proof(key_manager, voters, data)

    # Offer the redundant vote while building at slot three.
    block, post_state, attestations, proofs = spec.build_block(
        state,
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=block_two_root,
        known_block_roots={genesis_root, block_one_root, block_two_root},
        aggregated_payloads={data: {proof}},
    )

    # An already-justified target gains nothing from more votes, so it is excluded.
    assert attestations == []
    assert proofs == []

    # The produced block is the empty-body block on top of slot two.
    # Its post-state keeps justification exactly where the chain already had it.
    expected_block = Block(
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=block_two_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    expected_post_state = spec.process_block(spec.process_slots(state, Slot(3)), expected_block)
    expected_block = expected_block.model_copy(
        update={"state_root": hash_tree_root(expected_post_state)}
    )

    assert block == expected_block
    assert post_state == expected_post_state
    assert post_state.latest_justified == block_one


def test_build_block_fixed_point_unlocks_chained_source(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Justifying one target unlocks a second vote whose source was that target.

    Fixture state:

        chain      : genesis through slot two, empty bodies
        validators : 4
        first vote : source at genesis, target at slot one
        second vote: source at slot one, target at slot two

    - The second vote builds from slot one, which is not justified at the start.
    - The first pass selects the first vote and justifies slot one.
    - The second pass then admits the second vote and justifies slot two.
    """
    # Build a three-block chain with empty bodies, so only genesis is justified.
    state, genesis_root, block_one_root, block_two_root = _chain_through_slot_two(
        spec, key_manager, 4
    )
    voters = [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)]
    genesis = Checkpoint(root=genesis_root, slot=Slot(0))
    block_one = Checkpoint(root=block_one_root, slot=Slot(1))
    block_two = Checkpoint(root=block_two_root, slot=Slot(2))

    # The first vote builds from genesis and targets slot one.
    first_vote = AttestationData(slot=Slot(3), head=block_one, target=block_one, source=genesis)

    # The second vote builds from slot one and targets slot two.
    # Slot one is not justified when selection starts, so this vote is locked at first.
    second_vote = AttestationData(slot=Slot(3), head=block_two, target=block_two, source=block_one)
    first_proof = make_aggregated_proof(key_manager, voters, first_vote)
    second_proof = make_aggregated_proof(key_manager, voters, second_vote)

    # Offer both votes at once while building at slot three.
    block, post_state, attestations, _ = spec.build_block(
        state,
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=block_two_root,
        known_block_roots={genesis_root, block_one_root, block_two_root},
        aggregated_payloads={first_vote: {first_proof}, second_vote: {second_proof}},
    )

    # The first pass justifies slot one, which unlocks the second vote.
    # The second pass admits it, so the body carries both votes in selection order.
    # Each vote is one verbatim proof, so reconstruct the expected body directly.
    expected_first = AggregatedAttestation(
        aggregation_bits=first_proof.participants, data=first_vote
    )
    expected_second = AggregatedAttestation(
        aggregation_bits=second_proof.participants, data=second_vote
    )
    expected_block = Block(
        slot=Slot(3),
        proposer_index=ValidatorIndex(3),
        parent_root=block_two_root,
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[expected_first, expected_second])),
    )
    expected_post_state = spec.process_block(spec.process_slots(state, Slot(3)), expected_block)
    expected_block = expected_block.model_copy(
        update={"state_root": hash_tree_root(expected_post_state)}
    )

    assert block == expected_block
    assert post_state == expected_post_state

    # Including both advances justification all the way to slot two.
    assert post_state.latest_justified == block_two
