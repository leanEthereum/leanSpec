"""Consensus layer genesis state, block, and anchor construction for tests."""

from ssz import Uint64, hash_tree_root

from consensus_testing.keys import XmssKeyManager
from lean_spec.spec.forks import Checkpoint, Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    Block,
    BlockBody,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    State,
    Validator,
    Validators,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz_types import Bytes52


def build_genesis_state(
    num_validators: int = 4,
    *,
    genesis_time: Uint64 = Uint64(0),
    keyed: bool = True,
    fork: LstarSpec = LstarSpec(),
) -> State:
    """Build a genesis pre-state for consensus tests, with real or zeroed validator keys."""
    if keyed:
        key_manager = XmssKeyManager.shared()
        if num_validators > len(key_manager):
            raise ValueError(
                f"Not enough keys: need {num_validators} validators "
                f"but the key manager has only {len(key_manager)} keys"
            )
        validators = [
            Validator(
                attestation_public_key=Bytes52(
                    key_manager.get_public_keys(ValidatorIndex(validator_index))[0].encode_bytes()
                ),
                proposal_public_key=Bytes52(
                    key_manager.get_public_keys(ValidatorIndex(validator_index))[1].encode_bytes()
                ),
                index=ValidatorIndex(validator_index),
            )
            for validator_index in range(num_validators)
        ]
    else:
        validators = [
            Validator(
                attestation_public_key=Bytes52(b"\x00" * 52),
                proposal_public_key=Bytes52(b"\x00" * 52),
                index=ValidatorIndex(validator_position),
            )
            for validator_position in range(num_validators)
        ]

    return fork.generate_genesis(
        genesis_time=genesis_time,
        validators=Validators(data=validators),
    )


def reconstruct_block_from_header(state: State) -> Block:
    """Rebuild the block matching a state's latest header, with an empty body by convention."""
    return Block(
        slot=state.latest_block_header.slot,
        proposer_index=state.latest_block_header.proposer_index,
        parent_root=state.latest_block_header.parent_root,
        state_root=hash_tree_root(state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


def build_anchor(
    num_validators: int,
    anchor_slot: Slot,
    *,
    fork: LstarSpec = LstarSpec(),
    genesis_time: Uint64 = Uint64(0),
    keyed: bool = True,
    synced: bool = False,
) -> tuple[State, Block]:
    """Build an anchor by advancing the genesis state through a slot, genesis pair at slot 0."""
    state = build_genesis_state(num_validators, genesis_time=genesis_time, keyed=keyed, fork=fork)

    current_block = reconstruct_block_from_header(state)
    parent_root = hash_tree_root(current_block)

    num_validators_u64 = Uint64(num_validators)

    # Advance one empty block per slot, up to and including the anchor.
    # The spec's own builder gives the state real mid-chain history.
    for next_slot in range(1, int(anchor_slot) + 1):
        slot = Slot(next_slot)
        proposer_index = ValidatorIndex.proposer_for_slot(slot, num_validators_u64)
        current_block, state, _, _ = fork.build_block(
            state,
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots={parent_root},
        )
        parent_root = hash_tree_root(current_block)

    # A plain mid-chain anchor keeps the genesis checkpoints from the advance.
    if not synced:
        return state, current_block

    # Rebase the state as a freshly checkpoint-synced node would see it.
    # Such a node trusts the anchor as finalized, so both checkpoints move there.
    anchor_root = hash_tree_root(current_block)
    anchor_checkpoint = Checkpoint(root=anchor_root, slot=anchor_slot)

    # The justified-slots window starts at the slot after the finalized boundary.
    # Moving that boundary to the anchor drops the leading bits; nothing past it exists.
    rebase_distance = int(anchor_slot - state.latest_finalized.slot)
    rebased_justified_slots = JustifiedSlots(data=state.justified_slots.data[rebase_distance:])

    # No votes carry past the new finalized boundary, so pending tallies reset.
    state = state.model_copy(
        update={
            "latest_finalized": anchor_checkpoint,
            "latest_justified": anchor_checkpoint,
            "justified_slots": rebased_justified_slots,
            "justifications_roots": JustificationRoots(data=[]),
            "justifications_validators": JustificationValidators(data=[]),
        }
    )

    # The block must point at the rebased state, so recompute its state root.
    current_block = current_block.model_copy(update={"state_root": hash_tree_root(state)})

    return state, current_block


def build_genesis_store(
    num_validators: int = 4,
    *,
    genesis_time: int = 0,
    validator_index: ValidatorIndex | None = ValidatorIndex(0),
    observer: bool = False,
    keyed: bool = True,
    time: Interval | None = None,
) -> Store:
    """Build a genesis fork-choice store, owned by a validator unless observer is set."""
    # Slot 0 makes the anchor builder produce the genesis state and block pair.
    state, genesis_block = build_anchor(
        num_validators, Slot(0), genesis_time=Uint64(genesis_time), keyed=keyed
    )
    store = LstarSpec().create_store(
        state,
        genesis_block,
        validator_index=None if observer else validator_index,
    )
    return store if time is None else store.model_copy(update={"time": time})
