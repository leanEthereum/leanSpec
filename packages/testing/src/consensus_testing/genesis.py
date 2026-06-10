"""Consensus layer pre-state generation."""

from consensus_testing.keys import XmssKeyManager
from lean_spec.spec.crypto.merkleization import hash_tree_root
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
from lean_spec.spec.ssz import Bytes32, Bytes52, Uint64

_DEFAULT_GENESIS_TIME = Uint64(0)

_DEFAULT_VALIDATOR_INDEX = ValidatorIndex(0)
"""Owning validator for a genesis store, unless overridden."""


def _build_validators(num_validators: int) -> Validators:
    """Build a validator registry with real XMSS keys from the shared key manager."""
    key_manager = XmssKeyManager.shared()

    if num_validators > len(key_manager):
        raise ValueError(
            f"Not enough keys: need {num_validators} validators "
            f"but the key manager has only {len(key_manager)} keys"
        )

    validators = []
    for validator_position in range(num_validators):
        validator_index = ValidatorIndex(validator_position)
        attestation_public_key, proposal_public_key = key_manager.get_public_keys(validator_index)
        validators.append(
            Validator(
                attestation_public_key=Bytes52(attestation_public_key.encode_bytes()),
                proposal_public_key=Bytes52(proposal_public_key.encode_bytes()),
                index=validator_index,
            )
        )

    return Validators(data=validators)


def generate_pre_state(
    fork: LstarSpec | None = None,
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
    num_validators: int = 4,
) -> State:
    """
    Generate a default pre-state for consensus tests.

    Args:
        fork: Fork dispatching genesis construction. Defaults to a fresh
            LstarSpec instance.
        genesis_time: The genesis timestamp.
        num_validators: Number of validators to include.

    Returns:
        A properly initialized consensus state.
    """
    fork = fork or LstarSpec()
    validators = _build_validators(num_validators)
    return fork.generate_genesis(genesis_time=genesis_time, validators=validators)


def build_anchor(
    num_validators: int,
    anchor_slot: Slot,
    fork: LstarSpec | None = None,
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
    synced: bool = False,
) -> tuple[State, Block]:
    """
    Build a non-genesis anchor by advancing the genesis state to a slot.

    By default the anchor keeps the genesis checkpoints, modelling a mid-chain
    state that has not finalized anything yet.

    With synced set, it models a checkpoint-synced node instead: both checkpoints
    pin to the anchor slot and the justification window rebases onto that boundary.

    Either way the returned pair is internally consistent.
    The block state root equals the hash of the state.

    Args:
        num_validators: Size of the validator set in the anchor state.
        anchor_slot: Slot at which the anchor block lives. Must be > 0.
        fork: Fork dispatching genesis construction.
        genesis_time: Genesis timestamp for the underlying pre-state.
        synced: Pin both checkpoints to the anchor slot, for checkpoint-sync vectors.

    Returns:
        A tuple of (anchor_state, anchor_block).

    Raises:
        ValueError: If anchor_slot is not strictly positive.
    """
    if anchor_slot <= Slot(0):
        raise ValueError(
            f"Anchor slot must be strictly positive, got {anchor_slot}. "
            "For a genesis anchor use generate_pre_state instead."
        )

    fork = fork or LstarSpec()
    state = generate_pre_state(fork=fork, genesis_time=genesis_time, num_validators=num_validators)

    # Reconstruct the genesis block from the state's latest header.
    # The genesis block is fully determined by the genesis state.
    genesis_block = Block(
        slot=state.latest_block_header.slot,
        proposer_index=state.latest_block_header.proposer_index,
        parent_root=state.latest_block_header.parent_root,
        state_root=hash_tree_root(state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    current_block = genesis_block
    parent_root = hash_tree_root(current_block)

    num_validators_u64 = Uint64(num_validators)

    # Advance through empty blocks, one per slot, up to and including anchor_slot.
    # Each block is built by the spec's own builder so the resulting state
    # carries the real chain history (historical block hashes, justified slots,
    # justification tracking) that a real mid-chain state would have.
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

    # Rebase the state onto the anchor as a freshly checkpoint-synced node would see it.
    #
    # The empty-block advance leaves both checkpoints at the genesis boundary (slot 0).
    # A node that syncs from this anchor trusts it as finalized at the anchor slot.
    # So both checkpoints move to the anchor block at the anchor slot.
    anchor_root = hash_tree_root(current_block)
    anchor_checkpoint = Checkpoint(root=anchor_root, slot=anchor_slot)

    # The justified-slots window is stored relative to the finalized boundary.
    #
    # Its first bit is the slot just after finalization.
    # Moving the boundary forward by the anchor slot drops that many leading bits.
    # No slot beyond the anchor is materialized, so the rebased window is empty.
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


def make_validators(count: int) -> Validators:
    """Build a validator registry of the given size with zeroed public keys."""
    return Validators(
        data=[
            Validator(
                attestation_public_key=Bytes52(b"\x00" * 52),
                proposal_public_key=Bytes52(b"\x00" * 52),
                index=ValidatorIndex(validator_position),
            )
            for validator_position in range(count)
        ]
    )


def make_genesis_state(num_validators: int = 3, genesis_time: int = 0) -> State:
    """Build a genesis state with zeroed validator keys."""
    return LstarSpec().generate_genesis(
        genesis_time=Uint64(genesis_time),
        validators=make_validators(num_validators),
    )


def make_genesis_block(state: State) -> Block:
    """Build the genesis block matching a genesis state."""
    return Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


def make_genesis_store(
    num_validators: int = 4,
    *,
    genesis_time: int = 0,
    validator_index: ValidatorIndex | None = _DEFAULT_VALIDATOR_INDEX,
    observer: bool = False,
    keyed: bool = True,
    time: Interval | None = None,
) -> Store:
    """
    Build a genesis fork-choice store.

    Uses real XMSS keys when keyed, else zeroed keys for any validator count.
    Set observer for a store with no owning validator.
    """
    state = (
        generate_pre_state(genesis_time=Uint64(genesis_time), num_validators=num_validators)
        if keyed
        else make_genesis_state(num_validators=num_validators, genesis_time=genesis_time)
    )
    store = LstarSpec().create_store(
        state,
        make_genesis_block(state),
        validator_index=None if observer else validator_index,
    )
    return store if time is None else store.model_copy(update={"time": time})
