"""Consensus layer pre-state generation."""

from lean_spec.subspecs.containers.block import AggregatedAttestations, Block, BlockBody
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator, ValidatorIndex
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes52, Uint64

from .keys import XmssKeyManager

_DEFAULT_GENESIS_TIME = Uint64(0)


def generate_pre_state(
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
    num_validators: int = 4,
) -> State:
    """Generate a default pre-state for consensus tests.

    Args:
        genesis_time: The genesis timestamp.
        num_validators: Number of validators to include.

    Returns:
        A properly initialized consensus state.
    """
    key_manager = XmssKeyManager.shared()

    if num_validators > len(key_manager):
        raise ValueError(
            f"Not enough keys: need {num_validators} validators "
            f"but the key manager has only {len(key_manager)} keys"
        )

    validators = []
    for i in range(num_validators):
        idx = ValidatorIndex(i)
        attestation_pubkey, proposal_pubkey = key_manager.get_public_keys(idx)
        validators.append(
            Validator(
                attestation_pubkey=Bytes52(attestation_pubkey.encode_bytes()),
                proposal_pubkey=Bytes52(proposal_pubkey.encode_bytes()),
                index=idx,
            )
        )

    return State.generate_genesis(genesis_time=genesis_time, validators=Validators(data=validators))


def build_anchor(
    num_validators: int,
    anchor_slot: Slot,
    genesis_time: Uint64 = _DEFAULT_GENESIS_TIME,
) -> tuple[State, Block]:
    """Build a consistent non-genesis anchor by advancing the genesis state.

    Simulates the mid-chain view that a checkpoint-synced node would have:
    a real state reached via the normal state transition from genesis,
    plus the real block at that slot.

    The resulting (state, block) pair is internally consistent. That means:

    - Block state_root equals hash_tree_root(state).
    - State historical_block_hashes lists the real roots for slots 0..anchor_slot-1.
    - State latest_block_header matches the anchor block header (without state_root).

    Args:
        num_validators: Size of the validator set in the anchor state.
        anchor_slot: Slot at which the anchor block lives. Must be > 0.
        genesis_time: Genesis timestamp for the underlying pre-state.

    Returns:
        A tuple of (anchor_state, anchor_block) ready to seed a fork choice
        store at a non-genesis starting point.

    Raises:
        ValueError: If anchor_slot is not strictly positive.
    """
    if anchor_slot <= Slot(0):
        raise ValueError(
            f"Anchor slot must be strictly positive, got {anchor_slot}. "
            "For a genesis anchor use generate_pre_state instead."
        )

    state = generate_pre_state(genesis_time=genesis_time, num_validators=num_validators)

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
        proposer_index = ValidatorIndex(int(slot) % int(num_validators_u64))
        current_block, state, _, _ = state.build_block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots={parent_root},
        )
        parent_root = hash_tree_root(current_block)

    return state, current_block
