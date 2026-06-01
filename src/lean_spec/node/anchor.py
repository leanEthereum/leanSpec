"""
Boot anchor for the lean consensus node.

The forkchoice store starts at a trusted block plus its matching state.
Two sources land on the same return shape:

- Genesis: synthesise the store from the genesis validator set.
- Checkpoint: fetch a finalized state from a peer and build the store from it.

Once the store exists the protocol cannot tell the two sources apart.
"""

from __future__ import annotations

from typing import cast

from lean_spec.base import StrictBaseModel
from lean_spec.node.genesis import GenesisConfig
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.sync.checkpoint_sync import (
    CheckpointSyncError,
    fetch_finalized_state,
    verify_checkpoint_state,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import (
    AggregatedAttestations,
    Block,
    BlockBody,
    Checkpoint,
    ForkProtocol,
    Slot,
    Store,
    ValidatorIndex,
    Validators,
)
from lean_spec.spec.ssz import Bytes32


class Anchor(StrictBaseModel):
    """Starting state passed to the boot sequence regardless of the anchor source."""

    validators: Validators
    """Validator set the store sees at slot zero."""

    store: Store | None
    """Pre-built forkchoice store.

    A value of None asks the node to synthesise one from the validator set."""

    initial_status: Status
    """Status broadcast to peers before the listener starts serving."""

    @classmethod
    def from_genesis(cls, genesis: GenesisConfig) -> Anchor:
        """
        Build an anchor from a fresh genesis configuration.

        The store is left as None so the node can synthesise it from validators.
        The status carries zero roots because the genesis block has no id yet.

        Args:
            genesis: Genesis YAML loaded from disk.

        Returns:
            An anchor that asks the node to synthesise its own store.
        """
        zero_checkpoint = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
        return cls(
            validators=genesis.to_validators(),
            store=None,
            initial_status=Status(finalized=zero_checkpoint, head=zero_checkpoint),
        )

    @classmethod
    async def from_checkpoint(
        cls,
        url: str,
        genesis: GenesisConfig,
        fork: ForkProtocol,
        validator_index: ValidatorIndex | None,
    ) -> Anchor:
        """
        Build an anchor by fetching a finalized state from a peer.

        The fetched state replaces the genesis validator set.
        Deposits and exits since genesis are already baked into it.

        Args:
            url: HTTP endpoint of the node serving the checkpoint state.
            genesis: Local genesis used as a chain-identity guard via genesis time.
            fork: Fork specification driving state and store construction.
            validator_index: Local validator index used as a forkchoice tiebreaker hint.

        Raises:
            CheckpointSyncError: For every failure mode covering transport,
                structural verification, and genesis-time mismatch.
        """
        state = await fetch_finalized_state(url, fork.state_class)

        # Catches a corrupt download before it contaminates the forkchoice store.
        if not verify_checkpoint_state(state):
            raise CheckpointSyncError("checkpoint state failed structural verification")

        # Genesis time is the only chain-identity check available at this layer.
        # A mismatch means the checkpoint belongs to a different network.
        if state.config.genesis_time != genesis.genesis_time:
            raise CheckpointSyncError(
                f"genesis time mismatch: checkpoint={state.config.genesis_time}, "
                f"local={genesis.genesis_time}"
            )

        # Reconstruct the anchor block from the header embedded in the state.
        # A header stored before its post-state root carries a zero placeholder;
        # in that case we recompute the root from the state itself.
        # Fork choice only needs identity and lineage, so the body is left empty.
        header = state.latest_block_header
        state_root = (
            header.state_root if header.state_root != Bytes32.zero() else hash_tree_root(state)
        )
        anchor_block = Block(
            slot=header.slot,
            proposer_index=header.proposer_index,
            parent_root=header.parent_root,
            state_root=state_root,
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )

        # The protocol return type is structural, but only one concrete store ships.
        store = cast(Store, fork.create_store(state, anchor_block, validator_index))
        head_slot = store.blocks[store.head].slot

        return cls(
            validators=state.validators,
            store=store,
            initial_status=Status(
                finalized=store.latest_finalized,
                head=Checkpoint(root=store.head, slot=head_slot),
            ),
        )
