"""
Forkchoice store for tracking chain state and votes.

The Store tracks data required for the LMD GHOST forkchoice algorithm.
"""

import copy
from typing import Dict

from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    SECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import (
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    Config,
    SignedBlock,
    SignedValidatorAttestation,
    State,
    ValidatorAttestation,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import (
    Bytes32,
    Bytes4000,
    Uint64,
    ValidatorIndex,
    is_proposer,
)
from lean_spec.types.container import Container

from .helpers import get_fork_choice_head, get_latest_justified


class Store(Container):
    """
    Forkchoice store tracking chain state and validator votes.

    Maintains all data needed for LMD GHOST fork choice algorithm including
    blocks, states, checkpoints, and validator voting records.
    """

    time: Uint64
    """Current time in intervals since genesis."""

    config: Config
    """Chain configuration parameters."""

    head: Bytes32
    """Root of the current canonical chain head block."""

    safe_target: Bytes32
    """Root of the current safe target for attestation voting."""

    latest_justified: Checkpoint
    """Highest slot justified checkpoint known to the store."""

    latest_finalized: Checkpoint
    """Highest slot finalized checkpoint known to the store."""

    blocks: Dict[Bytes32, Block] = {}
    """Mapping from block root to Block objects."""

    states: Dict[Bytes32, "State"] = {}
    """Mapping from state root to State objects."""

    latest_known_votes: Dict[ValidatorIndex, SignedValidatorAttestation] = {}
    """Latest votes by validator that have been processed."""

    latest_new_votes: Dict[ValidatorIndex, SignedValidatorAttestation] = {}
    """Latest votes by validator that are pending processing."""

    @classmethod
    def get_forkchoice_store(
        cls,
        state: State,
        anchor_block: Block,
    ) -> "Store":
        """
        Initialize forkchoice store from an anchor state and block.

        The anchor serves as a trusted starting point for the forkchoice. This
        class method acts as a factory for creating a new Store instance.

        Args:
            state: The trusted state object to initialize the store from.
            anchor_block: The trusted block corresponding to the state.

        Returns:
            A new, initialized Store object.

        Raises:
            AssertionError: If the anchor block's state root does not match the
                            hash of the anchor state.
        """
        # Validate that the anchor block corresponds to the anchor state
        assert anchor_block.state_root == hash_tree_root(state), (
            "Anchor block state root must match anchor state hash"
        )

        anchor_root = hash_tree_root(anchor_block)
        anchor_slot = anchor_block.slot

        return cls(
            time=Uint64(anchor_slot * INTERVALS_PER_SLOT),
            config=state.config,
            head=anchor_root,
            safe_target=anchor_root,
            latest_justified=state.latest_justified,
            latest_finalized=state.latest_finalized,
            blocks={anchor_root: copy.copy(anchor_block)},
            states={anchor_root: copy.copy(state)},
        )

    def validate_attestation(
        self,
        signed_attestation: SignedValidatorAttestation,
    ) -> None:
        """Validate incoming attestation before processing.

        Performs basic validation checks on attestation structure and timing.

        Args:
            signed_attestation: Attestation to validate.

        Raises:
            AssertionError: If attestation fails validation.
        """
        attestation = signed_attestation.message
        data = attestation.data

        assert data.source.root in self.blocks, "Unknown source block"
        assert data.target.root in self.blocks, "Unknown target block"

        source_block = self.blocks[data.source.root]
        target_block = self.blocks[data.target.root]

        assert source_block.slot <= target_block.slot, (
            "Source slot must not exceed target"
        )
        assert data.source.slot <= data.target.slot, (
            "Source checkpoint slot must not exceed target"
        )

        assert source_block.slot == data.source.slot, (
            "Source checkpoint slot mismatch"
        )
        assert target_block.slot == data.target.slot, (
            "Target checkpoint slot mismatch"
        )

        current_slot = Slot(self.time // SECONDS_PER_INTERVAL)
        assert data.slot <= current_slot + Slot(1), (
            "Attestation too far in future"
        )

    def process_attestation(
        self,
        signed_attestation: SignedValidatorAttestation,
        is_from_block: bool = False,
    ) -> None:
        """Process attestation from block propagation or gossip."""
        self.validate_attestation(signed_attestation)

        attestation = signed_attestation.message
        validator_id = ValidatorIndex(attestation.validator_id)
        attestation_slot = attestation.data.slot

        if is_from_block:
            # update latest known votes if this is latest
            latest_known = self.latest_known_votes.get(validator_id)
            if (
                latest_known is None
                or latest_known.message.data.slot < attestation_slot
            ):
                self.latest_known_votes[validator_id] = signed_attestation

            # clear from new votes if this is latest
            latest_new = self.latest_new_votes.get(validator_id)
            if (
                latest_new is not None
                and latest_new.message.data.slot <= attestation_slot
            ):
                del self.latest_new_votes[validator_id]
            return

        # forkchoice should be correctly ticked to current time before
        # importing gossiped attestations
        time_slots = Slot(self.time // SECONDS_PER_INTERVAL)
        assert attestation_slot <= time_slots, "Attestation from future slot"

        # update latest new votes if this is the latest
        latest_new = self.latest_new_votes.get(validator_id)
        if (
            latest_new is None
            or latest_new.message.data.slot < attestation_slot
        ):
            self.latest_new_votes[validator_id] = signed_attestation

    def _validate_block_signatures(
        self,
        block: Block,
        signatures: list[Bytes4000],
    ) -> bool:
        """Temporary stub for aggregated signature validation."""
        # TODO: plug real aggregated signature validation once available.
        return True

    def process_block(self, block: Block | SignedBlock) -> None:
        """Process a new block or signed block and update votes and head."""
        signatures: list[Bytes4000] = []
        if isinstance(block, SignedBlock):
            signed_block = block
            block = signed_block.message
            signatures = list(signed_block.signature)

        block_hash = hash_tree_root(block)
        if block_hash in self.blocks:
            # If the block is already known, ignore it
            return

        parent_state = self.states.get(block.parent_root)
        # at this point parent state should be available so node should
        # sync parent chain if not available before adding block to forkchoice
        assert parent_state is not None, (
            "Parent state not found; sync parent chain first"
        )

        valid_signatures = self._validate_block_signatures(block, signatures)

        # Get post state from STF (State Transition Function)
        state = copy.deepcopy(parent_state).state_transition(
            block,
            valid_signatures,
        )

        self.blocks[block_hash] = block
        self.states[block_hash] = state

        # add block votes to the onchain known last votes
        for index, attestation in enumerate(block.body.attestations):
            signature = (
                signatures[index]
                if index < len(signatures)
                else Bytes4000.zero()
            )
            signed_attestation = SignedValidatorAttestation(
                message=attestation,
                # eventually one would be able to associate and consume an
                # aggregated signature for individual vote validity with that
                # information encoded in the signature
                signature=signature,
            )
            self.process_attestation(signed_attestation, is_from_block=True)

        self.update_head()

        proposer_signature_index = len(block.body.attestations)
        proposer_signature = (
            signatures[proposer_signature_index]
            if proposer_signature_index < len(signatures)
            else Bytes4000.zero()
        )
        # the proposer vote for the current slot and block as head is to be
        # treated as the vote is independently casted in the second interval
        proposer_attestation = ValidatorAttestation(
            validator_id=block.proposer_index,
            data=AttestationData(
                slot=block.slot,
                head=Checkpoint(root=block_hash, slot=block.slot),
                target=block.body.proposer_attestation.target,
                source=block.body.proposer_attestation.source,
            ),
        )
        signed_proposer_attestation = SignedValidatorAttestation(
            message=proposer_attestation,
            signature=proposer_signature,
        )
        # note that we pass False here to make sure this gets added to the new
        # votes so that this doesn't influence this node's validators upcoming
        # votes
        self.process_attestation(
            signed_proposer_attestation,
            is_from_block=False,
        )

    def update_head(self) -> None:
        """Refresh head and finalized checkpoints based on latest votes."""
        latest_justified = get_latest_justified(self.states)
        if latest_justified is not None:
            object.__setattr__(self, "latest_justified", latest_justified)

        new_head = get_fork_choice_head(
            self.blocks,
            self.latest_justified.root,
            self.latest_known_votes,
        )
        object.__setattr__(self, "head", new_head)

        finalized_state = self.states.get(new_head)
        if finalized_state is not None:
            object.__setattr__(
                self,
                "latest_finalized",
                finalized_state.latest_finalized,
            )

    def advance_time(self, time: Uint64, has_proposal: bool) -> None:
        """Advance store time to `time`, ticking intervals as needed."""
        tick_target = (
            time - self.config.genesis_time
        ) // SECONDS_PER_INTERVAL

        while self.time < tick_target:
            should_signal = (
                has_proposal
                and (self.time + Uint64(1)) == tick_target
            )
            self.tick_interval(should_signal)

    def tick_interval(self, has_proposal: bool) -> None:
        """Advance one interval and run interval-specific actions."""
        object.__setattr__(self, "time", self.time + Uint64(1))
        current_interval = self.time % INTERVALS_PER_SLOT

        if current_interval == Uint64(0):
            if has_proposal:
                self.accept_new_votes()
            return

        if current_interval == Uint64(1):
            return

        if current_interval == Uint64(2):
            self.update_safe_target()
            return

        self.accept_new_votes()

    def accept_new_votes(self) -> None:
        """Move pending votes into known votes and refresh the head."""
        for validator_id, attestation in self.latest_new_votes.items():
            self.latest_known_votes[validator_id] = attestation

        self.latest_new_votes.clear()
        self.update_head()

    def update_safe_target(self) -> None:
        """Recompute safe target using latest pending votes."""
        min_target_score = -(-self.config.num_validators * 2 // 3)

        safe_target = get_fork_choice_head(
            self.blocks,
            self.latest_justified.root,
            self.latest_new_votes,
            min_score=min_target_score,
        )
        object.__setattr__(self, "safe_target", safe_target)

    def get_proposal_head(self, slot: Slot) -> Bytes32:
        """Return the head a proposer should build on for `slot`."""
        slot_time = self.config.genesis_time + slot * SECONDS_PER_SLOT
        self.advance_time(slot_time, True)
        self.accept_new_votes()
        return self.head

    def get_vote_target(self) -> Checkpoint:
        """Compute the checkpoint a validator should target."""
        target_block_root = self.head

        for _ in range(3):
            if (
                self.blocks[target_block_root].slot
                > self.blocks[self.safe_target].slot
            ):
                target_block_root = self.blocks[target_block_root].parent_root

        while not self.blocks[target_block_root].slot.is_justifiable_after(
            self.latest_finalized.slot
        ):
            target_block_root = self.blocks[target_block_root].parent_root

        target_block = self.blocks[target_block_root]
        return Checkpoint(
            root=hash_tree_root(target_block),
            slot=target_block.slot,
        )

    def produce_block(
        self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> Block:
        """Produce a block for `slot` if `validator_index` is proposer."""
        if not is_proposer(validator_index, slot, self.config.num_validators):
            msg = (
                f"Validator {validator_index} is not the proposer "
                f"for slot {slot}"
            )
            raise AssertionError(msg)

        head_root = self.head
        head_state = self.states[head_root]

        attestations: list[ValidatorAttestation] = []

        while True:
            candidate_block = Block(
                slot=slot,
                proposer_index=validator_index,
                parent_root=head_root,
                state_root=Bytes32.zero(),
                body=BlockBody(
                    attestations=Attestations(data=list(attestations)),
                ),
            )

            advanced_state = head_state.process_slots(slot)
            post_state = advanced_state.process_block(candidate_block)

            new_attestations: list[ValidatorAttestation] = []
            for signed in self.latest_known_votes.values():
                data = signed.message.data
                if data.target.root not in self.blocks:
                    continue

                attestation_data = AttestationData(
                    slot=data.slot,
                    head=data.head,
                    target=data.target,
                    source=post_state.latest_justified,
                )
                candidate_attestation = ValidatorAttestation(
                    validator_id=signed.message.validator_id,
                    data=attestation_data,
                )

                if candidate_attestation not in attestations:
                    new_attestations.append(candidate_attestation)

            if not new_attestations:
                break

            attestations.extend(new_attestations)

        final_state = head_state.process_slots(slot)
        final_block = Block(
            slot=slot,
            proposer_index=validator_index,
            parent_root=head_root,
            state_root=Bytes32.zero(),
            body=BlockBody(
                attestations=Attestations(data=list(attestations)),
            ),
        )

        final_post_state = final_state.process_block(final_block)
        finalized_block = final_block.model_copy(
            update={
                "state_root": hash_tree_root(final_post_state),
            }
        )

        block_hash = hash_tree_root(finalized_block)
        self.blocks[block_hash] = finalized_block
        self.states[block_hash] = final_post_state

        return finalized_block

    def produce_attestation_vote(
        self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> ValidatorAttestation:
        """Produce the attestation payload a validator signs for `slot`."""
        head_root = self.head
        head_checkpoint = Checkpoint(
            root=head_root,
            slot=self.blocks[head_root].slot,
        )

        target_checkpoint = self.get_vote_target()

        attestation_data = AttestationData(
            slot=slot,
            head=head_checkpoint,
            target=target_checkpoint,
            source=self.latest_justified,
        )

        return ValidatorAttestation(
            validator_id=validator_index,
            data=attestation_data,
        )
