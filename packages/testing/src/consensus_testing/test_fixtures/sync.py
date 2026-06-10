"""Sync layer test fixture format."""

from typing import ClassVar, Literal

from consensus_testing.genesis import build_anchor, generate_pre_state
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.base import StrictBaseModel
from lean_spec.node.sync.checkpoint_sync import verify_checkpoint_state
from lean_spec.spec.forks import Slot
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Uint64


class VerifyCheckpointOutput(StrictBaseModel):
    """Verdict and reference bytes for one checkpoint verification."""

    valid: bool
    """Result of checkpoint-state verification on the built state."""

    state_bytes: str
    """SSZ-encoded state hex, so clients can run their own verification."""

    validator_count: int
    """Echoed for diagnostic clarity."""

    anchor_slot: int
    """Echoed so consumers see exactly which state was verified."""


class VerifyCheckpoint(StrictBaseModel):
    """
    Build a state for a validator count and anchor slot, then report the verdict.

    Zero (default) anchor slot yields a genesis state.
    Positive values walk an empty-block chain through the slot so
    historical block hashes reflect a real advanced anchor.
    """

    kind: Literal["verify_checkpoint"] = "verify_checkpoint"
    """Discriminator field for serialization."""

    num_validators: int
    """Number of validators in the state."""

    anchor_slot: int = 0
    """Slot to advance the chain through before verifying."""

    def run(self) -> VerifyCheckpointOutput:
        """Build the requested state and report the verification verdict."""
        fork = LstarSpec()
        if self.anchor_slot == 0:
            state = generate_pre_state(
                fork=fork, genesis_time=Uint64(0), num_validators=self.num_validators
            )
        else:
            state, _ = build_anchor(
                fork=fork,
                num_validators=self.num_validators,
                anchor_slot=Slot(self.anchor_slot),
                genesis_time=Uint64(0),
            )
        return VerifyCheckpointOutput(
            valid=verify_checkpoint_state(state),
            state_bytes="0x" + state.encode_bytes().hex(),
            validator_count=self.num_validators,
            anchor_slot=self.anchor_slot,
        )


SyncOperation = VerifyCheckpoint
"""Sync operations under test; grows into a discriminated union with new helpers."""


class SyncFixture(BaseConsensusFixture):
    """
    Emitted vector for sync-layer conformance.

    JSON output: operation, output.
    """

    operation: SyncOperation
    """Sync operation under test, with its typed inputs."""

    output: VerifyCheckpointOutput
    """Computed verdict and reference bytes."""


class SyncTest(BaseTestSpec):
    """
    Spec for sync-layer conformance.

    Each vector pins the expected verdict on a given input so clients
    can align their sync-layer decisions bit-for-bit.
    """

    format_name: ClassVar[str] = "sync_test"
    description: ClassVar[str] = "Tests sync-layer helpers clients must reproduce"

    operation: SyncOperation
    """Sync operation to run, with its typed inputs."""

    def generate(self) -> SyncFixture:
        """Run the operation and emit the vector."""
        return SyncFixture(operation=self.operation, output=self.operation.run())
