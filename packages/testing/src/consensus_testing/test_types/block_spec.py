"""Lightweight block specification for test definitions."""

from typing import Union

from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.block import BlockBody
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, CamelModel, ValidatorIndex

from .signed_attestation_spec import SignedAttestationSpec


class BlockSpec(CamelModel):
    """
    Block specification for test definitions.

    Contains the same fields as Block, but all optional except slot.
    The framework fills in any missing fields automatically.

    This matches the pattern from execution-specs where Block(...) is a spec
    that the framework builds into a full block.

    Usage:
    - Simple: BlockSpec(slot=Slot(1)) - framework computes everything
    - Custom: BlockSpec(slot=Slot(1), proposer_index=ValidatorIndex(5)) - override specific fields
    - Invalid: BlockSpec(slot=Slot(1), state_root=Bytes32.zero()) - test invalid blocks
    """

    slot: Slot
    """The slot for this block (required)."""

    proposer_index: ValidatorIndex | None = None
    """
    The proposer index for this block.

    If None, framework selects using round-robin based on slot and num_validators.
    """

    parent_root: Bytes32 | None = None
    """
    The root of the parent block.

    If None, framework computes from state.latest_block_header.
    """

    state_root: Bytes32 | None = None
    """
    The state root after applying this block.

    If None, framework computes via state_transition dry-run.
    """

    body: BlockBody | None = None
    """
    The block body containing attestations.

    If None, framework creates body from the attestations field.
    If both body and attestations are None, framework creates body with empty attestations.
    Note: If body is provided, attestations field is ignored.
    """

    attestations: list[Union[SignedAttestation, SignedAttestationSpec]] | None = None
    """
    List of signed attestations to include in this block's body.

    These attestations will be included in block.body.attestations.
    Can be either SignedAttestation (direct) or SignedAttestationSpec.

    If None, framework uses default behavior (empty body).
    If body is provided, this field is ignored.
    """

    label: str | None = None
    """
    Optional label to tag this block for later reference.

    Allows creating forks by building blocks on labeled ancestors:
    ```python
    BlockSpec(slot=Slot(1), label="fork_a")  # Tag this block
    BlockSpec(slot=Slot(2), parent_label="fork_a")  # Build on it
    ```

    Labels must be unique within a test.
    """

    parent_label: str | None = None
    """
    Optional label referencing a previously created block as parent.

    Enables explicit fork creation:
    ```python
    BlockSpec(slot=Slot(1), label="common")
    BlockSpec(slot=Slot(2), parent_label="common", label="fork_a")
    BlockSpec(slot=Slot(2), parent_label="common", label="fork_b")
    ```

    If None, parent is determined by the current canonical head.
    If specified, parent_root is computed from the labeled block.
    """
