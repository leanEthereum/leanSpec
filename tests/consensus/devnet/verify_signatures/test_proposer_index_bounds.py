"""Signature verification: proposer-index bounds rejection vector."""

import pytest
from consensus_testing import (
    BlockSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.forks.lstar.containers.slot import Slot

pytestmark = pytest.mark.valid_until("Devnet")


def test_proposer_index_out_of_range_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """A signed block whose proposer_index exceeds the validator registry is rejected.

    Scenario
    --------
    - Anchor state has 4 validators.
    - Block at slot 1 is built normally by the round-robin-selected
      in-range proposer.
    - The tamper hook then rewrites proposer_index to 99.

    Expected Behavior
    -----------------
    Signature verification fails with AssertionError: "Proposer index out of range"

    Why This Matters
    ----------------
    The builder's round-robin proposer selection never produces an
    out-of-range index, so the block.py bounds check only fires for
    blocks received from a malicious peer. This vector pins the
    rejection clients must raise in that case.

    Distinct from the round-robin check "Incorrect block proposer",
    which catches wrong-but-in-range proposers during state transition.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
        ),
        tamper={"operation": "set_proposer_index", "value": 99},
        expect_exception=AssertionError,
    )
