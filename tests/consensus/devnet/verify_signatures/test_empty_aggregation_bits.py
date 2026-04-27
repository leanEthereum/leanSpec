"""Signature verification: empty aggregation_bits rejection vector."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    VerifySignaturesTestFiller,
    generate_pre_state,
)

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_empty_aggregation_bits_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """A signed block whose attestation references zero participants is rejected.

    Scenario
    --------
    - Anchor state has 3 validators.
    - Block at slot 1 carries one aggregated attestation.
    - The tamper hook replaces the first attestation's aggregation_bits
      with a bitfield where no bit is set.

    Expected Behavior
    -----------------
    Signature verification fails with AssertionError:
    "Aggregated attestation must reference at least one validator"

    Why This Matters
    ----------------
    An aggregated attestation with no participants carries no signed
    message. The block builder never produces one because its
    aggregation pass starts from a non-empty validator set, but a
    malicious peer could. Clients must raise before attempting to look
    up public keys for a zero-participant attestation.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        tamper={"operation": "clear_first_attestation_bits"},
        expect_exception=AssertionError,
    )
