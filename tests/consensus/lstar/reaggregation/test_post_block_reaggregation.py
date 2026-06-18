"""Re-aggregation vector: split an attestation out of a block proof, fold with the local pool."""

import pytest

from consensus_testing import ReaggregationTestFiller
from lean_spec.spec.forks import ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_split_then_merge_with_overlapping_local_partial(
    reaggregation_test: ReaggregationTestFiller,
) -> None:
    """
    A recovered proof merges with an overlapping local partial into their union.

    Given
    -----
    - a block proof carrying an attestation signed by V0, V1, V2.
    - a local partial for the same attestation signed by V1, V2, V3.
    - the block and the local partial overlap on V1, V2.

    When
    ----
    - the block proof is split by the attestation message.
    - the recovered proof merges with the local partial.

    Then
    ----
    - the recovered proof covers V0, V1, V2.
    - the recovered proof verifies.
    - the local partial covers V1, V2, V3.
    - the re-aggregated proof covers V0, V1, V2, V3.
    - the re-aggregated proof verifies.
    """
    reaggregation_test(
        block_attesters=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
        local_attesters=[ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
    )
