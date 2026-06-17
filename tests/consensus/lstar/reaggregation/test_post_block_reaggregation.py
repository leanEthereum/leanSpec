"""Re-aggregation vectors: split an attestation out of a block proof, fold with the local pool."""

import pytest

from consensus_testing import ReaggregationTestFiller
from lean_spec.spec.forks import ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_split_only_when_data_unseen_locally(
    reaggregation_test: ReaggregationTestFiller,
) -> None:
    """
    An attestation unseen locally is recovered from the block proof and used as-is.

    Given
    -----
    - a block proof carrying an attestation signed by V0, V1, V2.
    - no local partial for that attestation.

    When
    ----
    - the block proof is split by the attestation message.

    Then
    ----
    - the recovered proof covers V0, V1, V2.
    - no local partial merges in.
    - the recovered proof verifies.
    """
    reaggregation_test(
        block_attesters=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
        local_attesters=[],
    )


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


def test_split_then_merge_with_disjoint_local_partial(
    reaggregation_test: ReaggregationTestFiller,
) -> None:
    """
    A recovered proof merges with a non-overlapping local partial into their union.

    Given
    -----
    - a block proof carrying an attestation signed by V0, V1.
    - a local partial for the same attestation signed by V2, V3.
    - the block and the local partial share no validators.

    When
    ----
    - the block proof is split by the attestation message.
    - the recovered proof merges with the local partial.

    Then
    ----
    - the recovered proof covers V0, V1.
    - the recovered proof verifies.
    - the local partial covers V2, V3.
    - the re-aggregated proof covers V0, V1, V2, V3.
    - the re-aggregated proof verifies.
    """
    reaggregation_test(
        block_attesters=[ValidatorIndex(0), ValidatorIndex(1)],
        local_attesters=[ValidatorIndex(2), ValidatorIndex(3)],
    )


def test_split_single_validator_block(
    reaggregation_test: ReaggregationTestFiller,
) -> None:
    """
    A single-validator block attestation is recovered from the block proof and used as-is.

    Given
    -----
    - a block proof carrying an attestation signed by V0.
    - no local partial for that attestation.

    When
    ----
    - the block proof is split by the attestation message.

    Then
    ----
    - the recovered proof covers V0.
    - no local partial merges in.
    - the recovered proof verifies.
    """
    reaggregation_test(
        block_attesters=[ValidatorIndex(0)],
        local_attesters=[],
    )


def test_split_then_merge_when_local_covers_a_superset(
    reaggregation_test: ReaggregationTestFiller,
) -> None:
    """
    A recovered proof merges with a local partial that already covers it, yielding the local set.

    Given
    -----
    - a block proof carrying an attestation signed by V0, V1.
    - a local partial for the same attestation signed by V0, V1, V2.
    - the local partial already covers every block attester.

    When
    ----
    - the block proof is split by the attestation message.
    - the recovered proof merges with the local partial.

    Then
    ----
    - the recovered proof covers V0, V1.
    - the recovered proof verifies.
    - the local partial covers V0, V1, V2.
    - the re-aggregated proof covers V0, V1, V2.
    - the re-aggregated proof verifies.
    """
    reaggregation_test(
        block_attesters=[ValidatorIndex(0), ValidatorIndex(1)],
        local_attesters=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
    )
