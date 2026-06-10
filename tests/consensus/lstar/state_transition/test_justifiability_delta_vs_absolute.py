"""State Transition: justifiability reads the delta from finalization, not the absolute slot."""

import pytest

from consensus_testing import JustifiabilityTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_absolute_non_justifiable_but_delta_justifiable(
    justifiability_test: JustifiabilityTestFiller,
) -> None:
    """
    A slot non-justifiable from genesis is justifiable on its delta from finalization.

    Given
    -----
    - the finalized slot is 3.
    - the candidate slot is 7.
    - measured from genesis the distance is 7, neither square nor pronic.
    - measured from finalization the delta is 4, a perfect square.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable, proving the rule reads the delta.
    """
    justifiability_test(slot=7, finalized_slot=3)


def test_absolute_justifiable_but_delta_non_justifiable(
    justifiability_test: JustifiabilityTestFiller,
) -> None:
    """
    A slot justifiable from genesis is non-justifiable on its delta from finalization.

    Given
    -----
    - the finalized slot is 2.
    - the candidate slot is 9.
    - measured from genesis the distance is 9, a perfect square.
    - measured from finalization the delta is 7, neither square nor pronic.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable, proving the rule reads the delta.
    """
    justifiability_test(slot=9, finalized_slot=2)
