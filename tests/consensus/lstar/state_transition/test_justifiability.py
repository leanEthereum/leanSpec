"""State Transition: 3SF-mini slot justifiability rules."""

import pytest

from consensus_testing import JustifiabilityTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_delta_0_finalized_slot_itself(
    justifiability_test: JustifiabilityTestFiller,
) -> None:
    """
    The finalized slot itself is justifiable at delta 0.

    Given
    -----
    - the finalized slot is 10.
    - the candidate slot is 10.
    - the delta is 0.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=10, finalized_slot=10)


def test_delta_1(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 1 is justifiable as the first slot of the immediate window.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 1.
    - the delta is 1, inside the immediate window.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=1, finalized_slot=0)


def test_delta_2(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 2 is justifiable inside the immediate window.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 2.
    - the delta is 2, inside the immediate window.
    - the delta is also pronic (1*2).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=2, finalized_slot=0)


def test_delta_3(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 3 is justifiable inside the immediate window.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 3.
    - the delta is 3, inside the immediate window.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=3, finalized_slot=0)


def test_delta_4(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 4 is justifiable inside the immediate window.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 4.
    - the delta is 4, inside the immediate window.
    - the delta is also a perfect square (2*2).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=4, finalized_slot=0)


def test_delta_5(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 5 is justifiable as the last slot of the immediate window.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 5.
    - the delta is 5, the last slot of the immediate window.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=5, finalized_slot=0)


def test_delta_6_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 6 is the first justifiable slot outside the immediate window.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 6.
    - the delta is 6, just past the immediate window.
    - the delta is pronic (2*3).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=6, finalized_slot=0)


def test_delta_7_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 7 is the first non-justifiable slot outside the immediate window.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 7.
    - the delta is 7, just past the immediate window.
    - the delta is neither square nor pronic.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=7, finalized_slot=0)


def test_delta_8_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 8 is not justifiable.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 8.
    - the delta is 8.
    - the delta is neither square nor pronic.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=8, finalized_slot=0)


def test_delta_9_square(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 9 is justifiable as a perfect square.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 9.
    - the delta is 9, a perfect square (3*3).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=9, finalized_slot=0)


def test_delta_16_square(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 16 is justifiable as a perfect square.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 16.
    - the delta is 16, a perfect square (4*4).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=16, finalized_slot=0)


def test_delta_25_square(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 25 is justifiable as a perfect square.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 25.
    - the delta is 25, a perfect square (5*5).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=25, finalized_slot=0)


def test_delta_36_square(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 36 is justifiable as a perfect square.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 36.
    - the delta is 36, a perfect square (6*6).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=36, finalized_slot=0)


def test_delta_49_square(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 49 is justifiable as a perfect square.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 49.
    - the delta is 49, a perfect square (7*7).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=49, finalized_slot=0)


def test_delta_64_square(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 64 is justifiable as a perfect square.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 64.
    - the delta is 64, a perfect square (8*8).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=64, finalized_slot=0)


def test_delta_100_square(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 100 is justifiable as a perfect square.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 100.
    - the delta is 100, a perfect square (10*10).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=100, finalized_slot=0)


def test_delta_12_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 12 is justifiable as a pronic number.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 12.
    - the delta is 12, pronic (3*4).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=12, finalized_slot=0)


def test_delta_20_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 20 is justifiable as a pronic number.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 20.
    - the delta is 20, pronic (4*5).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=20, finalized_slot=0)


def test_delta_30_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 30 is justifiable as a pronic number.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 30.
    - the delta is 30, pronic (5*6).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=30, finalized_slot=0)


def test_delta_42_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 42 is justifiable as a pronic number.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 42.
    - the delta is 42, pronic (6*7).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=42, finalized_slot=0)


def test_delta_56_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 56 is justifiable as a pronic number.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 56.
    - the delta is 56, pronic (7*8).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=56, finalized_slot=0)


def test_delta_72_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 72 is justifiable as a pronic number.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 72.
    - the delta is 72, pronic (8*9).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=72, finalized_slot=0)


def test_delta_110_pronic(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 110 is justifiable as a pronic number.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 110.
    - the delta is 110, pronic (10*11).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=110, finalized_slot=0)


def test_delta_10_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 10 is not justifiable.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 10.
    - the delta is 10, between square 9 and pronic 12.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=10, finalized_slot=0)


def test_delta_11_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 11 is not justifiable.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 11.
    - the delta is 11, between square 9 and pronic 12.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=11, finalized_slot=0)


def test_delta_13_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 13 is not justifiable.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 13.
    - the delta is 13, between pronic 12 and square 16.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=13, finalized_slot=0)


def test_delta_15_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 15 is not justifiable.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 15.
    - the delta is 15, between pronic 12 and square 16.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=15, finalized_slot=0)


def test_delta_17_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 17 is not justifiable.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 17.
    - the delta is 17, between square 16 and pronic 20.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=17, finalized_slot=0)


def test_delta_50_not_justifiable(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 50 is not justifiable.

    Given
    -----
    - the finalized slot is 0.
    - the candidate slot is 50.
    - the delta is 50, between square 49 and pronic 56.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=50, finalized_slot=0)


def test_nonzero_finalized_delta_1(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 1 is justifiable when measured from a non-zero finalized slot.

    Given
    -----
    - the finalized slot is 100.
    - the candidate slot is 101.
    - the delta is 1, inside the immediate window.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=101, finalized_slot=100)


def test_nonzero_finalized_delta_9(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 9 is justifiable when measured from a non-zero finalized slot.

    Given
    -----
    - the finalized slot is 100.
    - the candidate slot is 109.
    - the delta is 9, a perfect square.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=109, finalized_slot=100)


def test_nonzero_finalized_delta_7(justifiability_test: JustifiabilityTestFiller) -> None:
    """
    Delta 7 is not justifiable when measured from a non-zero finalized slot.

    Given
    -----
    - the finalized slot is 100.
    - the candidate slot is 107.
    - the delta is 7, neither square nor pronic.

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is not justifiable.
    """
    justifiability_test(slot=107, finalized_slot=100)


def test_nonzero_finalized_delta_12(
    justifiability_test: JustifiabilityTestFiller,
) -> None:
    """
    Delta 12 is justifiable when measured from a non-zero finalized slot.

    Given
    -----
    - the finalized slot is 500.
    - the candidate slot is 512.
    - the delta is 12, pronic (3*4).

    When
    ----
    - the candidate is checked for justifiability.

    Then
    ----
    - the candidate is justifiable.
    """
    justifiability_test(slot=512, finalized_slot=500)
