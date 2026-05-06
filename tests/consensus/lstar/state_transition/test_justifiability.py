"""Test vectors for 3SF-mini slot justifiability rules.

A slot is justifiable after a finalized slot if the distance (delta) is:
1. In the immediate window (delta <= 5)
2. A perfect square (1, 4, 9, 16, 25, 36, ...)
3. A pronic number n*(n+1) (2, 6, 12, 20, 30, 42, ...)

These vectors let client teams verify their square/pronic detection
independently of the full state transition machinery.
"""

import pytest
from consensus_testing import JustifiabilityTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


# --- Immediate window (delta 0-5, all justifiable) ---


def test_delta_0_finalized_slot_itself(
    justifiability: JustifiabilityTestFiller,
) -> None:
    """Delta 0: the finalized slot itself is always justifiable."""
    justifiability(slot=10, finalized_slot=10)


def test_delta_1(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 1: immediate window."""
    justifiability(slot=1, finalized_slot=0)


def test_delta_2(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 2: immediate window (also a pronic: 1*2)."""
    justifiability(slot=2, finalized_slot=0)


def test_delta_3(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 3: immediate window."""
    justifiability(slot=3, finalized_slot=0)


def test_delta_4(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 4: immediate window (also a perfect square: 2^2)."""
    justifiability(slot=4, finalized_slot=0)


def test_delta_5(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 5: last slot in the immediate window."""
    justifiability(slot=5, finalized_slot=0)


# --- First gap: delta 6 is pronic (2*3), delta 7-8 are not justifiable ---


def test_delta_6_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 6: pronic number (2*3). First justifiable slot outside the immediate window."""
    justifiability(slot=6, finalized_slot=0)


def test_delta_7_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 7: not square, not pronic, outside window. First non-justifiable delta."""
    justifiability(slot=7, finalized_slot=0)


def test_delta_8_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 8: not square, not pronic."""
    justifiability(slot=8, finalized_slot=0)


# --- Perfect squares ---


def test_delta_9_square(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 9: perfect square (3^2)."""
    justifiability(slot=9, finalized_slot=0)


def test_delta_16_square(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 16: perfect square (4^2)."""
    justifiability(slot=16, finalized_slot=0)


def test_delta_25_square(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 25: perfect square (5^2)."""
    justifiability(slot=25, finalized_slot=0)


def test_delta_36_square(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 36: perfect square (6^2)."""
    justifiability(slot=36, finalized_slot=0)


def test_delta_49_square(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 49: perfect square (7^2)."""
    justifiability(slot=49, finalized_slot=0)


def test_delta_64_square(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 64: perfect square (8^2)."""
    justifiability(slot=64, finalized_slot=0)


def test_delta_100_square(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 100: perfect square (10^2)."""
    justifiability(slot=100, finalized_slot=0)


# --- Pronic numbers n*(n+1) ---


def test_delta_12_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 12: pronic number (3*4)."""
    justifiability(slot=12, finalized_slot=0)


def test_delta_20_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 20: pronic number (4*5)."""
    justifiability(slot=20, finalized_slot=0)


def test_delta_30_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 30: pronic number (5*6)."""
    justifiability(slot=30, finalized_slot=0)


def test_delta_42_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 42: pronic number (6*7)."""
    justifiability(slot=42, finalized_slot=0)


def test_delta_56_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 56: pronic number (7*8)."""
    justifiability(slot=56, finalized_slot=0)


def test_delta_72_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 72: pronic number (8*9)."""
    justifiability(slot=72, finalized_slot=0)


def test_delta_110_pronic(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 110: pronic number (10*11)."""
    justifiability(slot=110, finalized_slot=0)


# --- Non-justifiable deltas (between squares/pronics) ---


def test_delta_10_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 10: between square 9 and pronic 12."""
    justifiability(slot=10, finalized_slot=0)


def test_delta_11_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 11: between square 9 and pronic 12."""
    justifiability(slot=11, finalized_slot=0)


def test_delta_13_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 13: between pronic 12 and square 16."""
    justifiability(slot=13, finalized_slot=0)


def test_delta_15_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 15: between pronic 12 and square 16."""
    justifiability(slot=15, finalized_slot=0)


def test_delta_17_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 17: between square 16 and pronic 20."""
    justifiability(slot=17, finalized_slot=0)


def test_delta_50_not_justifiable(justifiability: JustifiabilityTestFiller) -> None:
    """Delta 50: between square 49 and pronic 56."""
    justifiability(slot=50, finalized_slot=0)


# --- Non-zero finalized slot ---


def test_nonzero_finalized_delta_1(justifiability: JustifiabilityTestFiller) -> None:
    """Finalized at slot 100, candidate at 101. Delta 1: immediate window."""
    justifiability(slot=101, finalized_slot=100)


def test_nonzero_finalized_delta_9(justifiability: JustifiabilityTestFiller) -> None:
    """Finalized at slot 100, candidate at 109. Delta 9: perfect square."""
    justifiability(slot=109, finalized_slot=100)


def test_nonzero_finalized_delta_7(justifiability: JustifiabilityTestFiller) -> None:
    """Finalized at slot 100, candidate at 107. Delta 7: not justifiable."""
    justifiability(slot=107, finalized_slot=100)


def test_nonzero_finalized_delta_12(
    justifiability: JustifiabilityTestFiller,
) -> None:
    """Finalized at slot 500, candidate at 512. Delta 12: pronic (3*4)."""
    justifiability(slot=512, finalized_slot=500)
