"""3SF-mini justifiability test fixture.

Generates JSON test vectors for the Slot.is_justifiable_after function
that implements the core 3SF-mini justification rule. A slot is
justifiable after a finalized slot if the distance (delta) satisfies:

1. delta <= 5 (immediate window)
2. delta is a perfect square (4, 9, 16, 25, ...)
3. delta is a pronic number n*(n+1) (6, 12, 20, 30, ...)

Every client must implement this identically for consensus.
"""

from typing import Any, ClassVar

from lean_spec.forks.lstar.containers.slot import Slot

from .base import BaseConsensusFixture


class JustifiabilityTest(BaseConsensusFixture):
    """Fixture for 3SF-mini justifiability conformance.

    Tests Slot.is_justifiable_after(finalized_slot) which determines
    whether a slot can be a justification target.

    JSON output: slot, finalizedSlot, output.
    """

    format_name: ClassVar[str] = "justifiability"
    description: ClassVar[str] = "Tests 3SF-mini slot justifiability rules"

    slot: int
    """Candidate slot to test."""

    finalized_slot: int
    """Last finalized slot."""

    output: dict[str, Any] = {}
    """Computed output. Filled by make_fixture."""

    def make_fixture(self) -> "JustifiabilityTest":
        """Compute justifiability and delta classification."""
        s = Slot(self.slot)
        f = Slot(self.finalized_slot)
        delta = self.slot - self.finalized_slot
        justifiable = s.is_justifiable_after(f)

        output = {
            "delta": delta,
            "isJustifiable": justifiable,
        }
        return self.model_copy(update={"output": output})
