"""3SF-mini justifiability test fixture."""

from typing import ClassVar

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.base import StrictBaseModel
from lean_spec.spec.forks import Slot


class JustifiabilityOutput(StrictBaseModel):
    """Computed delta and justifiability verdict for one candidate slot."""

    delta: int
    """Slots between the candidate slot and the last finalized slot."""

    is_justifiable: bool
    """Whether the candidate slot may serve as a justification target."""


class JustifiabilityFixture(BaseConsensusFixture):
    """
    Emitted vector for 3SF-mini justifiability conformance.

    JSON output: slot, finalizedSlot, output.
    """

    slot: int
    """Candidate slot under test."""

    finalized_slot: int
    """Last finalized slot."""

    output: JustifiabilityOutput
    """Computed delta and justifiability verdict."""


class JustifiabilityTest(BaseTestSpec):
    """
    Spec for 3SF-mini justifiability conformance.

    Tests Slot.is_justifiable_after(finalized_slot) which determines
    whether a slot can be a justification target.
    """

    format_name: ClassVar[str] = "justifiability_test"
    description: ClassVar[str] = "Tests 3SF-mini slot justifiability rules"

    slot: int
    """Candidate slot to test."""

    finalized_slot: int
    """Last finalized slot."""

    def generate(self) -> JustifiabilityFixture:
        """Compute justifiability and delta classification."""
        candidate_slot = Slot(self.slot)
        finalized_slot = Slot(self.finalized_slot)
        delta = self.slot - self.finalized_slot
        justifiable = candidate_slot.is_justifiable_after(finalized_slot)

        return JustifiabilityFixture(
            slot=self.slot,
            finalized_slot=self.finalized_slot,
            output=JustifiabilityOutput(delta=delta, is_justifiable=justifiable),
        )
