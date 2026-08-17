"""
Protection against consuming one validator key twice within a slot.

The signature scheme is a stateful one-time signature indexed by slot.
Signing two different messages under the same key and slot opens two positions
in the same hash chains, which is enough to forge a third signature.
`sign` states that obligation but does not enforce it, so the enforcement lives
here: a record of the highest slot each key has signed, checked before signing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from lean_spec.node.storage import Database
from lean_spec.spec.forks import Slot, ValidatorIndex

logger = logging.getLogger(__name__)

type SigningRole = Literal["attestation", "proposal"]
"""Which of a validator's two keys a signature consumes.

The roles hold separate keys, so a proposal and an attestation in one slot
consume one slot each rather than colliding.
"""


class SigningProtectionError(Exception):
    """Raised when a signature would consume a slot one of the keys already spent."""


@dataclass(slots=True)
class SigningProtection:
    """
    Enforces at most one signature per validator key per slot.

    Records live in the node database when one is configured, so they survive a
    restart, a clock that steps backwards, and a restore from backup. Without a
    database they are process-local, which leaves a crash inside a slot
    unprotected — `is_durable` reports which of the two is in force.

    Two instances must never share a key. Concurrent nodes holding the same key
    keep separate records and can each sign the same slot.
    """

    database: Database | None = None
    """Store for signing records, or None to keep them in this process only."""

    _slots_in_memory: dict[tuple[ValidatorIndex, SigningRole], Slot] = field(default_factory=dict)
    """Records used while no database is configured."""

    @property
    def is_durable(self) -> bool:
        """Whether the records survive a restart of this process."""
        return self.database is not None

    def reserve(self, validator_index: ValidatorIndex, role: SigningRole, slot: Slot) -> None:
        """
        Claim a slot for one of a validator's keys, to be called before it signs.

        Raises `SigningProtectionError` when that key already signed this slot or
        a later one. The claim is stored before the caller signs, so an
        interruption in between forfeits the duty rather than the key.
        """
        last_signed = self.last_signed_slot(validator_index, role)
        if last_signed is not None and slot <= last_signed:
            raise SigningProtectionError(
                f"validator {validator_index} {role} key last signed slot {last_signed}; "
                f"signing slot {slot} would reuse a one-time key"
            )

        if self.database is None:
            self._slots_in_memory[(validator_index, role)] = slot
            return

        # Commit on its own so the record outlives the signature it guards.
        with self.database.batch_write():
            self.database.put_last_signed_slot(validator_index, role, slot)

    def last_signed_slot(self, validator_index: ValidatorIndex, role: SigningRole) -> Slot | None:
        """Return the highest slot this key has signed, or None if it never signed."""
        if self.database is None:
            return self._slots_in_memory.get((validator_index, role))
        return self.database.get_last_signed_slot(validator_index, role)
