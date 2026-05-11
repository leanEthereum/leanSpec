"""Optional structural capabilities a fork may advertise.

Capabilities sit alongside the required Spec*Type protocols in
forks/protocol.py.

- Required protocols every fork must satisfy via its *_class bindings.
- A capability is optional: a fork advertises it by binding a matching
  attribute, and the test filler keys off presence to deselect tests
  that need it.

Today there is one capability: SigScheme. Future capabilities live in
this module too.
"""

from typing import ClassVar, Protocol, runtime_checkable

from lean_spec.subspecs.xmss.interface import GeneralizedXmssScheme


@runtime_checkable
class SigScheme(Protocol):
    """Fork advertising a generalized XMSS signature scheme.

    The runtime check only verifies the attribute is present.
    The attribute's type contract is enforced statically.
    """

    sig_scheme: ClassVar[GeneralizedXmssScheme]
