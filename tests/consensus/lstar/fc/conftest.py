"""Shared fixtures for fork-choice filler tests."""

from collections.abc import Iterator

import pytest
from consensus_testing.keys import XmssKeyManager


@pytest.fixture(autouse=True)
def _reset_xmss_signing_state() -> Iterator[None]:
    """Reset cached XMSS signing state around every fork-choice filler.

    XMSS keys are stateful and advance past used slots on every sign.
    Without a reset, a filler that signs at a high slot poisons the
    shared cache for any later filler that needs to sign at a lower
    slot — leading to "Verification failed" errors that only appear
    when several tests share a worker.
    """
    XmssKeyManager.reset_signing_state()
    yield
    XmssKeyManager.reset_signing_state()
