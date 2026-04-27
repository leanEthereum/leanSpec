"""Gossipsub topic network-name validation vectors.

Validates that a parsed topic carries the network name a client
expects. A mismatch is the only mechanism preventing cross-fork mesh
admission; pinning both branches stops clients from silently admitting
wrong-fork messages into their subscriptions.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Devnet")


def test_gossip_topic_network_name_matches(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Block topic whose network name matches the expected value validates cleanly.

    Pins the accept branch of validate_fork: a topic built with a network
    name equal to the expected one must pass the check.
    """
    networking_codec(
        codec_name="gossip_topic",
        input={
            "kind": "block",
            "forkDigest": "0x12345678",
            "expectedForkDigest": "0x12345678",
        },
    )


def test_gossip_topic_network_name_mismatch(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Block topic with a network name different from the expected one is rejected.

    Pins the reject branch of validate_fork: a topic built for one fork
    must not pass when validated against a different network name. The
    output reports forkValid=false so clients align on the rejection
    verdict.
    """
    networking_codec(
        codec_name="gossip_topic",
        input={
            "kind": "block",
            "forkDigest": "0x12345678",
            "expectedForkDigest": "0xdeadbeef",
        },
    )


def test_gossip_topic_network_name_match_on_attestation_subnet(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Attestation-subnet topic carries the subnet id and still validates its network name.

    Mixes a non-default kind and subnet id with the network-name check
    to confirm the validator reads network_name independent of other
    topic components.
    """
    networking_codec(
        codec_name="gossip_topic",
        input={
            "kind": "attestation",
            "forkDigest": "0xabcdef01",
            "subnetId": 7,
            "expectedForkDigest": "0xabcdef01",
        },
    )
