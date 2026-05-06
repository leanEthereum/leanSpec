"""Test vectors for gossipsub RPC protobuf encoding."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

TOPIC_A = "/leanconsensus/0x12345678/block/ssz_snappy"
TOPIC_B = "/leanconsensus/0x12345678/aggregation/ssz_snappy"
MSG_ID_1 = "0x" + "aa" * 20
MSG_ID_2 = "0x" + "bb" * 20
MSG_ID_3 = "0x" + "cc" * 20
PEER_ID = "0x" + "dd" * 32


# --- SubOpts ---


def test_sub_opts_subscribe(networking_codec: NetworkingCodecTestFiller) -> None:
    """SubOpts encoding for a topic subscription."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [{"subscribe": True, "topicId": TOPIC_A}],
            "publish": [],
        },
    )


def test_sub_opts_unsubscribe(networking_codec: NetworkingCodecTestFiller) -> None:
    """SubOpts encoding for a topic unsubscription."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [{"subscribe": False, "topicId": TOPIC_A}],
            "publish": [],
        },
    )


def test_sub_opts_empty_topic(networking_codec: NetworkingCodecTestFiller) -> None:
    """SubOpts with an empty topic string."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [{"subscribe": True, "topicId": ""}],
            "publish": [],
        },
    )


# --- Message ---


def test_message_topic_only(networking_codec: NetworkingCodecTestFiller) -> None:
    """Published message with only the topic field set."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [{"topic": TOPIC_A}],
        },
    )


def test_message_all_fields(networking_codec: NetworkingCodecTestFiller) -> None:
    """Published message with every optional field populated."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [
                {
                    "fromPeer": "0x" + "01" * 32,
                    "data": "0xdeadbeef",
                    "seqno": "0x0000000000000001",
                    "topic": TOPIC_A,
                    "signature": "0x" + "ff" * 64,
                    "key": "0x" + "02" * 33,
                }
            ],
        },
    )


def test_message_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """Published message with no fields set. Encodes as zero bytes."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [{}],
        },
    )


# --- ControlGraft ---


def test_graft_single_topic(networking_codec: NetworkingCodecTestFiller) -> None:
    """GRAFT requesting mesh membership for one topic."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {"graft": [{"topicId": TOPIC_A}]},
        },
    )


def test_graft_empty_topic(networking_codec: NetworkingCodecTestFiller) -> None:
    """GRAFT with an empty topic string."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {"graft": [{"topicId": ""}]},
        },
    )


# --- ControlIHave ---


def test_ihave_single_id(networking_codec: NetworkingCodecTestFiller) -> None:
    """IHAVE advertising one cached message ID."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "ihave": [{"topicId": TOPIC_A, "messageIds": [MSG_ID_1]}],
            },
        },
    )


def test_ihave_multiple_ids(networking_codec: NetworkingCodecTestFiller) -> None:
    """IHAVE advertising three cached message IDs."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "ihave": [{"topicId": TOPIC_A, "messageIds": [MSG_ID_1, MSG_ID_2, MSG_ID_3]}],
            },
        },
    )


def test_ihave_empty_ids(networking_codec: NetworkingCodecTestFiller) -> None:
    """IHAVE with a topic but no message IDs."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "ihave": [{"topicId": TOPIC_A, "messageIds": []}],
            },
        },
    )


# --- ControlIWant ---


def test_iwant_single_id(networking_codec: NetworkingCodecTestFiller) -> None:
    """IWANT requesting one message by ID."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "iwant": [{"messageIds": [MSG_ID_1]}],
            },
        },
    )


def test_iwant_multiple_ids(networking_codec: NetworkingCodecTestFiller) -> None:
    """IWANT requesting two messages by ID."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "iwant": [{"messageIds": [MSG_ID_1, MSG_ID_2]}],
            },
        },
    )


# --- ControlPrune ---


def test_prune_topic_only(networking_codec: NetworkingCodecTestFiller) -> None:
    """PRUNE with topic but no peer exchange or backoff."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "prune": [{"topicId": TOPIC_A}],
            },
        },
    )


def test_prune_with_backoff(networking_codec: NetworkingCodecTestFiller) -> None:
    """PRUNE with a 60-second backoff duration."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "prune": [{"topicId": TOPIC_A, "backoff": 60}],
            },
        },
    )


def test_prune_with_peer_exchange(networking_codec: NetworkingCodecTestFiller) -> None:
    """PRUNE with peer exchange information and backoff."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "prune": [
                    {
                        "topicId": TOPIC_A,
                        "backoff": 120,
                        "peers": [
                            {"peerId": PEER_ID, "signedPeerRecord": "0xcafebabe"},
                        ],
                    }
                ],
            },
        },
    )


# --- ControlIDontWant ---


def test_idontwant_single_id(networking_codec: NetworkingCodecTestFiller) -> None:
    """IDONTWANT declining one message. Gossipsub v1.2 extension."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "idontwant": [{"messageIds": [MSG_ID_1]}],
            },
        },
    )


def test_idontwant_multiple_ids(networking_codec: NetworkingCodecTestFiller) -> None:
    """IDONTWANT declining two messages."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "idontwant": [{"messageIds": [MSG_ID_1, MSG_ID_2]}],
            },
        },
    )


# --- ControlMessage ---


def test_control_single_graft(networking_codec: NetworkingCodecTestFiller) -> None:
    """Control message containing only a single GRAFT."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {"graft": [{"topicId": TOPIC_A}]},
        },
    )


def test_control_all_types(networking_codec: NetworkingCodecTestFiller) -> None:
    """Control message with one of each control type."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "ihave": [{"topicId": TOPIC_A, "messageIds": [MSG_ID_1]}],
                "iwant": [{"messageIds": [MSG_ID_2]}],
                "graft": [{"topicId": TOPIC_A}],
                "prune": [{"topicId": TOPIC_B, "backoff": 60}],
                "idontwant": [{"messageIds": [MSG_ID_3]}],
            },
        },
    )


def test_control_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """Empty control message. All repeated fields empty, encodes to zero bytes."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {},
        },
    )


# --- Full RPC ---


def test_rpc_subscriptions_only(networking_codec: NetworkingCodecTestFiller) -> None:
    """RPC with only subscription changes."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [
                {"subscribe": True, "topicId": TOPIC_A},
                {"subscribe": True, "topicId": TOPIC_B},
            ],
            "publish": [],
        },
    )


def test_rpc_publish_only(networking_codec: NetworkingCodecTestFiller) -> None:
    """RPC with only published messages."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [
                {"topic": TOPIC_A, "data": "0xdeadbeef"},
                {"topic": TOPIC_B, "data": "0xcafebabe"},
            ],
        },
    )


def test_rpc_control_only(networking_codec: NetworkingCodecTestFiller) -> None:
    """RPC with only control messages."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
            "control": {
                "graft": [{"topicId": TOPIC_A}],
                "prune": [{"topicId": TOPIC_B, "backoff": 60}],
            },
        },
    )


def test_rpc_full(networking_codec: NetworkingCodecTestFiller) -> None:
    """RPC with subscriptions, published messages, and control all present."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [{"subscribe": True, "topicId": TOPIC_A}],
            "publish": [{"topic": TOPIC_A, "data": "0xdeadbeef"}],
            "control": {
                "graft": [{"topicId": TOPIC_B}],
                "idontwant": [{"messageIds": [MSG_ID_1]}],
            },
        },
    )


def test_rpc_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """Empty RPC. No subscriptions, messages, or control."""
    networking_codec(
        codec_name="gossipsub_rpc",
        input={
            "subscriptions": [],
            "publish": [],
        },
    )
