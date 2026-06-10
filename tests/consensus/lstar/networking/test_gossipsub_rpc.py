"""Test vectors for gossipsub RPC protobuf encoding."""

import pytest

from consensus_testing import (
    GossipsubRpcRoundtrip,
    NetworkingCodecTestFiller,
    RpcControlSpec,
    RpcGraftSpec,
    RpcIDontWantSpec,
    RpcIHaveSpec,
    RpcIWantSpec,
    RpcMessageSpec,
    RpcPruneSpec,
    RpcSubscriptionSpec,
)

pytestmark = pytest.mark.valid_until("Lstar")

TOPIC_A = "/leanconsensus/0x12345678/block/ssz_snappy"
TOPIC_B = "/leanconsensus/0x12345678/aggregation/ssz_snappy"
MESSAGE_ID_1 = "0x" + "aa" * 20
MESSAGE_ID_2 = "0x" + "bb" * 20
MESSAGE_ID_3 = "0x" + "cc" * 20


def test_sub_opts_subscribe(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A subscribe entry round-trips through the RPC encoding.

    Given
    -----
    - an RPC with one subscription entry that subscribes to a topic.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_A)], publish=[]
        ),
    )


def test_sub_opts_unsubscribe(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An unsubscribe entry round-trips through the RPC encoding.

    Given
    -----
    - an RPC with one subscription entry that unsubscribes from a topic.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=False, topic_id=TOPIC_A)], publish=[]
        ),
    )


def test_sub_opts_empty_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A subscribe entry with an empty topic round-trips.

    Given
    -----
    - an RPC with one subscription entry whose topic is an empty string.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=True, topic_id="")], publish=[]
        ),
    )


def test_message_topic_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A published message with only a topic round-trips.

    Given
    -----
    - an RPC with one published message that sets only the topic field.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[RpcMessageSpec(topic=TOPIC_A)]),
    )


def test_message_all_fields(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A published message with every field round-trips.

    Given
    -----
    - an RPC with one published message.
    - the from_peer, data, seqno, topic, signature, and key fields are all set.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[
                RpcMessageSpec(
                    from_peer="0x" + "01" * 32,
                    data="0xdeadbeef",
                    seqno="0x0000000000000001",
                    topic=TOPIC_A,
                    signature="0x" + "ff" * 64,
                    key="0x" + "02" * 33,
                )
            ],
        ),
    )


def test_message_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A published message with no fields encodes to zero bytes and round-trips.

    Given
    -----
    - an RPC with one published message that sets no fields.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the message encodes to zero bytes.
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[RpcMessageSpec()]),
    )


def test_graft_single_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A GRAFT for one topic round-trips through the RPC encoding.

    Given
    -----
    - an RPC whose control message holds a GRAFT for one topic.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(graft=[RpcGraftSpec(topic_id=TOPIC_A)]),
        ),
    )


def test_graft_empty_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A GRAFT with an empty topic round-trips.

    Given
    -----
    - an RPC whose control message holds a GRAFT with an empty topic.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[], publish=[], control=RpcControlSpec(graft=[RpcGraftSpec(topic_id="")])
        ),
    )


def test_ihave_single_id(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An IHAVE advertising one message id round-trips.

    Given
    -----
    - an RPC whose control message holds an IHAVE with one message id.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                ihave=[RpcIHaveSpec(topic_id=TOPIC_A, message_ids=[MESSAGE_ID_1])]
            ),
        ),
    )


def test_ihave_multiple_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An IHAVE advertising three message ids round-trips.

    Given
    -----
    - an RPC whose control message holds an IHAVE with three message ids.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                ihave=[
                    RpcIHaveSpec(
                        topic_id=TOPIC_A, message_ids=[MESSAGE_ID_1, MESSAGE_ID_2, MESSAGE_ID_3]
                    )
                ]
            ),
        ),
    )


def test_ihave_empty_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An IHAVE with a topic but no message ids round-trips.

    Given
    -----
    - an RPC whose control message holds an IHAVE with a topic and no ids.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(ihave=[RpcIHaveSpec(topic_id=TOPIC_A, message_ids=[])]),
        ),
    )


def test_iwant_single_id(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An IWANT requesting one message id round-trips.

    Given
    -----
    - an RPC whose control message holds an IWANT with one message id.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(iwant=[RpcIWantSpec(message_ids=[MESSAGE_ID_1])]),
        ),
    )


def test_iwant_multiple_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An IWANT requesting two message ids round-trips.

    Given
    -----
    - an RPC whose control message holds an IWANT with two message ids.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(iwant=[RpcIWantSpec(message_ids=[MESSAGE_ID_1, MESSAGE_ID_2])]),
        ),
    )


def test_prune_topic_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A PRUNE with only a topic round-trips.

    Given
    -----
    - an RPC whose control message holds a PRUNE with a topic and no backoff.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(prune=[RpcPruneSpec(topic_id=TOPIC_A)]),
        ),
    )


def test_prune_with_backoff(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A PRUNE with a 60-second backoff round-trips.

    Given
    -----
    - an RPC whose control message holds a PRUNE with a 60-second backoff.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(prune=[RpcPruneSpec(topic_id=TOPIC_A, backoff=60)]),
        ),
    )


def test_prune_with_two_minute_backoff(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A PRUNE with a 120-second backoff round-trips.

    Given
    -----
    - an RPC whose control message holds a PRUNE with a 120-second backoff.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.

    Notes
    -----
    - peer exchange records are not part of the lean wire format.
    - this vector carries no peer exchange records.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(prune=[RpcPruneSpec(topic_id=TOPIC_A, backoff=120)]),
        ),
    )


def test_idontwant_single_id(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An IDONTWANT declining one message id round-trips.

    Given
    -----
    - an RPC whose control message holds an IDONTWANT with one message id.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_1])]),
        ),
    )


def test_idontwant_multiple_ids(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An IDONTWANT declining two message ids round-trips.

    Given
    -----
    - an RPC whose control message holds an IDONTWANT with two message ids.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_1, MESSAGE_ID_2])]
            ),
        ),
    )


def test_control_single_graft(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A control message holding a single GRAFT round-trips.

    Given
    -----
    - an RPC whose control message holds one GRAFT.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(graft=[RpcGraftSpec(topic_id=TOPIC_A)]),
        ),
    )


def test_control_all_types(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A control message holding one of each control type round-trips.

    Given
    -----
    - an RPC whose control message holds an IHAVE, IWANT, GRAFT, PRUNE, and IDONTWANT.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                ihave=[RpcIHaveSpec(topic_id=TOPIC_A, message_ids=[MESSAGE_ID_1])],
                iwant=[RpcIWantSpec(message_ids=[MESSAGE_ID_2])],
                graft=[RpcGraftSpec(topic_id=TOPIC_A)],
                prune=[RpcPruneSpec(topic_id=TOPIC_B, backoff=60)],
                idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_3])],
            ),
        ),
    )


def test_control_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An empty control message encodes to zero bytes and round-trips.

    Given
    -----
    - an RPC whose control message holds no entries.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the control message encodes to zero bytes.
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[], control=RpcControlSpec()),
    )


def test_rpc_subscriptions_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An RPC with only subscription changes round-trips.

    Given
    -----
    - an RPC with two subscribe entries and no messages or control.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[
                RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_A),
                RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_B),
            ],
            publish=[],
        ),
    )


def test_rpc_publish_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An RPC with only published messages round-trips.

    Given
    -----
    - an RPC with two published messages and no subscriptions or control.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[
                RpcMessageSpec(topic=TOPIC_A, data="0xdeadbeef"),
                RpcMessageSpec(topic=TOPIC_B, data="0xcafebabe"),
            ],
        ),
    )


def test_rpc_control_only(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An RPC with only control messages round-trips.

    Given
    -----
    - an RPC whose control message holds a GRAFT and a PRUNE.
    - no subscriptions or published messages are present.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[],
            publish=[],
            control=RpcControlSpec(
                graft=[RpcGraftSpec(topic_id=TOPIC_A)],
                prune=[RpcPruneSpec(topic_id=TOPIC_B, backoff=60)],
            ),
        ),
    )


def test_rpc_full(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A full RPC carrying every section round-trips.

    Given
    -----
    - an RPC with a subscription, a published message, and a control message.
    - the control message holds a GRAFT and an IDONTWANT.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(
            subscriptions=[RpcSubscriptionSpec(subscribe=True, topic_id=TOPIC_A)],
            publish=[RpcMessageSpec(topic=TOPIC_A, data="0xdeadbeef")],
            control=RpcControlSpec(
                graft=[RpcGraftSpec(topic_id=TOPIC_B)],
                idontwant=[RpcIDontWantSpec(message_ids=[MESSAGE_ID_1])],
            ),
        ),
    )


def test_rpc_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An empty RPC round-trips.

    Given
    -----
    - an RPC with no subscriptions, no messages, and no control.

    When
    ----
    - the RPC is encoded and decoded.

    Then
    ----
    - the decoded RPC matches the input.
    """
    networking_codec_test(
        codec=GossipsubRpcRoundtrip(subscriptions=[], publish=[]),
    )
