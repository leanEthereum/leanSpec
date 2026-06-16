"""Networking codec test fixture for wire-format conformance testing."""

from collections.abc import Callable
from typing import Annotated, ClassVar, Final, Literal

from pydantic import Field

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_fixtures.hex_codec import from_hex, to_hex
from lean_spec.base import StrictBaseModel
from lean_spec.node.networking.enr.enr import ENR
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    SubOpts,
)
from lean_spec.node.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.node.networking.gossipsub.types import TopicId
from lean_spec.node.networking.reqresp.codec import (
    ResponseCode,
    decode_request,
    encode_request,
)
from lean_spec.node.networking.transport.peer_id import KeyType, PeerId, PublicKeyProtobuf
from lean_spec.node.networking.varint import decode_varint, encode_varint
from lean_spec.node.snappy import compress, decompress, frame_compress, frame_decompress
from lean_spec.spec.forks import SubnetId


class EncodedOutput(StrictBaseModel):
    """Reference encoding for a roundtrip vector."""

    encoded: str
    """Hex encoding the client must reproduce."""


class VarintOutput(StrictBaseModel):
    """Reference LEB128 encoding."""

    encoded: str
    """Hex LEB128 bytes the client must reproduce."""

    byte_length: int
    """Number of bytes in the encoding."""


class VarintRoundtrip(StrictBaseModel):
    """Encode a value as LEB128, decode it back, assert roundtrip."""

    kind: Literal["varint"] = "varint"
    """Discriminator field for serialization."""

    value: int
    """Value to encode."""

    def run(self) -> VarintOutput:
        """Encode, decode back, and emit the reference bytes."""
        encoded = encode_varint(self.value)

        # Decode must recover the original value and consume all bytes.
        decoded, byte_length = decode_varint(encoded)
        assert decoded == self.value, (
            f"Varint roundtrip: {self.value} -> {encoded.hex()} -> {decoded}"
        )
        assert byte_length == len(encoded), f"Length: {byte_length} != {len(encoded)}"

        return VarintOutput(encoded=to_hex(encoded), byte_length=byte_length)


class GossipTopicOutput(StrictBaseModel):
    """Reference topic string and optional fork verdict."""

    topic_string: str
    """Canonical topic string the client must produce."""

    fork_valid: bool | None = None
    """Fork validation verdict, present when an expected network name was given."""


class GossipTopicRoundtrip(StrictBaseModel):
    """
    Build a topic string from components, parse it back, assert roundtrip.

    When an expected network name is given, also run fork validation
    against the parsed topic and report whether the network name matched.
    This pins the accept / reject branches clients must agree on when
    deciding which mesh to admit a topic into.
    """

    kind: Literal["gossip_topic"] = "gossip_topic"
    """Discriminator field for serialization."""

    topic_kind: str
    """Topic kind under test (e.g. block, attestation)."""

    network_name: str
    """Network name component of the topic."""

    subnet_id: int | None = None
    """Optional subnet component for subnet topics."""

    expected_network_name: str | None = None
    """When set, the parsed topic is validated against this network name."""

    def run(self) -> GossipTopicOutput:
        """Build, parse back, optionally validate the fork, and emit the verdicts."""
        topic = GossipTopic(
            kind=TopicKind(self.topic_kind),
            network_name=self.network_name,
            subnet_id=SubnetId(self.subnet_id) if self.subnet_id is not None else None,
        )
        topic_string = topic.to_topic_id()

        # Parse the string back to verify it reconstructs the same topic.
        parsed = GossipTopic.from_string(topic_string)
        assert parsed == topic, f"Topic roundtrip: {topic} -> {topic_string!r} -> {parsed}"

        fork_valid: bool | None = None
        if self.expected_network_name is not None:
            try:
                parsed.validate_fork(self.expected_network_name)
                fork_valid = True
            except ValueError:
                fork_valid = False

        return GossipTopicOutput(topic_string=topic_string, fork_valid=fork_valid)


class GossipMessageIdentifierOutput(StrictBaseModel):
    """Reference gossipsub message identifier."""

    message_id: str
    """Hex 20-byte message identifier the client must reproduce."""


class GossipMessageIdentifier(StrictBaseModel):
    """Compute a 20-byte gossipsub message identifier from topic, data, and domain."""

    kind: Literal["gossip_message_id"] = "gossip_message_id"
    """Discriminator field for serialization."""

    topic: str
    """Hex topic bytes."""

    data: str
    """Hex message payload."""

    domain: str
    """Hex domain separator."""

    def run(self) -> GossipMessageIdentifierOutput:
        """Compute the identifier: SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]."""
        message_id = GossipsubMessage.compute_id(
            from_hex(self.topic), from_hex(self.data), domain=from_hex(self.domain)
        )
        return GossipMessageIdentifierOutput(message_id=to_hex(message_id))


class RpcSubscriptionSpec(StrictBaseModel):
    """One subscription change inside an RPC."""

    subscribe: bool
    """True to subscribe, False to unsubscribe."""

    topic_id: str
    """Topic the change applies to."""


class RpcMessageSpec(StrictBaseModel):
    """One published message inside an RPC. Bytes fields are hex-encoded."""

    from_peer: str | None = None
    """Hex sender peer bytes."""

    data: str | None = None
    """Hex message payload."""

    seqno: str | None = None
    """Hex sequence number bytes."""

    topic: str = ""
    """Topic the message belongs to."""

    signature: str | None = None
    """Hex message signature."""

    key: str | None = None
    """Hex signer key."""

    def build(self) -> Message:
        """Convert to the wire-format message."""
        return Message(
            from_peer=from_hex(self.from_peer) if self.from_peer else b"",
            data=from_hex(self.data) if self.data else b"",
            seqno=from_hex(self.seqno) if self.seqno else b"",
            topic=TopicId(self.topic),
            signature=from_hex(self.signature) if self.signature else b"",
            key=from_hex(self.key) if self.key else b"",
        )


class RpcIHaveSpec(StrictBaseModel):
    """One IHAVE control entry."""

    topic_id: str = ""
    """Topic the advertised messages belong to."""

    message_ids: list[str] = []
    """Hex identifiers of the advertised messages."""


class RpcIWantSpec(StrictBaseModel):
    """One IWANT control entry."""

    message_ids: list[str] = []
    """Hex identifiers of the requested messages."""


class RpcGraftSpec(StrictBaseModel):
    """One GRAFT control entry."""

    topic_id: str
    """Topic to graft into the mesh."""


class RpcPruneSpec(StrictBaseModel):
    """One PRUNE control entry."""

    topic_id: str = ""
    """Topic to prune from the mesh."""

    backoff: int = 0
    """Backoff seconds before re-grafting is allowed."""


class RpcIDontWantSpec(StrictBaseModel):
    """One IDONTWANT control entry."""

    message_ids: list[str] = []
    """Hex identifiers of the unwanted messages."""


class RpcControlSpec(StrictBaseModel):
    """Control sub-messages inside an RPC."""

    ihave: list[RpcIHaveSpec] = []
    """IHAVE advertisements."""

    iwant: list[RpcIWantSpec] = []
    """IWANT requests."""

    graft: list[RpcGraftSpec] = []
    """GRAFT requests."""

    prune: list[RpcPruneSpec] = []
    """PRUNE notices."""

    idontwant: list[RpcIDontWantSpec] = []
    """IDONTWANT notices."""

    def build(self) -> ControlMessage:
        """Convert to the wire-format control message."""
        return ControlMessage(
            ihave=[
                ControlIHave(
                    topic_id=TopicId(ihave.topic_id),
                    message_ids=[from_hex(message_id) for message_id in ihave.message_ids],
                )
                for ihave in self.ihave
            ],
            iwant=[
                ControlIWant(message_ids=[from_hex(message_id) for message_id in iwant.message_ids])
                for iwant in self.iwant
            ],
            graft=[ControlGraft(topic_id=TopicId(graft.topic_id)) for graft in self.graft],
            prune=[
                ControlPrune(topic_id=TopicId(prune.topic_id), backoff=prune.backoff)
                for prune in self.prune
            ],
            idontwant=[
                ControlIDontWant(
                    message_ids=[from_hex(message_id) for message_id in idontwant.message_ids]
                )
                for idontwant in self.idontwant
            ],
        )


class GossipsubRpcRoundtrip(StrictBaseModel):
    """Encode an RPC message as protobuf, decode it back, assert roundtrip."""

    kind: Literal["gossipsub_rpc"] = "gossipsub_rpc"
    """Discriminator field for serialization."""

    subscriptions: list[RpcSubscriptionSpec] = []
    """Subscription changes carried by the RPC."""

    publish: list[RpcMessageSpec] = []
    """Messages carried by the RPC."""

    control: RpcControlSpec | None = None
    """Optional control sub-messages."""

    def run(self) -> EncodedOutput:
        """Encode the RPC, decode it back, and emit the reference bytes."""
        rpc = RPC(
            subscriptions=[
                SubOpts(subscribe=subscription.subscribe, topic_id=TopicId(subscription.topic_id))
                for subscription in self.subscriptions
            ],
            publish=[message.build() for message in self.publish],
            control=self.control.build() if self.control is not None else None,
        )
        encoded = rpc.encode()

        # Decode and re-encode must produce identical bytes.
        re_encoded = RPC.decode(encoded).encode()
        assert encoded == re_encoded, "RPC roundtrip produced different bytes"

        return EncodedOutput(encoded=to_hex(encoded))


class ReqRespRequestRoundtrip(StrictBaseModel):
    """Encode an SSZ request as varint + snappy, decode it back, assert roundtrip."""

    kind: Literal["reqresp_request"] = "reqresp_request"
    """Discriminator field for serialization."""

    ssz_data: str
    """Hex SSZ payload."""

    def run(self) -> EncodedOutput:
        """Encode the request, decode it back, and emit the reference bytes."""
        ssz_data = from_hex(self.ssz_data)
        encoded = encode_request(ssz_data)

        # Decode must recover the original SSZ bytes.
        decoded = decode_request(encoded)
        assert decoded == ssz_data, "Request roundtrip produced different bytes"

        return EncodedOutput(encoded=to_hex(encoded))


class ReqRespResponseRoundtrip(StrictBaseModel):
    """Encode an SSZ response with code, decode it back, assert roundtrip."""

    kind: Literal["reqresp_response"] = "reqresp_response"
    """Discriminator field for serialization."""

    response_code: int
    """Response code byte."""

    ssz_data: str
    """Hex SSZ payload."""

    def run(self) -> EncodedOutput:
        """Encode the response, decode it back, and emit the reference bytes."""
        code = ResponseCode(self.response_code)
        ssz_data = from_hex(self.ssz_data)
        encoded = code.encode(ssz_data)

        # Decode must recover both the response code and SSZ bytes.
        decoded_code, decoded_data = ResponseCode.decode(encoded)
        assert decoded_code == code, f"Code mismatch: {decoded_code} != {code}"
        assert decoded_data == ssz_data, "Response roundtrip produced different bytes"

        return EncodedOutput(encoded=to_hex(encoded))


class ResponseChunkSpec(StrictBaseModel):
    """One chunk of a multi-chunk response stream."""

    response_code: int
    """Response code byte for this chunk."""

    ssz_data: str
    """Hex SSZ payload for this chunk."""


class ResponseStreamOutput(StrictBaseModel):
    """Reference encoding of a multi-chunk response stream."""

    encoded: str
    """Concatenated stream hex the client must reproduce."""

    chunk_count: int
    """Number of chunks in the stream."""


class ReqRespResponseStream(StrictBaseModel):
    """
    Encode a sequence of response chunks as a concatenated stream.

    Multi-chunk responses (for example BlocksByRoot returning N blocks)
    send their chunks back-to-back on a single libp2p stream: each
    chunk is its own [code][varint][snappy_frame] triple, and the
    receiver reads them in order until EOF.
    """

    kind: Literal["reqresp_response_stream"] = "reqresp_response_stream"
    """Discriminator field for serialization."""

    chunks: list[ResponseChunkSpec]
    """Ordered chunks; each is encoded independently and concatenated."""

    def run(self) -> ResponseStreamOutput:
        """Encode every chunk back-to-back and emit the reference stream."""
        buffer = bytearray()
        for chunk in self.chunks:
            buffer.extend(ResponseCode(chunk.response_code).encode(from_hex(chunk.ssz_data)))
        return ResponseStreamOutput(
            encoded=to_hex(bytes(buffer)),
            chunk_count=len(self.chunks),
        )


class EnrEth2DataOutput(StrictBaseModel):
    """Decoded eth2 ENR entry."""

    fork_digest: str
    """Hex fork digest."""

    next_fork_version: str
    """Hex next fork version."""

    next_fork_epoch: int
    """Next fork epoch."""


class EnrOutput(StrictBaseModel):
    """Decoded ENR properties the client must reproduce."""

    rlp: str
    """Hex RLP encoding."""

    seq: int
    """Sequence number."""

    identity_scheme: str
    """Identity scheme name."""

    node_id: str | None = None
    """Hex node identifier, when derivable."""

    public_key: str | None = None
    """Hex public key, when present."""

    ip4: str | None = None
    """IPv4 address, when present."""

    udp_port: int | None = None
    """UDP port, when present."""

    quic_port: int | None = None
    """QUIC port, when present."""

    multiaddr: str | None = None
    """Derived multiaddress, when derivable."""

    eth2_data: EnrEth2DataOutput | None = None
    """Decoded eth2 entry, when present."""

    attestation_subnets: list[int] | None = None
    """Subscribed attestation subnets, when the attnets entry is present."""

    is_aggregator: bool
    """Aggregator flag."""

    signature_valid: bool
    """Whether the record signature verifies."""

    is_valid: bool
    """Whether the record is valid overall."""


class EnrRoundtrip(StrictBaseModel):
    """Parse an ENR string, re-serialize, assert roundtrip, extract properties."""

    kind: Literal["enr"] = "enr"
    """Discriminator field for serialization."""

    enr_string: str
    """Text ENR record under test."""

    def run(self) -> EnrOutput:
        """Roundtrip the record through text and RLP, then emit its properties."""
        enr = ENR.from_string(self.enr_string)

        # Text roundtrip: parse → serialize → must match original.
        assert enr.to_string() == self.enr_string, "ENR text roundtrip failed"

        # RLP roundtrip: serialize → parse → serialize → must match.
        rlp_bytes = enr.to_rlp()
        assert ENR.from_rlp(rlp_bytes).to_rlp() == rlp_bytes, "ENR RLP roundtrip failed"

        # Invariant: every record that survives the roundtrips names its scheme.
        assert enr.identity_scheme is not None, "ENR record carries no identity scheme"

        eth2_data = enr.eth2_data
        attestation_subnets = enr.attestation_subnets
        return EnrOutput(
            rlp=to_hex(rlp_bytes),
            seq=int(enr.seq),
            identity_scheme=enr.identity_scheme,
            node_id=to_hex(enr.node_id) if enr.node_id else None,
            public_key=to_hex(enr.public_key) if enr.public_key else None,
            ip4=enr.ip4 if enr.ip4 else None,
            udp_port=int(enr.udp_port) if enr.udp_port is not None else None,
            quic_port=int(enr.quic_port) if enr.quic_port is not None else None,
            multiaddr=str(enr.multiaddr()) if enr.multiaddr() is not None else None,
            eth2_data=(
                EnrEth2DataOutput(
                    fork_digest=to_hex(eth2_data.fork_digest),
                    next_fork_version=to_hex(eth2_data.next_fork_version),
                    next_fork_epoch=int(eth2_data.next_fork_epoch),
                )
                if eth2_data is not None
                else None
            ),
            attestation_subnets=(
                [int(subnet_id) for subnet_id in attestation_subnets.subscribed_subnets()]
                if attestation_subnets is not None
                else None
            ),
            is_aggregator=enr.is_aggregator,
            # The accept/reject verdict is the canonical contract a client must reproduce.
            # Both verdicts are a deterministic function of the record bytes alone.
            # Structural validity reads the record fields.
            # Signature validity is secp256k1 ECDSA verification over keccak256 of the content.
            # Verification takes no time, nonce, or RNG input, so the emitted value is stable.
            signature_valid=enr.verify_signature(),
            is_valid=enr.is_valid(),
        )


class PeerIdentifierOutput(StrictBaseModel):
    """Reference peer identifier derivation."""

    protobuf_encoded: str
    """Hex protobuf encoding of the public key."""

    peer_id: str
    """Base58 peer identifier string."""


class PeerIdentifierDerivation(StrictBaseModel):
    """Derive a peer identifier from a public key."""

    kind: Literal["peer_id"] = "peer_id"
    """Discriminator field for serialization."""

    key_type: Literal["ed25519", "secp256k1", "ecdsa", "rsa"]
    """Public key algorithm."""

    public_key: str
    """Hex public key bytes."""

    def run(self) -> PeerIdentifierOutput:
        """Derive the identifier and assert the Base58 roundtrip."""
        # The literal values match the enum member names once upper-cased.
        protobuf = PublicKeyProtobuf(
            key_type=KeyType[self.key_type.upper()], key_data=from_hex(self.public_key)
        )
        peer_id = PeerId.from_public_key(protobuf)
        peer_id_string = str(peer_id)

        # Roundtrip: Base58 decode → re-encode must match.
        roundtrip = PeerId.from_base58(peer_id_string)
        assert roundtrip == peer_id, "PeerId Base58 roundtrip failed"

        return PeerIdentifierOutput(
            protobuf_encoded=to_hex(protobuf.encode()),
            peer_id=peer_id_string,
        )


class SnappyBlockOutput(StrictBaseModel):
    """Reference raw Snappy block compression."""

    compressed: str
    """Hex compressed bytes."""

    compressed_length: int
    """Compressed byte count."""

    uncompressed_length: int
    """Original byte count."""


class SnappyBlockRoundtrip(StrictBaseModel):
    """Compress with raw Snappy block format, decompress, assert roundtrip."""

    kind: Literal["snappy_block"] = "snappy_block"
    """Discriminator field for serialization."""

    data: str
    """Hex payload to compress."""

    def run(self) -> SnappyBlockOutput:
        """Compress, decompress back, and emit the reference bytes."""
        uncompressed_bytes = from_hex(self.data)
        compressed = compress(uncompressed_bytes)

        decompressed = decompress(compressed)
        assert decompressed == uncompressed_bytes, "Snappy block roundtrip produced different bytes"

        return SnappyBlockOutput(
            compressed=to_hex(compressed),
            compressed_length=len(compressed),
            uncompressed_length=len(uncompressed_bytes),
        )


class SnappyFrameOutput(StrictBaseModel):
    """Reference framed Snappy compression."""

    framed: str
    """Hex framed bytes."""

    framed_length: int
    """Framed byte count."""

    uncompressed_length: int
    """Original byte count."""


class SnappyFrameRoundtrip(StrictBaseModel):
    """Compress with Snappy framing format (Ethereum wire format), decompress, roundtrip."""

    kind: Literal["snappy_frame"] = "snappy_frame"
    """Discriminator field for serialization."""

    data: str
    """Hex payload to compress."""

    def run(self) -> SnappyFrameOutput:
        """Compress with framing, decompress back, and emit the reference bytes."""
        uncompressed_bytes = from_hex(self.data)
        framed = frame_compress(uncompressed_bytes)

        decompressed = frame_decompress(framed)
        assert decompressed == uncompressed_bytes, "Snappy frame roundtrip produced different bytes"

        return SnappyFrameOutput(
            framed=to_hex(framed),
            framed_length=len(framed),
            uncompressed_length=len(uncompressed_bytes),
        )


class DecodeFailureOutput(StrictBaseModel):
    """Echo of the decoder a rejection vector targets."""

    decoder: str
    """Name of the decoder that must reject the input."""


_DECODERS_BY_NAME: Final[dict[str, Callable[[bytes], object]]] = {
    "varint": decode_varint,
    "snappy_frame": frame_decompress,
    "snappy_block": decompress,
    "gossipsub_rpc": RPC.decode,
    "reqresp_request": decode_request,
    "reqresp_response": ResponseCode.decode,
    "enr": ENR.from_rlp,
}
"""Wire-format decoders keyed by the name a rejection vector targets."""


class DecodeFailure(StrictBaseModel):
    """Assert that a wire-format decoder rejects malformed input."""

    kind: Literal["decode_failure"] = "decode_failure"
    """Discriminator field for serialization."""

    decoder: Literal[
        "varint",
        "snappy_frame",
        "snappy_block",
        "gossipsub_rpc",
        "reqresp_request",
        "reqresp_response",
        "enr",
    ]
    """Decoder under test."""

    raw_bytes: str
    """Hex malformed input the decoder must reject."""

    def attempt_decode(self) -> Exception | None:
        """Run the decoder on the malformed input and return what it raised."""
        try:
            _DECODERS_BY_NAME[self.decoder](from_hex(self.raw_bytes))
        except Exception as exception:
            return exception
        return None


NetworkingCodec = Annotated[
    VarintRoundtrip
    | GossipTopicRoundtrip
    | GossipMessageIdentifier
    | GossipsubRpcRoundtrip
    | ReqRespRequestRoundtrip
    | ReqRespResponseRoundtrip
    | ReqRespResponseStream
    | EnrRoundtrip
    | PeerIdentifierDerivation
    | SnappyBlockRoundtrip
    | SnappyFrameRoundtrip
    | DecodeFailure,
    Field(discriminator="kind"),
]
"""Discriminated union of every networking codec case under test."""

NetworkingCodecOutput = (
    VarintOutput
    | GossipTopicOutput
    | GossipMessageIdentifierOutput
    | EncodedOutput
    | ResponseStreamOutput
    | EnrOutput
    | PeerIdentifierOutput
    | SnappyBlockOutput
    | SnappyFrameOutput
    | DecodeFailureOutput
)
"""Union of the computed results, paired with the codec kind."""


class NetworkingCodecFixture(BaseConsensusFixture):
    """
    Emitted vector for networking wire-format conformance.

    JSON output: codec, output.
    """

    codec: NetworkingCodec
    """Codec case under test, with its typed inputs."""

    output: NetworkingCodecOutput
    """Computed result the client must reproduce."""


class NetworkingCodecTest(BaseTestSpec):
    """
    Spec for networking wire-format conformance.

    Verifies encode/decode roundtrips for networking codecs.
    """

    format_name: ClassVar[str] = "networking_codec_test"
    description: ClassVar[str] = "Tests networking codec encode/decode roundtrip"

    codec: NetworkingCodec
    """Codec case to run, with its typed inputs."""

    def generate(self) -> NetworkingCodecFixture:
        """Run the codec case and emit the vector."""
        if isinstance(self.codec, DecodeFailure):
            # Emit the language-neutral reason clients assert against.
            return NetworkingCodecFixture(
                codec=self.codec,
                output=DecodeFailureOutput(decoder=self.codec.decoder),
                rejection_reason=self.assert_decode_rejection(
                    self.codec.attempt_decode(), self.codec.decoder
                ),
            )
        return NetworkingCodecFixture(codec=self.codec, output=self.codec.run())
