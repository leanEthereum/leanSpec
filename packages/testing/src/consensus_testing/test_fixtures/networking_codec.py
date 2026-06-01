"""Networking codec test fixture for wire-format conformance testing."""

from typing import Any, ClassVar

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

from .base import BaseConsensusFixture


def _to_hex(data: bytes) -> str:
    """Format raw bytes as a 0x-prefixed hex string."""
    return "0x" + data.hex()


def _from_hex(hex_str: str) -> bytes:
    """Parse a 0x-prefixed hex string into raw bytes."""
    return bytes.fromhex(hex_str.removeprefix("0x"))


class NetworkingCodecTest(BaseConsensusFixture):
    """Fixture for networking wire-format conformance.

    Verifies encode/decode roundtrips for networking codecs.

    JSON output: codecName, input, output.
    """

    format_name: ClassVar[str] = "networking_codec"
    description: ClassVar[str] = "Tests networking codec encode/decode roundtrip"

    codec_name: str
    """Codec under test: varint, gossip_topic, or gossip_message_id."""

    input: dict[str, Any]
    """Codec-specific input parameters."""

    output: dict[str, Any] = {}
    """Computed output. Filled by make_fixture."""

    def make_fixture(self) -> "NetworkingCodecTest":
        """Dispatch to the codec handler and produce computed output.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If codec_name is unknown.
        """
        match self.codec_name:
            case "varint":
                output = self._make_varint()
            case "gossip_topic":
                output = self._make_gossip_topic()
            case "gossip_message_id":
                output = self._make_gossip_message_id()
            case "gossipsub_rpc":
                output = self._make_gossipsub_rpc()
            case "reqresp_request":
                output = self._make_reqresp_request()
            case "reqresp_response":
                output = self._make_reqresp_response()
            case "reqresp_response_stream":
                output = self._make_reqresp_response_stream()
            case "enr":
                output = self._make_enr()
            case "peer_id":
                output = self._make_peer_id()
            case "snappy_block":
                output = self._make_snappy_block()
            case "snappy_frame":
                output = self._make_snappy_frame()
            case "decode_failure":
                output = self._make_decode_failure()
            case _:
                raise ValueError(f"Unknown codec: {self.codec_name}")
        self.output = output
        return self

    def _make_decode_failure(self) -> dict[str, Any]:
        """Assert that decoding `input.bytes` with `input.decoder` raises.

        Dispatches to one of the wire-format decoders and confirms that the
        expected exception (on :attribute:`expect_exception`) is raised. Used to
        generate negative-path test vectors for client decoders.

        The input record carries two fields:

        - `decoder`: name of the target decoder (`varint`, `snappy_frame`,
          `gossipsub_rpc`, `reqresp_request`, `reqresp_response`, `enr`).
        - `bytes`: hex-encoded malformed input.

        Returns:
            A dict echoing the decoder name along with the error type and
            message for reproducibility.

        Raises:
            AssertionError: If the decoder succeeds or raises a mismatched
                exception type.
            ValueError: If `expect_exception` is unset or the decoder is
                unknown.
        """
        if self.expect_exception is None:
            raise ValueError("decode_failure codec requires expect_exception to be set")

        decoder_name = self.input["decoder"]
        raw = _from_hex(self.input["bytes"])

        decoders: dict[str, Any] = {
            "varint": decode_varint,
            "snappy_frame": frame_decompress,
            "snappy_block": decompress,
            "gossipsub_rpc": RPC.decode,
            "reqresp_request": decode_request,
            "reqresp_response": ResponseCode.decode,
            "enr": ENR.from_rlp,
        }
        if decoder_name not in decoders:
            raise ValueError(f"Unknown decoder for decode_failure: {decoder_name!r}")

        decoder = decoders[decoder_name]
        exception_raised: Exception | None = None
        try:
            decoder(raw)
        except Exception as exception:
            exception_raised = exception

        if exception_raised is None:
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} from "
                f"{decoder_name!r} decode, but decode succeeded"
            )
        if not isinstance(exception_raised, self.expect_exception):
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but got "
                f"{type(exception_raised).__name__}: {exception_raised}"
            )

        return {
            "decoder": decoder_name,
            "errorType": type(exception_raised).__name__,
            "errorMessage": str(exception_raised),
        }

    def _make_varint(self) -> dict[str, Any]:
        """Encode a value as LEB128, decode it back, assert roundtrip."""
        value = self.input["value"]
        encoded = encode_varint(value)

        # Decode must recover the original value and consume all bytes.
        decoded, byte_length = decode_varint(encoded)
        assert decoded == value, f"Varint roundtrip: {value} -> {encoded.hex()} -> {decoded}"
        assert byte_length == len(encoded), f"Length: {byte_length} != {len(encoded)}"

        return {"encoded": _to_hex(encoded), "byteLength": byte_length}

    def _make_gossip_topic(self) -> dict[str, Any]:
        """Build a topic string from components, parse it back, assert roundtrip.

        When the input carries `expectedForkDigest`, also run validate_fork
        against the parsed topic and report whether the network name matched.
        This pins the accept / reject branches clients must agree on when
        deciding which mesh to admit a topic into.
        """
        kind = TopicKind(self.input["kind"])
        network_name = self.input["forkDigest"]
        raw_subnet = self.input.get("subnetId")
        subnet_id = SubnetId(raw_subnet) if raw_subnet is not None else None

        topic = GossipTopic(kind=kind, network_name=network_name, subnet_id=subnet_id)
        topic_string = topic.to_topic_id()

        # Parse the string back to verify it reconstructs the same topic.
        parsed = GossipTopic.from_string(topic_string)
        assert parsed == topic, f"Topic roundtrip: {topic} -> {topic_string!r} -> {parsed}"

        output: dict[str, Any] = {"topicString": topic_string}

        expected_network_name = self.input.get("expectedForkDigest")
        if expected_network_name is not None:
            try:
                parsed.validate_fork(expected_network_name)
                output["forkValid"] = True
            except ValueError:
                output["forkValid"] = False

        return output

    def _make_gossip_message_id(self) -> dict[str, Any]:
        """Compute a 20-byte gossipsub message ID from topic, data, and domain."""
        topic = _from_hex(self.input["topic"])
        data = _from_hex(self.input["data"])
        domain = _from_hex(self.input["domain"])

        # SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]
        message_id = GossipsubMessage.compute_id(topic, data, domain=domain)

        return {"messageId": _to_hex(message_id)}

    def _make_gossipsub_rpc(self) -> dict[str, Any]:
        """Encode an RPC message as protobuf, decode it back, assert roundtrip."""
        rpc = _build_rpc(self.input)
        encoded = rpc.encode()

        # Decode and re-encode must produce identical bytes.
        re_encoded = RPC.decode(encoded).encode()
        assert encoded == re_encoded, "RPC roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}

    def _make_reqresp_request(self) -> dict[str, Any]:
        """Encode an SSZ request as varint + snappy, decode it back, assert roundtrip."""
        ssz_data = _from_hex(self.input["sszData"])
        encoded = encode_request(ssz_data)

        # Decode must recover the original SSZ bytes.
        decoded = decode_request(encoded)
        assert decoded == ssz_data, "Request roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}

    def _make_reqresp_response(self) -> dict[str, Any]:
        """Encode an SSZ response with code, decode it back, assert roundtrip."""
        code = ResponseCode(self.input["responseCode"])
        ssz_data = _from_hex(self.input["sszData"])
        encoded = code.encode(ssz_data)

        # Decode must recover both the response code and SSZ bytes.
        decoded_code, decoded_data = ResponseCode.decode(encoded)
        assert decoded_code == code, f"Code mismatch: {decoded_code} != {code}"
        assert decoded_data == ssz_data, "Response roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}

    def _make_reqresp_response_stream(self) -> dict[str, Any]:
        """Encode a sequence of response chunks as a concatenated stream.

        Multi-chunk responses (for example BlocksByRoot returning N blocks)
        send their chunks back-to-back on a single libp2p stream: each
        chunk is its own [code][varint][snappy_frame] triple, and the
        receiver reads them in order until EOF.

        Input keys:

        - `chunks`: ordered list of `{"responseCode": int, "sszData": hex}`.
          Each entry is encoded independently with ResponseCode.encode
          and the resulting bytes are concatenated.

        Output:

        - `encoded`: concatenated stream hex. Clients reproduce the
          same bytes and their multi-chunk reader must yield the same
          sequence of (code, ssz_data) records.
        - `chunkCount`: number of chunks in the stream.
        """
        raw_chunks = self.input["chunks"]
        buffer = bytearray()
        for entry in raw_chunks:
            code = ResponseCode(entry["responseCode"])
            ssz_data = _from_hex(entry["sszData"])
            buffer.extend(code.encode(ssz_data))
        return {
            "encoded": _to_hex(bytes(buffer)),
            "chunkCount": len(raw_chunks),
        }

    def _make_snappy_block(self) -> dict[str, Any]:
        """Compress with raw Snappy block format, decompress, assert roundtrip."""
        data = _from_hex(self.input["data"])
        compressed = compress(data)

        decompressed = decompress(compressed)
        assert decompressed == data, "Snappy block roundtrip produced different bytes"

        return {
            "compressed": _to_hex(compressed),
            "compressedLength": len(compressed),
            "uncompressedLength": len(data),
        }

    def _make_snappy_frame(self) -> dict[str, Any]:
        """Compress with Snappy framing format (Ethereum wire format), decompress, roundtrip."""
        data = _from_hex(self.input["data"])
        framed = frame_compress(data)

        decompressed = frame_decompress(framed)
        assert decompressed == data, "Snappy frame roundtrip produced different bytes"

        return {
            "framed": _to_hex(framed),
            "framedLength": len(framed),
            "uncompressedLength": len(data),
        }

    def _make_enr(self) -> dict[str, Any]:
        """Parse an ENR string, re-serialize, assert roundtrip, extract properties."""
        enr_string = self.input["enrString"]
        enr = ENR.from_string(enr_string)

        # Text roundtrip: parse → serialize → must match original.
        assert enr.to_string() == enr_string, "ENR text roundtrip failed"

        # RLP roundtrip: serialize → parse → serialize → must match.
        rlp_bytes = enr.to_rlp()
        assert ENR.from_rlp(rlp_bytes).to_rlp() == rlp_bytes, "ENR RLP roundtrip failed"

        # Extract all properties into the output.
        output: dict[str, Any] = {
            "rlp": _to_hex(rlp_bytes),
            "seq": int(enr.seq),
            "identityScheme": enr.identity_scheme,
        }

        if enr.node_id:
            output["nodeId"] = _to_hex(enr.node_id)
        if enr.public_key:
            output["publicKey"] = _to_hex(enr.public_key)
        if enr.ip4:
            output["ip4"] = enr.ip4
        if enr.udp_port is not None:
            output["udpPort"] = int(enr.udp_port)
        if enr.quic_port is not None:
            output["quicPort"] = int(enr.quic_port)
        if (ma := enr.multiaddr()) is not None:
            output["multiaddr"] = str(ma)
        if (eth2 := enr.eth2_data) is not None:
            output["eth2Data"] = {
                "forkDigest": _to_hex(eth2.fork_digest),
                "nextForkVersion": _to_hex(eth2.next_fork_version),
                "nextForkEpoch": int(eth2.next_fork_epoch),
            }
        if (subnets := enr.attestation_subnets) is not None:
            output["attestationSubnets"] = [int(s) for s in subnets.subscribed_subnets()]
        output["isAggregator"] = enr.is_aggregator
        output["signatureValid"] = enr.verify_signature()
        output["isValid"] = enr.is_valid()

        return output

    def _make_peer_id(self) -> dict[str, Any]:
        """Derive a PeerId from a public key, output protobuf encoding and Base58 string."""
        key_type_map = {
            "ed25519": KeyType.ED25519,
            "secp256k1": KeyType.SECP256K1,
            "ecdsa": KeyType.ECDSA,
            "rsa": KeyType.RSA,
        }
        key_type = key_type_map[self.input["keyType"]]
        key_data = _from_hex(self.input["publicKey"])

        protobuf = PublicKeyProtobuf(key_type=key_type, key_data=key_data)
        encoded_protobuf = protobuf.encode()
        peer_id = PeerId.from_public_key(protobuf)
        peer_id_str = str(peer_id)

        # Roundtrip: Base58 decode → re-encode must match.
        roundtrip = PeerId.from_base58(peer_id_str)
        assert roundtrip == peer_id, "PeerId Base58 roundtrip failed"

        return {
            "protobufEncoded": _to_hex(encoded_protobuf),
            "peerId": peer_id_str,
        }


def _build_rpc(d: dict[str, Any]) -> RPC:
    """Build an RPC from a JSON-friendly dict."""
    subs = [_build_sub_opts(s) for s in d.get("subscriptions", [])]
    messages = [_build_message(m) for m in d.get("publish", [])]
    ctrl = _build_control(d["control"]) if d.get("control") else None
    return RPC(subscriptions=subs, publish=messages, control=ctrl)


def _build_sub_opts(d: dict[str, Any]) -> SubOpts:
    """Build a SubOpts from a dict."""
    return SubOpts(subscribe=d["subscribe"], topic_id=TopicId(d["topicId"]))


def _build_message(d: dict[str, Any]) -> Message:
    """Build a Message from a dict. Bytes fields are hex-encoded."""
    return Message(
        from_peer=_from_hex(d["fromPeer"]) if d.get("fromPeer") else b"",
        data=_from_hex(d["data"]) if d.get("data") else b"",
        seqno=_from_hex(d["seqno"]) if d.get("seqno") else b"",
        topic=TopicId(d.get("topic", "")),
        signature=_from_hex(d["signature"]) if d.get("signature") else b"",
        key=_from_hex(d["key"]) if d.get("key") else b"",
    )


def _build_control(d: dict[str, Any]) -> ControlMessage:
    """Build a ControlMessage from a dict."""
    return ControlMessage(
        ihave=[_build_ihave(x) for x in d.get("ihave", [])],
        iwant=[_build_iwant(x) for x in d.get("iwant", [])],
        graft=[ControlGraft(topic_id=TopicId(x["topicId"])) for x in d.get("graft", [])],
        prune=[_build_prune(x) for x in d.get("prune", [])],
        idontwant=[_build_idontwant(x) for x in d.get("idontwant", [])],
    )


def _build_ihave(d: dict[str, Any]) -> ControlIHave:
    """Build a ControlIHave from a dict."""
    return ControlIHave(
        topic_id=TopicId(d.get("topicId", "")),
        message_ids=[_from_hex(mid) for mid in d.get("messageIds", [])],
    )


def _build_iwant(d: dict[str, Any]) -> ControlIWant:
    """Build a ControlIWant from a dict."""
    return ControlIWant(message_ids=[_from_hex(mid) for mid in d.get("messageIds", [])])


def _build_prune(d: dict[str, Any]) -> ControlPrune:
    """Build a ControlPrune from a dict."""
    return ControlPrune(
        topic_id=TopicId(d.get("topicId", "")),
        backoff=d.get("backoff", 0),
    )


def _build_idontwant(d: dict[str, Any]) -> ControlIDontWant:
    """Build a ControlIDontWant from a dict."""
    return ControlIDontWant(message_ids=[_from_hex(mid) for mid in d.get("messageIds", [])])
