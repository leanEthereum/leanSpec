"""Networking codec test fixture for wire-format conformance testing."""

from typing import Any, ClassVar

from lean_spec.forks.lstar.containers.validator import SubnetId
from lean_spec.snappy import compress, decompress, frame_compress, frame_decompress
from lean_spec.subspecs.networking.discovery.codec import decode_message, encode_message
from lean_spec.subspecs.networking.discovery.messages import (
    Distance,
    FindNode,
    IdNonce,
    IPv4,
    IPv6,
    Nodes,
    Nonce,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
    TalkReq,
    TalkResp,
)
from lean_spec.subspecs.networking.discovery.packet import (
    decode_handshake_authdata,
    decode_message_authdata,
    decode_packet_header,
    decode_whoareyou_authdata,
    encode_handshake_authdata,
    encode_message_authdata,
    encode_packet,
    encode_whoareyou_authdata,
)
from lean_spec.subspecs.networking.discovery.routing import log2_distance, xor_distance
from lean_spec.subspecs.networking.enr.enr import ENR
from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    PrunePeerInfo,
    SubOpts,
)
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.subspecs.networking.gossipsub.types import TopicId
from lean_spec.subspecs.networking.reqresp.codec import (
    ResponseCode,
    decode_request,
    encode_request,
)
from lean_spec.subspecs.networking.transport.peer_id import KeyType, PeerId, PublicKeyProto
from lean_spec.subspecs.networking.types import NodeId, SeqNumber
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint
from lean_spec.types import Bytes16, Bytes33, Bytes64

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
            case "discv5_message":
                output = self._make_discv5_message()
            case "discv5_packet":
                output = self._make_discv5_packet()
            case "snappy_block":
                output = self._make_snappy_block()
            case "snappy_frame":
                output = self._make_snappy_frame()
            case "xor_distance":
                output = self._make_xor_distance()
            case "log2_distance":
                output = self._make_log2_distance()
            case "decode_failure":
                output = self._make_decode_failure()
            case _:
                raise ValueError(f"Unknown codec: {self.codec_name}")
        return self.model_copy(update={"output": output})

    def _make_decode_failure(self) -> dict[str, Any]:
        """Assert that decoding `input.bytes` with `input.decoder` raises.

        Dispatches to one of the wire-format decoders and confirms that the
        expected exception (on :attr:`expect_exception`) is raised. Used to
        generate negative-path test vectors for client decoders.

        The input record carries two fields:

        - `decoder`: name of the target decoder (`varint`, `snappy_frame`,
          `gossipsub_rpc`, `reqresp_request`, `reqresp_response`,
          `discv5_message`, `enr`).
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
            "discv5_message": decode_message,
            "discv5_packet": lambda raw: decode_packet_header(
                NodeId(_from_hex(self.input.get("localNodeId", "0x" + "00" * 32))),
                raw,
            ),
            "enr": ENR.from_rlp,
        }
        if decoder_name not in decoders:
            raise ValueError(f"Unknown decoder for decode_failure: {decoder_name!r}")

        decoder = decoders[decoder_name]
        exception_raised: Exception | None = None
        try:
            decoder(raw)
        except Exception as exc:
            exception_raised = exc

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

    def _make_xor_distance(self) -> dict[str, Any]:
        """Compute XOR distance between two node IDs."""
        node_a = NodeId(_from_hex(self.input["nodeA"]))
        node_b = NodeId(_from_hex(self.input["nodeB"]))
        distance = xor_distance(node_a, node_b)
        return {"distance": hex(distance)}

    def _make_log2_distance(self) -> dict[str, Any]:
        """Compute log2 of XOR distance for k-bucket assignment."""
        node_a = NodeId(_from_hex(self.input["nodeA"]))
        node_b = NodeId(_from_hex(self.input["nodeB"]))
        distance = int(log2_distance(node_a, node_b))
        return {"distance": distance}

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
        if enr.udp6_port is not None:
            output["udp6Port"] = int(enr.udp6_port)
        if enr.ip6:
            output["ip6"] = enr.ip6
        if enr.quic_port is not None:
            output["quicPort"] = int(enr.quic_port)
        if enr.quic6_port is not None:
            output["quic6Port"] = int(enr.quic6_port)
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
        if (sync := enr.sync_committee_subnets) is not None:
            output["syncCommitteeSubnets"] = [int(s) for s in sync.subscribed_subnets()]
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

        proto = PublicKeyProto(key_type=key_type, key_data=key_data)
        encoded_proto = proto.encode()
        peer_id = PeerId.from_public_key(proto)
        peer_id_str = str(peer_id)

        # Roundtrip: Base58 decode → re-encode must match.
        roundtrip = PeerId.from_base58(peer_id_str)
        assert roundtrip == peer_id, "PeerId Base58 roundtrip failed"

        return {
            "protobufEncoded": _to_hex(encoded_proto),
            "peerId": peer_id_str,
        }

    def _make_discv5_message(self) -> dict[str, Any]:
        """Encode a discv5 message as type byte + RLP, decode it back, assert roundtrip."""
        msg = _build_discv5_message(self.input)
        encoded = encode_message(msg)

        # Decode and re-encode must produce identical bytes.
        re_encoded = encode_message(decode_message(encoded))
        assert encoded == re_encoded, "Discv5 message roundtrip produced different bytes"

        return {"encoded": _to_hex(encoded)}

    def _make_discv5_packet(self) -> dict[str, Any]:
        """Encode a Discovery v5 packet and roundtrip-decode the header.

        Input keys (all hex unless noted):

        - `packetType`: "message", "whoareyou", or "handshake".
        - `destNodeId`: 32-byte destination node ID. Masking key
          derives from its first 16 bytes; clients also use this as the
          local node id when decoding.
        - `nonce`: 12-byte message nonce.
        - `maskingIv`: 16-byte header-masking IV, supplied explicitly
          so the produced bytes are deterministic.
        - `message`: message payload (empty for WHOAREYOU, otherwise
          the already-encrypted ciphertext bytes).
        - `encryptionKey`: 16-byte AES-GCM key for non-WHOAREYOU.

        Packet-type-specific input keys:

        - message: `srcId`.
        - whoareyou: `idNonce`, `enrSeq` (uint64 integer).
        - handshake: `srcId`, `idSignature`, `ephPubkey`, optional
          `record` (RLP-encoded ENR).

        Output:

        - `encoded`: full packet hex.
        - `flag`: numeric flag (0/1/2) recovered via decode.
        - `authdataSize`: size of authdata in bytes.
        """
        packet_type = self.input["packetType"]
        dest_node_id = NodeId(_from_hex(self.input["destNodeId"]))
        nonce = Nonce(_from_hex(self.input["nonce"]))
        masking_iv = Bytes16(_from_hex(self.input["maskingIv"]))
        message_bytes = _from_hex(self.input.get("message", "0x"))

        if packet_type == "message":
            flag = PacketFlag.MESSAGE
            authdata = encode_message_authdata(NodeId(_from_hex(self.input["srcId"])))
            encryption_key: Bytes16 | None = Bytes16(_from_hex(self.input["encryptionKey"]))
        elif packet_type == "whoareyou":
            flag = PacketFlag.WHOAREYOU
            authdata = encode_whoareyou_authdata(
                IdNonce(_from_hex(self.input["idNonce"])),
                SeqNumber(int(self.input["enrSeq"])),
            )
            encryption_key = None
        elif packet_type == "handshake":
            flag = PacketFlag.HANDSHAKE
            record = _from_hex(self.input["record"]) if self.input.get("record") else None
            authdata = encode_handshake_authdata(
                NodeId(_from_hex(self.input["srcId"])),
                Bytes64(_from_hex(self.input["idSignature"])),
                Bytes33(_from_hex(self.input["ephPubkey"])),
                record=record,
            )
            encryption_key = Bytes16(_from_hex(self.input["encryptionKey"]))
        else:
            raise ValueError(f"Unknown discv5 packet type: {packet_type!r}")

        encoded = encode_packet(
            dest_node_id=dest_node_id,
            flag=flag,
            nonce=nonce,
            authdata=authdata,
            message=message_bytes,
            encryption_key=encryption_key,
            masking_iv=masking_iv,
        )

        # Roundtrip: decode header and assert shape matches.
        header, _msg, _ad = decode_packet_header(dest_node_id, encoded)
        assert header.flag == flag, "Packet flag roundtrip mismatch"
        assert header.nonce == nonce, "Packet nonce roundtrip mismatch"
        assert header.authdata == authdata, "Packet authdata roundtrip mismatch"

        # Exercise per-type authdata decode for extra shape coverage.
        if flag == PacketFlag.MESSAGE:
            decode_message_authdata(header.authdata)
        elif flag == PacketFlag.WHOAREYOU:
            decode_whoareyou_authdata(header.authdata)
        elif flag == PacketFlag.HANDSHAKE:
            decode_handshake_authdata(header.authdata)

        return {
            "encoded": _to_hex(encoded),
            "flag": int(flag),
            "authdataSize": len(authdata),
        }


def _build_discv5_message(
    d: dict[str, Any],
) -> Ping | Pong | FindNode | Nodes | TalkReq | TalkResp:
    """Build a discv5 message dataclass from a JSON-friendly dict."""
    request_id = RequestId(data=_from_hex(d["requestId"]))
    match d["type"]:
        case "ping":
            return Ping(request_id=request_id, enr_seq=SeqNumber(d["enrSeq"]))
        case "pong":
            ip_bytes = _from_hex(d["recipientIp"])
            ip = IPv4(ip_bytes) if len(ip_bytes) == 4 else IPv6(ip_bytes)
            return Pong(
                request_id=request_id,
                enr_seq=SeqNumber(d["enrSeq"]),
                recipient_ip=ip,
                recipient_port=Port(d["recipientPort"]),
            )
        case "findnode":
            return FindNode(
                request_id=request_id,
                distances=[Distance(x) for x in d["distances"]],
            )
        case "nodes":
            return Nodes(
                request_id=request_id,
                total=d["total"],
                enrs=[_from_hex(e) for e in d.get("enrs", [])],
            )
        case "talkreq":
            return TalkReq(
                request_id=request_id,
                protocol=_from_hex(d["protocol"]),
                request=_from_hex(d["request"]),
            )
        case "talkresp":
            return TalkResp(
                request_id=request_id,
                response=_from_hex(d["response"]),
            )
        case _:
            raise ValueError(f"Unknown discv5 message type: {d['type']}")


def _build_rpc(d: dict[str, Any]) -> RPC:
    """Build an RPC from a JSON-friendly dict."""
    subs = [_build_sub_opts(s) for s in d.get("subscriptions", [])]
    msgs = [_build_message(m) for m in d.get("publish", [])]
    ctrl = _build_control(d["control"]) if d.get("control") else None
    return RPC(subscriptions=subs, publish=msgs, control=ctrl)


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
    peers = [_build_prune_peer(p) for p in d.get("peers", [])]
    return ControlPrune(
        topic_id=TopicId(d.get("topicId", "")),
        peers=peers,
        backoff=d.get("backoff", 0),
    )


def _build_prune_peer(p: dict[str, Any]) -> PrunePeerInfo:
    """Build a PrunePeerInfo from a dict."""
    return PrunePeerInfo(
        peer_id=_from_hex(p["peerId"]) if p.get("peerId") else b"",
        signed_peer_record=(_from_hex(p["signedPeerRecord"]) if p.get("signedPeerRecord") else b""),
    )


def _build_idontwant(d: dict[str, Any]) -> ControlIDontWant:
    """Build a ControlIDontWant from a dict."""
    return ControlIDontWant(message_ids=[_from_hex(mid) for mid in d.get("messageIds", [])])
