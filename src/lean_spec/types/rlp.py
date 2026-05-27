"""
Recursive Length Prefix (RLP) encoding for Ethereum.

RLP serializes byte strings and arbitrarily nested lists of byte strings.

It is the wire format for transactions, blocks, ENR records, and devp2p messages.

Encoding rules (Yellow Paper Appendix B):

    prefix range   meaning
    0x00 .. 0x7f   single byte payload, encoded as itself
    0x80 .. 0xb7   string of 0 to 55 bytes, length = prefix - 0x80
    0xb8 .. 0xbf   long string, prefix - 0xb7 = number of length bytes that follow
    0xc0 .. 0xf7   list with 0 to 55 payload bytes, length = prefix - 0xc0
    0xf8 .. 0xff   long list, prefix - 0xf7 = number of length bytes that follow

Strings and lists share the same length-prefix structure.
The only difference is the base byte: 0x80 for strings, 0xc0 for lists.
The 0x40 gap is the entire string-vs-list distinction.

References:
- Ethereum Yellow Paper, Appendix B.
- https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
"""

import math
from typing import Final

type RLPItem = bytes | list[RLPItem]
"""A byte string or a list of items recursively."""


STRING_BASE: Final = 0x80
"""The byte at which byte-string prefixes begin.

Anything below (0x00 through 0x7F) is its own encoding, with no prefix needed.
From this byte upward, a prefix carries either the string's length or a length-of-length.
The boundary keeps small single bytes free of encoding overhead.
"""

LIST_BASE: Final = 0xC0
"""The byte at which list prefixes begin.

Lists and byte strings share the same length-prefix structure, just shifted by 0x40.
That offset is what tells the decoder to open a list instead of a string.
0xC0 sits above all 64 string prefixes (0x80 to 0xBF), leaving them undisturbed.
"""

SHORT_FORM_MAX: Final = 55
"""The largest payload length that fits the compact one-byte prefix.

- Smaller payloads encode with just base + length as the prefix, no extra bytes.
- Larger payloads switch to the long form, where the prefix carries a length-of-length.

Why 55: each base owns 64 prefix values.
Lengths 0 through 55 take 56 of them, leaving 8 for long-form variants.
"""


class RLPDecodingError(Exception):
    """Raised when RLP input is malformed or non-canonical."""


def encode_rlp(item: RLPItem) -> bytes:
    """
    Encode bytes or a nested list of bytes to RLP.

    Args:
        item: A byte string or a list of items (lists may nest arbitrarily).

    Returns:
        The RLP encoding of the input.

    Raises:
        TypeError: If any element is neither bytes nor list.
    """
    # Bytes branch: either bare-byte fast path or length-prefixed string.
    #
    # A single byte below 0x80 is its own complete encoding.
    # The spec writes this boundary as "< 0x80" so the literal matches the prose.
    #
    # Examples:
    #
    #   b"\x7f"   ->  7f               (bare byte, no prefix)
    #   b"\x80"   ->  81 80            (length-prefixed: single byte at or above 0x80)
    #   b""       ->  80               (empty string is the length-zero short form)
    #   b"dog"    ->  83 64 6f 67      (short string of length 3)
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < STRING_BASE:
            return item
        return _with_length_prefix(item, base=STRING_BASE)

    # List branch: encode each element, concatenate, then wrap with a list prefix.
    #
    # Recursion handles nesting at any depth.
    # The list base 0xC0 is what distinguishes lists from strings on the wire.
    #
    # Examples:
    #
    #   []                ->  c0                                    (empty list)
    #   [b"a", b"b"]      ->  c2 61 62                              (short list, payload "a" "b")
    #   [b"dog", b"god"]  ->  c8 83 64 6f 67 83 67 6f 64            (two short strings inside)
    if isinstance(item, list):
        payload = b"".join(encode_rlp(element) for element in item)
        return _with_length_prefix(payload, base=LIST_BASE)

    raise TypeError(f"Cannot RLP encode type: {type(item).__name__}")


def _with_length_prefix(payload: bytes, base: int) -> bytes:
    """
    Wrap a payload with an RLP length prefix.

    Args:
        payload: Already-encoded body to wrap.
        base: 0x80 for strings, 0xC0 for lists.

    Returns:
        Prefix byte, optional length bytes, then the payload.
    """
    length = len(payload)

    # Short form (payload of 0 to 55 bytes).
    #
    # The prefix byte alone carries the length.
    # No separate length field is needed.
    #
    # Example: base = 0x80, payload = b"dog" (length 3)
    #
    #   prefix  =  0x80 + 3  =  0x83
    #   output  =  83 64 6f 67     (prefix, then "dog")
    if length <= SHORT_FORM_MAX:
        return bytes([base + length]) + payload

    # Long form (payload of 56 bytes or more).
    #
    # The length itself is written as a minimal big-endian field.
    # The prefix byte encodes how many bytes that field occupies.
    #
    # For a payload of N bytes:
    #
    #   - N.bit_length()                  1-indexed position of the highest set bit of N.
    #   - math.ceil(bit_length / 8)       minimal byte count needed to hold N.
    #   - base + 55 + that byte count     prefix byte for this long encoding.
    #
    # The +55 lifts the prefix above the short range.
    # The byte count is what differentiates each long prefix value.
    #
    # Example: base = 0x80, payload of length 1024
    #
    #   bit_length(1024)              =  11
    #   math.ceil(11 / 8)             =  2
    #   length_bytes                  =  04 00          (1024 big-endian, two bytes)
    #   prefix                        =  0x80 + 55 + 2  =  0xB9
    #   output                        =  B9 04 00 [1024 bytes of payload]
    length_bytes = length.to_bytes(math.ceil(length.bit_length() / 8), "big")
    return bytes([base + SHORT_FORM_MAX + len(length_bytes)]) + length_bytes + payload


def decode_rlp(data: bytes) -> RLPItem:
    """
    Decode a single RLP item from the full input.

    Args:
        data: RLP-encoded bytes containing exactly one top-level item.

    Returns:
        The decoded byte string or list.

    Raises:
        RLPDecodingError: If the input is empty, truncated, has trailing bytes, or is non-canonical.
    """
    if len(data) == 0:
        raise RLPDecodingError("Empty RLP data")

    item, consumed = _decode_item(data, 0)

    # Reject trailing data so each input maps to exactly one item.
    if consumed != len(data):
        raise RLPDecodingError(f"Trailing data: decoded {consumed} of {len(data)} bytes")

    return item


def decode_rlp_list(data: bytes) -> list[bytes]:
    """
    Decode an RLP list of byte strings, rejecting nested lists.

    Used by callers that expect a flat record such as ENR.

    Args:
        data: RLP-encoded bytes that must decode to a list of byte strings.

    Returns:
        The decoded byte strings in order.

    Raises:
        RLPDecodingError: If the input is not a flat list of byte strings.
    """
    item = decode_rlp(data)

    # Top-level must be a list, not a bare byte string.
    if not isinstance(item, list):
        raise RLPDecodingError("Expected RLP list")

    # Validate every element while building the narrowed result.
    #
    # Each iteration proves the element is bytes before appending.
    # The new list carries the precise element type without needing a cast.
    result: list[bytes] = []
    for index, element in enumerate(item):
        if not isinstance(element, bytes):
            raise RLPDecodingError(f"Element {index} is not bytes")
        result.append(element)
    return result


def _decode_item(data: bytes, offset: int) -> tuple[RLPItem, int]:
    """
    Decode one item starting at offset and report how many bytes it consumed.

    The prefix byte selects bare-byte, string, or list dispatch.
    String and list paths share length parsing because the only difference is the base.

    Args:
        data: Full input buffer.
        offset: Position of this item's prefix byte.

    Returns:
        A pair of decoded item and absolute offset of the next byte.

    Raises:
        RLPDecodingError: On truncation, non-canonical length, or non-minimal length bytes.
    """
    # The caller guarantees the offset is within bounds.
    #
    # Top-level entry rejects empty input before any recursion.
    # Recursive entry only fires while the cursor lies inside the parent list payload.
    # The length helper bounds every payload by the buffer length.
    prefix = data[offset]

    # Bare byte: prefix below 0x80 is the entire payload.
    #
    # Example: data = 7f, offset = 0
    #
    #   prefix          =  0x7f         (below 0x80, no length field)
    #   item            =  b"\x7f"
    #   next offset     =  1
    if prefix < STRING_BASE:
        return data[offset : offset + 1], offset + 1

    # String or list dispatch by prefix family.
    #
    # The string range ends at 0xC0 (exclusive) and the list range starts there.
    # The shared length helper resolves payload bounds for either family.
    base = STRING_BASE if prefix < LIST_BASE else LIST_BASE
    payload_start, payload_end = _decode_length(data, offset, base)

    # String branch: payload bytes are the decoded value.
    #
    # Example: data = 83 64 6f 67, offset = 0
    #
    #   prefix          =  0x83          (0x80 + 3, short string of length 3)
    #   payload range   =  [1, 4)
    #   item            =  b"dog"
    #   next offset     =  4
    if base == STRING_BASE:
        return data[payload_start:payload_end], payload_end

    # List branch: drain items from the bounded payload range.
    #
    # The cursor advances by each child item's consumed bytes.
    # It must land exactly on the payload end after the final item.
    # A mismatch means an inner item declared a length that overflowed the list boundary.
    #
    # Example: data = c8 83 64 6f 67 83 67 6f 64, offset = 0
    #
    #   prefix          =  0xc8          (0xc0 + 8, short list of 8 payload bytes)
    #   payload range   =  [1, 9)
    #   cursor walk     =  1 -> 5 -> 9   (two short strings consumed in turn)
    #   items           =  [b"dog", b"god"]
    items: list[RLPItem] = []
    cursor = payload_start
    while cursor < payload_end:
        inner, cursor = _decode_item(data, cursor)
        items.append(inner)
    if cursor != payload_end:
        raise RLPDecodingError("List payload length mismatch")
    return items, payload_end


def _decode_length(data: bytes, offset: int, base: int) -> tuple[int, int]:
    """
    Resolve the payload range for a string or list prefix.

    # Why canonicalization checks

    RLP must have one canonical encoding per value to be hash-deterministic.
    Two rules enforce this:

    - Length bytes themselves must be minimal, so a leading zero in a multi-byte length is invalid.
    - A payload short enough for the short form must not appear in the long form.

    Both rules are consensus-critical for ENR.

    Args:
        data: Full input buffer.
        offset: Position of the prefix byte.
        base: 0x80 for strings, 0xC0 for lists.

    Returns:
        Start and end offsets of the payload within the buffer.

    Raises:
        RLPDecodingError: On truncation or non-canonical length encoding.
    """
    prefix = data[offset]
    short_length = prefix - base

    # Phase 1: short form (prefix in base..base+55).
    #
    # The low bits of the prefix carry the payload length directly.
    # The payload starts right after the prefix byte.
    #
    # Example: data = 83 64 6f 67, offset = 0, base = 0x80
    #
    #   prefix          =  0x83
    #   short_length    =  0x83 - 0x80  =  3
    #   payload range   =  [1, 4)       (bytes 64 6f 67 = "dog")
    if short_length <= SHORT_FORM_MAX:
        start = offset + 1
        end = start + short_length
        if end > len(data):
            raise RLPDecodingError(f"Data too short: need {end}, have {len(data)}")
        return start, end

    # Phase 2: long form (prefix in base+56..base+63).
    #
    # The low bits of the prefix carry the length-of-length.
    # The next length-of-length bytes form a big-endian length field.
    # The payload starts right after the length field.
    #
    # Example: data = b9 04 00 [1024 payload bytes], offset = 0, base = 0x80
    #
    #   prefix          =  0xb9
    #   short_length    =  0xb9 - 0x80  =  57
    #   len_of_len      =  57 - 55      =  2
    #   length          =  int(04 00, big)  =  1024
    #   payload range   =  [3, 1027)
    len_of_len = short_length - SHORT_FORM_MAX
    length_start = offset + 1
    length_end = length_start + len_of_len
    if length_end > len(data):
        raise RLPDecodingError(f"Data too short: need {length_end}, have {len(data)}")

    # Canonicalization check: leading-zero length bytes are forbidden.
    #
    # A leading zero would give the same length value with a shorter encoding.
    # Allowing both forms would produce two valid encodings for the same item.
    #
    # Example: input b9 00 38 [56 bytes] is rejected.
    # The shorter equivalent b8 38 [56 bytes] is the canonical form.
    if len_of_len > 1 and data[length_start] == 0:
        raise RLPDecodingError("Non-canonical: leading zeros in length encoding")

    length = int.from_bytes(data[length_start:length_end], "big")

    # Canonicalization check: payloads that fit the short form must use it.
    #
    # Any length up to 55 has a short-form prefix between base and base+55.
    # Wrapping such a payload in long form would be a second valid encoding.
    #
    # Example: input b8 37 [55 "a" bytes] is rejected.
    # The shorter equivalent b7 [55 "a" bytes] is the canonical form.
    if length <= SHORT_FORM_MAX:
        kind = "string" if base == STRING_BASE else "list"
        raise RLPDecodingError(f"Non-canonical: long {kind} encoding for short {kind}")

    start = length_end
    end = start + length
    if end > len(data):
        raise RLPDecodingError(f"Data too short: need {end}, have {len(data)}")
    return start, end
