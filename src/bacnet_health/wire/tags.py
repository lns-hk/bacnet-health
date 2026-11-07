"""BACnet tag encoding (ASHRAE 135 clause 20.2).

Decoded Python representations:

=================== ===================================================================
null                ``None``
boolean             ``bool``
unsigned/enumerated ``int``
signed              ``int``
real/double         ``float``
octet-string        ``bytes``
character-string    ``str`` (UTF-8, UCS-2, UCS-4, ISO-8859-1; other charsets -> ``repr`` of the raw bytes)
bit-string          ``list[bool]`` (bit 0 first)
date                ``{"year", "month", "day", "weekday"}``; 255 ("unspecified") -> ``None``
time                ``{"hour", "minute", "second", "hundredths"}``; 255 -> ``None``
object-identifier   ``{"type": "device", "instance": 5}`` (unknown types -> ``"unknown-N"``)
=================== ===================================================================

For encoding, plain ``int`` is encoded as unsigned (or signed if negative). Use the marker types
:class:`Enumerated`, :class:`Signed`, :class:`Double` and :class:`Raw` (pre-encoded tag bytes) to choose otherwise.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from bacnet_health.wire.constants import ApplicationTag, ObjectType, name_of, value_of
from bacnet_health.wire.errors import DecodeError

# ---------------------------------------------------------------------------------------------------------------------
# Marker types for encoding
# ---------------------------------------------------------------------------------------------------------------------


class Enumerated(int):
    """Encode this int as ENUMERATED rather than UNSIGNED."""


class Signed(int):
    """Encode this int as SIGNED even when non-negative."""


class Double(float):
    """Encode this float as DOUBLE rather than REAL."""


class Raw(bytes):
    """Already-encoded tag bytes, inserted verbatim."""


# ---------------------------------------------------------------------------------------------------------------------
# Tag header
# ---------------------------------------------------------------------------------------------------------------------


@dataclass
class Tag:
    number: int
    context: bool
    lvt: int  # length (primitive), boolean value (application boolean), or 6/7 for opening/closing
    opening: bool = False
    closing: bool = False
    start: int = 0  # offset of the content octets
    end: int = 0  # offset just past the content octets

    @property
    def length(self) -> int:
        return self.end - self.start


def decode_tag(data: bytes, offset: int, limit: int | None = None) -> Tag:
    """Decode the tag header at ``offset`` (not reading past ``limit``). ``Tag.end`` is where the next tag starts."""
    n = len(data) if limit is None else min(limit, len(data))
    if offset >= n:
        raise DecodeError("tag: unexpected end of data")
    b = data[offset]
    pos = offset + 1
    number = b >> 4
    context = bool(b & 0x08)
    lvt = b & 0x07
    if number == 0x0F:
        if pos >= n:
            raise DecodeError("tag: truncated extended tag number")
        number = data[pos]
        pos += 1
    if context and lvt in (6, 7):
        return Tag(number, True, lvt, opening=lvt == 6, closing=lvt == 7, start=pos, end=pos)
    if not context and number == ApplicationTag.BOOLEAN:
        if lvt > 1:
            raise DecodeError("tag: application boolean value > 1")
        return Tag(number, False, lvt, start=pos, end=pos)
    if not context and lvt in (6, 7):
        raise DecodeError("tag: opening/closing tag must be context-specific")
    length = lvt
    if lvt == 5:
        if pos >= n:
            raise DecodeError("tag: truncated extended length")
        length = data[pos]
        pos += 1
        if length == 254:
            if pos + 2 > n:
                raise DecodeError("tag: truncated 2-octet length")
            length = int.from_bytes(data[pos : pos + 2], "big")
            pos += 2
        elif length == 255:
            if pos + 4 > n:
                raise DecodeError("tag: truncated 4-octet length")
            length = int.from_bytes(data[pos : pos + 4], "big")
            pos += 4
    if pos + length > n:
        raise DecodeError(f"tag: content length {length} exceeds data")
    return Tag(number, context, lvt, start=pos, end=pos + length)


def encode_tag(number: int, context: bool, length: int) -> bytes:
    """Encode a primitive tag header for ``length`` content octets."""
    if not 0 <= number <= 254:
        raise ValueError("tag number out of range")
    first = (min(number, 15) << 4) | (0x08 if context else 0)
    ext = bytes([number]) if number >= 15 else b""
    if length < 5:
        return bytes([first | length]) + ext
    first |= 5
    if length < 254:
        return bytes([first]) + ext + bytes([length])
    if length < 65536:
        return bytes([first]) + ext + b"\xfe" + length.to_bytes(2, "big")
    return bytes([first]) + ext + b"\xff" + length.to_bytes(4, "big")


def opening_tag(number: int) -> bytes:
    return _pair_tag(number, 6)


def closing_tag(number: int) -> bytes:
    return _pair_tag(number, 7)


def _pair_tag(number: int, lvt: int) -> bytes:
    if number >= 15:
        return bytes([0xF8 | lvt, number])
    return bytes([(number << 4) | 0x08 | lvt])


# ---------------------------------------------------------------------------------------------------------------------
# Primitive content encode / decode
# ---------------------------------------------------------------------------------------------------------------------


def _uint_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned value must be >= 0")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _sint_bytes(value: int) -> bytes:
    length = 1
    while not -(1 << (8 * length - 1)) <= value < (1 << (8 * length - 1)):
        length += 1
    return value.to_bytes(length, "big", signed=True)


def objid_value(obj_type: int | str, instance: int) -> int:
    t = value_of(ObjectType, obj_type)
    if not 0 <= t <= 0x3FF or not 0 <= instance <= 0x3FFFFF:
        raise ValueError("object identifier out of range")
    return (t << 22) | instance


def objid_dict(raw: int) -> dict[str, Any]:
    return {"type": name_of(ObjectType, raw >> 22), "instance": raw & 0x3FFFFF}


def _date_bytes(d: dict[str, Any]) -> bytes:
    year = d.get("year")
    return bytes(
        [
            255 if year is None else year - 1900,
            _b255(d.get("month")),
            _b255(d.get("day")),
            _b255(d.get("weekday")),
        ]
    )


def _time_bytes(t: dict[str, Any]) -> bytes:
    return bytes(_b255(t.get(k)) for k in ("hour", "minute", "second", "hundredths"))


def _b255(v: int | None) -> int:
    return 255 if v is None else int(v)


def _n255(v: int) -> int | None:
    return None if v == 255 else v


def decode_primitive(app_tag: int, content: bytes, lvt: int = 0) -> Any:
    """Decode primitive content octets as application type ``app_tag`` (also used for context tags)."""
    n = len(content)
    if app_tag == ApplicationTag.NULL:
        if n:
            raise DecodeError("null with content")
        return None
    if app_tag == ApplicationTag.BOOLEAN:
        # Application booleans carry the value in the LVT; context booleans in one content octet.
        if n == 0:
            return bool(lvt)
        if n != 1 or content[0] > 1:
            raise DecodeError("bad boolean")
        return bool(content[0])
    if app_tag in (ApplicationTag.UNSIGNED, ApplicationTag.ENUMERATED):
        if not 1 <= n <= 8:
            raise DecodeError("bad unsigned/enumerated length")
        return int.from_bytes(content, "big")
    if app_tag == ApplicationTag.SIGNED:
        if not 1 <= n <= 8:
            raise DecodeError("bad signed length")
        return int.from_bytes(content, "big", signed=True)
    if app_tag == ApplicationTag.REAL:
        if n != 4:
            raise DecodeError("real must be 4 octets")
        return struct.unpack(">f", content)[0]
    if app_tag == ApplicationTag.DOUBLE:
        if n != 8:
            raise DecodeError("double must be 8 octets")
        return struct.unpack(">d", content)[0]
    if app_tag == ApplicationTag.OCTET_STRING:
        return bytes(content)
    if app_tag == ApplicationTag.CHARACTER_STRING:
        return _decode_charstring(content)
    if app_tag == ApplicationTag.BIT_STRING:
        if n == 0:
            raise DecodeError("bit-string without unused-bits octet")
        unused = content[0]
        if unused > 7 or (n == 1 and unused):
            raise DecodeError("bad bit-string unused-bits")
        bits = [bool(byte & (0x80 >> i)) for byte in content[1:] for i in range(8)]
        return bits[: len(bits) - unused] if unused else bits
    if app_tag == ApplicationTag.DATE:
        if n != 4:
            raise DecodeError("date must be 4 octets")
        y, m, d, w = content
        return {"year": None if y == 255 else 1900 + y, "month": _n255(m), "day": _n255(d), "weekday": _n255(w)}
    if app_tag == ApplicationTag.TIME:
        if n != 4:
            raise DecodeError("time must be 4 octets")
        h, mi, s, hu = content
        return {"hour": _n255(h), "minute": _n255(mi), "second": _n255(s), "hundredths": _n255(hu)}
    if app_tag == ApplicationTag.OBJECT_IDENTIFIER:
        if n != 4:
            raise DecodeError("object-identifier must be 4 octets")
        return objid_dict(int.from_bytes(content, "big"))
    raise DecodeError(f"reserved application tag {app_tag}")


def _decode_charstring(content: bytes) -> str:
    if not content:
        raise DecodeError("character-string without charset octet")
    charset, raw = content[0], bytes(content[1:])
    codec = {0: "utf-8", 3: "utf-32-be", 4: "utf-16-be", 5: "latin-1"}.get(charset)
    if codec is None:
        return repr(raw)
    return raw.decode(codec, errors="replace")


def _encode_charstring(s: str) -> bytes:
    return b"\x00" + s.encode("utf-8")


def _encode_bitstring(bits: list[bool]) -> bytes:
    unused = (8 - len(bits) % 8) % 8
    out = bytearray([unused])
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i : i + 8]):
            if bit:
                byte |= 0x80 >> j
        out.append(byte)
    return bytes(out)


def _classify(value: Any) -> tuple[int, bytes, int]:
    """Return (application tag, content octets, lvt override for boolean) for a Python value."""
    if value is None:
        return ApplicationTag.NULL, b"", 0
    if isinstance(value, bool):
        return ApplicationTag.BOOLEAN, b"", int(value)
    if isinstance(value, Enumerated):
        return ApplicationTag.ENUMERATED, _uint_bytes(int(value)), -1
    if isinstance(value, Signed):
        return ApplicationTag.SIGNED, _sint_bytes(int(value)), -1
    if isinstance(value, int):
        if value < 0:
            return ApplicationTag.SIGNED, _sint_bytes(value), -1
        return ApplicationTag.UNSIGNED, _uint_bytes(value), -1
    if isinstance(value, Double):
        return ApplicationTag.DOUBLE, struct.pack(">d", value), -1
    if isinstance(value, float):
        return ApplicationTag.REAL, struct.pack(">f", value), -1
    if isinstance(value, (bytes, bytearray)):
        return ApplicationTag.OCTET_STRING, bytes(value), -1
    if isinstance(value, str):
        return ApplicationTag.CHARACTER_STRING, _encode_charstring(value), -1
    if isinstance(value, dict):
        if "instance" in value:
            raw = objid_value(value["type"], value["instance"])
            return ApplicationTag.OBJECT_IDENTIFIER, raw.to_bytes(4, "big"), -1
        if "year" in value or "weekday" in value:
            return ApplicationTag.DATE, _date_bytes(value), -1
        if "hour" in value:
            return ApplicationTag.TIME, _time_bytes(value), -1
    raise ValueError(f"cannot encode value of type {type(value).__name__}")


def encode_application(value: Any) -> bytes:
    """Encode one Python value as an application-tagged primitive (see module docstring)."""
    if isinstance(value, Raw):
        return bytes(value)
    if isinstance(value, list) and value and all(isinstance(b, bool) for b in value):
        return _tagged(ApplicationTag.BIT_STRING, _encode_bitstring(value))
    tag, content, lvt = _classify(value)
    if tag == ApplicationTag.BOOLEAN:
        return bytes([(ApplicationTag.BOOLEAN << 4) | lvt])
    return _tagged(tag, content)


def _tagged(tag: int, content: bytes) -> bytes:
    return encode_tag(tag, False, len(content)) + content


def encode_context(number: int, value: Any) -> bytes:
    """Encode a Python value as a context-tagged primitive with tag ``number``."""
    if isinstance(value, list) and all(isinstance(b, bool) for b in value):
        content = _encode_bitstring(value)
    else:
        tag, content, lvt = _classify(value)
        if tag == ApplicationTag.BOOLEAN:
            content = bytes([lvt])
    return encode_tag(number, True, len(content)) + content


def encode_value(value: Any) -> bytes:
    """Encode a property value: a scalar, or a list (array/list) of scalars. Bit-strings are ``list[bool]``.

    To encode an empty bit-string pass ``Raw(b"\\x81\\x00")``.
    """
    if isinstance(value, list) and not (value and all(isinstance(b, bool) for b in value)):
        return b"".join(encode_application(v) for v in value)
    return encode_application(value)


# ---------------------------------------------------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------------------------------------------------


def decode_any_application(data: bytes, offset: int = 0) -> tuple[Any, int]:
    """Decode one application-tagged value at ``offset``; return ``(value, next_offset)``."""
    tag = decode_tag(data, offset)
    if tag.context:
        raise DecodeError(f"expected application tag, got context tag {tag.number}")
    return decode_primitive(tag.number, data[tag.start : tag.end], tag.lvt), tag.end


def decode_values(data: bytes, start: int, end: int) -> Any:
    """Decode the content between an opening and closing tag (a property value).

    One application value -> that value; several -> list; nothing -> empty list. Constructed (context-tagged) data is
    decoded generically into ``{"context": n, "value": ...}`` (primitive -> hex string) so nothing is lost.
    """
    items = _decode_sequence(data, start, end, 0)
    return items[0] if len(items) == 1 else items


MAX_NESTING = 16


def _decode_sequence(data: bytes, start: int, end: int, depth: int) -> list[Any]:
    if depth > MAX_NESTING:
        raise DecodeError("constructed value nested too deeply")
    items: list[Any] = []
    pos = start
    while pos < end:
        tag = decode_tag(data, pos, end)
        if tag.closing:
            raise DecodeError("unexpected closing tag")
        if tag.opening:
            inner_end = find_closing(data, tag.end, tag.number, end)
            inner = _decode_sequence(data, tag.end, inner_end, depth + 1)
            items.append({"context": tag.number, "value": inner[0] if len(inner) == 1 else inner})
            pos = decode_tag(data, inner_end, end).end
        elif tag.context:
            items.append({"context": tag.number, "hex": data[tag.start : tag.end].hex()})
            pos = tag.end
        else:
            items.append(decode_primitive(tag.number, data[tag.start : tag.end], tag.lvt))
            pos = tag.end
    return items


def find_closing(data: bytes, offset: int, number: int, limit: int | None = None) -> int:
    """Return the offset of the closing tag matching an opening tag ``number`` whose content starts at ``offset``."""
    depth = 0
    pos = offset
    while True:
        tag = decode_tag(data, pos, limit)
        if tag.opening:
            depth += 1
        elif tag.closing:
            if depth == 0:
                if tag.number != number:
                    raise DecodeError("mismatched closing tag")
                return pos
            depth -= 1
        pos = tag.end


class TagReader:
    """Sequential reader over a service payload with bounds-checked typed accessors."""

    def __init__(self, data: bytes, offset: int = 0, end: int | None = None) -> None:
        self.data = bytes(data)
        self.pos = offset
        self.end = len(self.data) if end is None else end

    def at_end(self) -> bool:
        return self.pos >= self.end

    def peek(self) -> Tag | None:
        if self.at_end():
            return None
        return decode_tag(self.data, self.pos, self.end)

    def peek_context(self, number: int) -> bool:
        tag = self.peek()
        return tag is not None and tag.context and tag.number == number and not tag.closing and not tag.opening

    def peek_opening(self, number: int) -> bool:
        tag = self.peek()
        return tag is not None and tag.opening and tag.number == number

    def peek_closing(self, number: int) -> bool:
        tag = self.peek()
        return tag is not None and tag.closing and tag.number == number

    def application(self, expected: int | None = None) -> Any:
        tag = self._next()
        if tag.context:
            raise DecodeError(f"expected application tag, got context {tag.number}")
        if expected is not None and tag.number != expected:
            raise DecodeError(f"expected application tag {expected}, got {tag.number}")
        return decode_primitive(tag.number, self.data[tag.start : tag.end], tag.lvt)

    def context(self, number: int, app_type: int) -> Any:
        tag = self._next()
        if not tag.context or tag.opening or tag.closing or tag.number != number:
            raise DecodeError(f"expected context tag {number}")
        return decode_primitive(app_type, self.data[tag.start : tag.end], tag.lvt)

    def optional_context(self, number: int, app_type: int) -> Any:
        return self.context(number, app_type) if self.peek_context(number) else None

    def opening(self, number: int) -> None:
        tag = self._next()
        if not tag.opening or tag.number != number:
            raise DecodeError(f"expected opening tag {number}")

    def closing(self, number: int) -> None:
        tag = self._next()
        if not tag.closing or tag.number != number:
            raise DecodeError(f"expected closing tag {number}")

    def enclosed(self, number: int) -> tuple[int, int]:
        """Consume ``[number] ... [/number]``; return (start, end) offsets of the content."""
        self.opening(number)
        start = self.pos
        end = find_closing(self.data, start, number, self.end)
        self.pos = decode_tag(self.data, end, self.end).end
        return start, end

    def skip(self) -> None:
        tag = self._next()
        if tag.opening:
            end = find_closing(self.data, self.pos, tag.number, self.end)
            self.pos = decode_tag(self.data, end, self.end).end

    def expect_end(self) -> None:
        if not self.at_end():
            raise DecodeError("unexpected trailing data")

    def _next(self) -> Tag:
        if self.at_end():
            raise DecodeError("unexpected end of payload")
        tag = decode_tag(self.data, self.pos, self.end)
        self.pos = tag.end
        return tag
