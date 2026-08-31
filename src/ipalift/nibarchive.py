"""Bounded parser for compiled UIKit ``NIBArchive`` object graphs."""

from __future__ import annotations

import math
import plistlib
import struct
from dataclasses import dataclass
from typing import Any


MAGIC = b"NIBArchive"
HEADER_SIZE = 50
MAX_TABLE_ENTRIES = 200_000
MAX_STRING_BYTES = 16 * 1024 * 1024


class NIBArchiveError(ValueError):
    """A compiled UIKit NIB archive is malformed or unsupported."""


@dataclass(frozen=True)
class DecodedNIBArchive:
    document: dict[str, Any]
    format_version: int
    coder_version: int
    object_count: int
    key_count: int
    value_count: int
    class_count: int
    trailing_byte_count: int


@dataclass(frozen=True)
class _ObjectRecord:
    class_index: int
    value_start: int
    value_count: int


def _vint32(data: bytes, offset: int, limit: int, context: str) -> tuple[int, int]:
    value = 0
    for position in range(5):
        if offset >= limit:
            raise NIBArchiveError(f"Truncated VInt32 while reading {context}")
        current = data[offset]
        offset += 1
        if position == 4 and current & 0x70:
            raise NIBArchiveError(f"VInt32 overflow while reading {context}")
        value |= (current & 0x7F) << (position * 7)
        if current & 0x80:
            return value, offset
    raise NIBArchiveError(f"Unterminated VInt32 while reading {context}")


def _fixed(data: bytes, offset: int, size: int, limit: int, context: str) -> tuple[bytes, int]:
    end = offset + size
    if size < 0 or end < offset or end > limit:
        raise NIBArchiveError(f"Truncated data while reading {context}")
    return data[offset:end], end


def _text(data: bytes, context: str, *, nul_terminated: bool = False) -> str:
    if len(data) > MAX_STRING_BYTES:
        raise NIBArchiveError(f"{context} is too large")
    if nul_terminated:
        if not data or data[-1] != 0:
            raise NIBArchiveError(f"{context} is missing its NUL terminator")
        data = data[:-1]
        if b"\x00" in data:
            raise NIBArchiveError(f"{context} contains an embedded NUL")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NIBArchiveError(f"{context} is not valid UTF-8") from exc


def _string_payload(data: bytes) -> str | None:
    raw = data[:-1] if data.endswith(b"\x00") else data
    for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            value = raw.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if value and "\x00" not in value and all(character.isprintable() or character in "\r\n\t" for character in value):
            return value
    return "" if not raw else None


def _insert_field(fields: dict[str, Any], key: str, value: Any) -> None:
    if key not in fields:
        fields[key] = value
        return
    previous = fields[key]
    if isinstance(previous, list):
        previous.append(value)
    else:
        fields[key] = [previous, value]


def _decode_value(
    data: bytes,
    offset: int,
    limit: int,
    value_type: int,
    object_count: int,
    context: str,
) -> tuple[Any, int]:
    fixed_sizes = {0: 1, 1: 2, 2: 4, 3: 8, 6: 4, 7: 8, 10: 4}
    if value_type in fixed_sizes:
        raw, offset = _fixed(data, offset, fixed_sizes[value_type], limit, context)
        if value_type in {0, 1, 2, 3}:
            return int.from_bytes(raw, "little", signed=True), offset
        if value_type == 6:
            value = struct.unpack("<f", raw)[0]
        elif value_type == 7:
            value = struct.unpack("<d", raw)[0]
        else:
            index = int.from_bytes(raw, "little")
            if index >= object_count:
                raise NIBArchiveError(f"Object reference {index} is out of range while reading {context}")
            return plistlib.UID(index), offset
        if not math.isfinite(value):
            raise NIBArchiveError(f"Non-finite floating-point value while reading {context}")
        return value, offset
    if value_type == 4:
        return False, offset
    if value_type == 5:
        return True, offset
    if value_type == 8:
        length, offset = _vint32(data, offset, limit, f"{context} byte length")
        return _fixed(data, offset, length, limit, context)
    if value_type == 9:
        return None, offset
    raise NIBArchiveError(f"Unsupported NIB coder value type {value_type} while reading {context}")


def decode_nibarchive(data: bytes) -> DecodedNIBArchive:
    """Decode a version-1 UIKit NIB archive into an NSKeyedArchiver-like graph."""
    if len(data) < HEADER_SIZE or data[:10] != MAGIC:
        raise NIBArchiveError("Compiled NIB archive has an invalid or truncated header")
    (
        format_version,
        coder_version,
        object_count,
        object_offset,
        key_count,
        key_offset,
        value_count,
        value_offset,
        class_count,
        class_offset,
    ) = struct.unpack_from("<10I", data, 10)
    if format_version != 1:
        raise NIBArchiveError(f"Unsupported NIB archive format version {format_version}")
    counts = {
        "object": object_count,
        "key": key_count,
        "value": value_count,
        "class": class_count,
    }
    for name, count in counts.items():
        if count > MAX_TABLE_ENTRIES:
            raise NIBArchiveError(
                f"Compiled NIB archive contains {count} {name} records; limit is {MAX_TABLE_ENTRIES}"
            )
    if object_count and not class_count:
        raise NIBArchiveError("Compiled NIB archive has objects but no class table")
    offsets = (object_offset, key_offset, value_offset, class_offset, len(data))
    if object_offset != HEADER_SIZE:
        raise NIBArchiveError(f"Compiled NIB object table begins at {object_offset}; expected {HEADER_SIZE}")
    if any(left > right for left, right in zip(offsets, offsets[1:])):
        raise NIBArchiveError("Compiled NIB table offsets are not monotonic or exceed the file size")

    objects: list[_ObjectRecord] = []
    offset = object_offset
    for index in range(object_count):
        class_index, offset = _vint32(data, offset, key_offset, f"object {index} class")
        value_start, offset = _vint32(data, offset, key_offset, f"object {index} value start")
        item_count, offset = _vint32(data, offset, key_offset, f"object {index} value count")
        if class_index >= class_count:
            raise NIBArchiveError(f"Object {index} class index {class_index} is out of range")
        if value_start > value_count or item_count > value_count - value_start:
            raise NIBArchiveError(f"Object {index} value range is out of bounds")
        objects.append(_ObjectRecord(class_index, value_start, item_count))
    if offset != key_offset:
        raise NIBArchiveError("Compiled NIB object table size does not match its declared key-table offset")

    keys: list[str] = []
    offset = key_offset
    for index in range(key_count):
        length, offset = _vint32(data, offset, value_offset, f"key {index} length")
        raw, offset = _fixed(data, offset, length, value_offset, f"key {index}")
        keys.append(_text(raw, f"key {index}"))
    if offset != value_offset:
        raise NIBArchiveError("Compiled NIB key table size does not match its declared value-table offset")

    values: list[tuple[int, Any]] = []
    offset = value_offset
    for index in range(value_count):
        key_index, offset = _vint32(data, offset, class_offset, f"value {index} key")
        if key_index >= key_count:
            raise NIBArchiveError(f"Value {index} key index {key_index} is out of range")
        raw_type, offset = _fixed(data, offset, 1, class_offset, f"value {index} type")
        value, offset = _decode_value(
            data,
            offset,
            class_offset,
            raw_type[0],
            object_count,
            f"value {index}",
        )
        values.append((key_index, value))
    if offset != class_offset:
        raise NIBArchiveError("Compiled NIB value table size does not match its declared class-table offset")

    class_names: list[str] = []
    offset = class_offset
    for index in range(class_count):
        name_length, offset = _vint32(data, offset, len(data), f"class {index} name length")
        fallback_count, offset = _vint32(data, offset, len(data), f"class {index} fallback count")
        for fallback_position in range(fallback_count):
            raw, offset = _fixed(data, offset, 4, len(data), f"class {index} fallback {fallback_position}")
            fallback_index = int.from_bytes(raw, "little")
            if fallback_index >= class_count:
                raise NIBArchiveError(
                    f"Class {index} fallback index {fallback_index} is out of range"
                )
        raw_name, offset = _fixed(data, offset, name_length, len(data), f"class {index} name")
        name = _text(raw_name, f"class {index} name", nul_terminated=True)
        if not name:
            raise NIBArchiveError(f"Class {index} has an empty name")
        class_names.append(name)

    keyed_objects: list[Any] = []
    for index, record in enumerate(objects):
        class_name = class_names[record.class_index]
        fields: dict[str, Any] = {
            "$class": plistlib.UID(object_count + record.class_index),
        }
        item_values = values[record.value_start:record.value_start + record.value_count]
        for key_index, value in item_values:
            _insert_field(fields, keys[key_index], value)

        empty_values = fields.get("UINibEncoderEmptyKey", [])
        if not isinstance(empty_values, list):
            empty_values = [empty_values]
        if class_name in {"NSArray", "NSMutableArray", "NSSet", "NSMutableSet", "NSOrderedSet"}:
            fields["NS.objects"] = empty_values
        elif class_name in {"NSDictionary", "NSMutableDictionary"}:
            fields["NS.keys"] = empty_values[0::2]
            fields["NS.objects"] = empty_values[1::2]
        elif class_name in {"NSString", "NSMutableString"}:
            candidates = [
                fields.get("NS.string"),
                fields.get("NS.bytes"),
                fields.get("UINibEncoderEmptyKey"),
            ]
            for candidate in candidates:
                if isinstance(candidate, list) and len(candidate) == 1:
                    candidate = candidate[0]
                if isinstance(candidate, bytes):
                    decoded = _string_payload(candidate)
                    if decoded is not None:
                        fields["NS.string"] = decoded
                        break
        keyed_objects.append(fields)

    for class_name in class_names:
        keyed_objects.append({
            "$classname": class_name,
            "$classes": [class_name, "NSObject"],
        })

    document = {
        "$archiver": "UINibDecoder",
        "$version": coder_version,
        "$objects": keyed_objects,
        "$top": {"UINibTopLevelObjectsKey": plistlib.UID(0)} if object_count else {},
    }
    return DecodedNIBArchive(
        document=document,
        format_version=format_version,
        coder_version=coder_version,
        object_count=object_count,
        key_count=key_count,
        value_count=value_count,
        class_count=class_count,
        trailing_byte_count=len(data) - offset,
    )
