#!/usr/bin/env python3
"""Deterministically normalize standard and Apple CgBI PNGs.

Standard PNGs are copied byte-for-byte. CgBI files are decoded from raw DEFLATE,
unfiltered, converted from premultiplied BGRA to RGBA, and emitted as canonical
PNG (filter 0, zlib level 9). Only the recovered 8-bit RGBA case is accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path


ALGORITHM_VERSION = "reconstruction-core-png-normalizer-v1"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("input does not have a PNG signature")
    result: list[tuple[bytes, bytes]] = []
    offset = len(PNG_SIGNATURE)
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        chunk_type = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("PNG chunk exceeds file length")
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"CRC mismatch in {chunk_type.decode('ascii', 'replace')}")
        result.append((chunk_type, payload))
        offset = end
        if chunk_type == b"IEND":
            if offset != len(data):
                raise ValueError("data follows IEND")
            return result
    raise ValueError("PNG does not contain IEND")


def png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + chunk_type
        + payload
        + struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    )


def canonical_zlib_store(data: bytes) -> bytes:
    """Return a portable byte-stable zlib stream using DEFLATE stored blocks."""
    output = bytearray(b"\x78\x01")
    if not data:
        output.extend(b"\x01\x00\x00\xff\xff")
    else:
        cursor = 0
        while cursor < len(data):
            block = data[cursor : cursor + 65535]
            cursor += len(block)
            output.append(1 if cursor == len(data) else 0)
            length = len(block)
            output.extend(struct.pack("<HH", length, length ^ 0xFFFF))
            output.extend(block)
    output.extend(struct.pack(">I", zlib.adler32(data) & 0xFFFFFFFF))
    return bytes(output)


def paeth(left: int, above: int, upper_left: int) -> int:
    prediction = left + above - upper_left
    left_distance = abs(prediction - left)
    above_distance = abs(prediction - above)
    upper_left_distance = abs(prediction - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def unfilter(raw: bytes, width: int, height: int) -> list[bytearray]:
    stride = width * 4
    expected = height * (stride + 1)
    if len(raw) != expected:
        raise ValueError(f"decompressed size {len(raw)} does not match expected {expected}")
    rows: list[bytearray] = []
    cursor = 0
    for _ in range(height):
        filter_type = raw[cursor]
        cursor += 1
        encoded = raw[cursor : cursor + stride]
        cursor += stride
        previous = rows[-1] if rows else bytearray(stride)
        row = bytearray(stride)
        for index, byte in enumerate(encoded):
            left = row[index - 4] if index >= 4 else 0
            above = previous[index]
            upper_left = previous[index - 4] if index >= 4 else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            elif filter_type == 4:
                predictor = paeth(left, above, upper_left)
            else:
                raise ValueError(f"unsupported PNG filter {filter_type}")
            row[index] = (byte + predictor) & 0xFF
        rows.append(row)
    return rows


def cgbi_to_png(parsed: list[tuple[bytes, bytes]]) -> tuple[bytes, int, int]:
    ihdr = next((payload for kind, payload in parsed if kind == b"IHDR"), None)
    if ihdr is None or len(ihdr) != 13:
        raise ValueError("CgBI input lacks a valid IHDR")
    width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", ihdr
    )
    if (bit_depth, color_type, compression, filtering, interlace) != (8, 6, 0, 0, 0):
        raise ValueError("only non-interlaced 8-bit RGBA CgBI PNGs are supported")
    compressed = b"".join(payload for kind, payload in parsed if kind == b"IDAT")
    rows = unfilter(zlib.decompress(compressed, -15), width, height)
    scanlines = bytearray()
    for row in rows:
        scanlines.append(0)
        for offset in range(0, len(row), 4):
            blue, green, red, alpha = row[offset : offset + 4]
            if alpha:
                red = min(255, (red * 255 + alpha // 2) // alpha)
                green = min(255, (green * 255 + alpha // 2) // alpha)
                blue = min(255, (blue * 255 + alpha // 2) // alpha)
            scanlines.extend((red, green, blue, alpha))
    output = (
        PNG_SIGNATURE
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", canonical_zlib_store(bytes(scanlines)))
        + png_chunk(b"IEND", b"")
    )
    return output, width, height


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def convert(source: Path, destination: Path, provenance: str) -> dict[str, object]:
    source_data = source.read_bytes()
    parsed = chunks(source_data)
    ihdr = next((payload for kind, payload in parsed if kind == b"IHDR"), None)
    if ihdr is None or len(ihdr) != 13:
        raise ValueError(f"{source}: missing IHDR")
    width, height = struct.unpack_from(">II", ihdr)
    source_format = "apple-cgbi" if any(kind == b"CgBI" for kind, _ in parsed) else "standard"
    if source_format == "apple-cgbi":
        output_data, width, height = cgbi_to_png(parsed)
    else:
        output_data = source_data
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(output_data)
    return {
        "algorithm_version": ALGORITHM_VERSION,
        "height": height,
        "output": destination.name,
        "output_sha256": sha256(output_data),
        "provenance": provenance,
        "source": source.name,
        "source_format": source_format,
        "source_sha256": sha256(source_data),
        "width": width,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("files", nargs="+")
    arguments = parser.parse_args()

    records = []
    for name in sorted(arguments.files):
        records.append(
            convert(arguments.source_root / name, arguments.output_root / name, arguments.provenance)
        )
    manifest = {
        "algorithm_version": ALGORITHM_VERSION,
        "assets": records,

    }
    arguments.manifest.parent.mkdir(parents=True, exist_ok=True)
    arguments.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
