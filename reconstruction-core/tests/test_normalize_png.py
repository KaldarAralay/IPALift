#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path


SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def fixtures(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    rgba = bytes((0, 12, 34, 56, 255))
    standard = SIGNATURE + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rgba)) + chunk(b"IEND", b"")
    (root / "standard.png").write_bytes(standard)
    compressor = zlib.compressobj(level=9, wbits=-15)
    bgra_premultiplied = bytes((0, 25, 50, 100, 128))
    raw = compressor.compress(bgra_premultiplied) + compressor.flush()
    cgbi = (
        SIGNATURE
        + chunk(b"CgBI", b"")
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", raw)
        + chunk(b"IEND", b"")
    )
    (root / "cgbi.png").write_bytes(cgbi)


def run(tool: Path, source: Path, output: Path) -> dict[str, object]:
    manifest = output / "manifest.json"
    subprocess.run(
        [sys.executable, str(tool), "--source-root", str(source), "--output-root", str(output),
         "--manifest", str(manifest), "--provenance", "synthetic-core-test",
         "standard.png", "cgbi.png"],
        check=True,
    )
    return json.loads(manifest.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    if args.work_root.exists():
        shutil.rmtree(args.work_root)
    source = args.work_root / "source"
    fixtures(source)
    first = run(args.tool, source, args.work_root / "first")
    second = run(args.tool, source, args.work_root / "second")
    assert first == second
    assert first["algorithm_version"] == "reconstruction-core-png-normalizer-v1"
    assert "manual_replacement" not in first
    records = {item["source"]: item for item in first["assets"]}
    assert records["standard.png"]["source_format"] == "standard"
    assert (args.work_root / "first" / "standard.png").read_bytes() == (source / "standard.png").read_bytes()
    assert records["cgbi.png"]["source_format"] == "apple-cgbi"
    assert b"CgBI" not in (args.work_root / "first" / "cgbi.png").read_bytes()
    print("RECONSTRUCTION_CORE_PNG_TESTS_OK standard=identity cgbi=normalized deterministic=2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
