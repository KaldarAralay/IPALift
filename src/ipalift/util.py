"""Small deterministic I/O and normalization helpers."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any, BinaryIO, Iterator


SCHEMA_VERSION = 1
COPY_CHUNK_SIZE = 1024 * 1024


def sha256_stream(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        block = stream.read(COPY_CHUNK_SIZE)
        if not block:
            break
        digest.update(block)
        size += len(block)
    return digest.hexdigest(), size


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return sha256_stream(stream)[0]


def iter_file_blocks(stream: BinaryIO) -> Iterator[bytes]:
    while True:
        block = stream.read(COPY_CHUNK_SIZE)
        if not block:
            return
        yield block


def normalize_json(value: Any) -> Any:
    """Convert plist/Python values into stable JSON-compatible values."""
    if isinstance(value, dict):
        return {str(key): normalize_json(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [normalize_json(item) for item in value]
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dt.datetime):
        normalized = value
        if normalized.tzinfo is None:
            normalized = normalized.replace(tzinfo=dt.timezone.utc)
        return normalized.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Path):
        return value.as_posix()
    return value


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(normalize_json(value), indent=2, sort_keys=True, ensure_ascii=False)
    write_text_atomic(path, rendered + "\n")


def write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def report_envelope(artifact: str, facts: Any, *, hypotheses: list | None = None, errors: list | None = None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact": artifact,
        "facts": facts,
        "hypotheses": hypotheses or [],
        "errors": errors or [],
    }

