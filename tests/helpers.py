from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path


def version(major: int, minor: int = 0, patch: int = 0) -> int:
    return (major << 16) | (minor << 8) | patch


def minimal_macho(*, crypt_id: int = 0) -> bytes:
    segment = struct.pack(
        "<II16sIIIIiiII",
        0x1,
        56,
        b"__TEXT".ljust(16, b"\0"),
        0,
        0,
        0,
        0,
        7,
        5,
        0,
        0,
    )
    library_path = b"/System/Library/Frameworks/UIKit.framework/UIKit\0"
    library_size = (24 + len(library_path) + 3) & ~3
    library = (
        struct.pack("<IIIIII", 0xC, library_size, 24, 0, version(1), version(1))
        + library_path
    ).ljust(library_size, b"\0")
    deployment = struct.pack("<IIII", 0x25, 16, version(2, 1), version(2, 1))
    encryption = struct.pack("<IIIII", 0x21, 20, 0x1000, 0x2000, crypt_id)
    commands = segment + library + deployment + encryption
    header = struct.pack("<IiiIIII", 0xFEEDFACE, 12, 6, 2, 4, len(commands), 0)
    return header + commands


def create_test_ipa(path: Path, *, executable: bytes | None = None) -> Path:
    info = {
        "CFBundleDisplayName": "Fixture App",
        "CFBundleExecutable": "Fixture",
        "CFBundleIdentifier": "test.ipalift.fixture",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1.0",
        "MinimumOSVersion": "2.1",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Payload/Fixture.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY, sort_keys=True))
        archive.writestr("Payload/Fixture.app/Fixture", executable or minimal_macho())
        archive.writestr("Payload/Fixture.app/image.png", b"fixture-image")
        archive.writestr("Payload/Fixture.app/config.xml", b"<fixture />")
    return path

