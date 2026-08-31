"""Safe IPA validation, extraction, plist loading, and file inventory."""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import InvalidIPAError
from .util import COPY_CHUNK_SIZE, normalize_json, sha256_file


MAX_ENTRIES = 100_000
MAX_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 2_000
MAX_SYMLINK_TARGET_BYTES = 4_096
DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")

ASSET_CATEGORIES = {
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".tiff": "image",
    ".bmp": "image",
    ".pvr": "texture",
    ".ktx": "texture",
    ".caf": "audio",
    ".wav": "audio",
    ".mp3": "audio",
    ".m4a": "audio",
    ".aac": "audio",
    ".aiff": "audio",
    ".plist": "property_list",
    ".strings": "localization",
    ".stringsdict": "localization",
    ".nib": "interface",
    ".storyboard": "interface",
    ".xib": "interface",
    ".sqlite": "database",
    ".sqlite3": "database",
    ".db": "database",
    ".xml": "data",
    ".json": "data",
    ".csv": "data",
    ".txt": "text",
    ".ttf": "font",
    ".otf": "font",
    ".metallib": "shader",
    ".glsl": "shader",
    ".vert": "shader",
    ".frag": "shader",
}

NON_ASSET_NAMES = {"PkgInfo", "CodeResources", "ResourceRules.plist", "Info.plist", "embedded.mobileprovision"}


@dataclass(frozen=True)
class SourceIdentity:
    path: Path
    size: int
    mtime_ns: int
    sha256: str

    @classmethod
    def capture(cls, path: Path) -> "SourceIdentity":
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        if not resolved.is_file():
            raise InvalidIPAError(f"Input is not a file: {resolved}")
        return cls(resolved, info.st_size, info.st_mtime_ns, sha256_file(resolved))

    def assert_unchanged(self) -> None:
        current = self.path.stat()
        if current.st_size != self.size or current.st_mtime_ns != self.mtime_ns:
            raise InvalidIPAError("The source IPA changed while it was being analyzed")
        if sha256_file(self.path) != self.sha256:
            raise InvalidIPAError("The source IPA content changed while it was being analyzed")


@dataclass
class Bundle:
    archive_root: str
    bundle_name: str
    info_path: str
    executable_name: str
    executable_path: str
    plist: dict[str, Any]


@dataclass
class ExtractionResult:
    source: SourceIdentity
    bundle: Bundle
    files: list[dict[str, Any]]
    assets: list[dict[str, Any]]
    total_uncompressed_bytes: int
    evidence_root: Path
    issues: list[dict[str, Any]]


@dataclass(frozen=True)
class ArchiveMember:
    archive_info: zipfile.ZipInfo
    path: PurePosixPath
    content_info: zipfile.ZipInfo
    link_target: str | None = None
    resolved_archive_path: str | None = None
    link_status: str | None = None


def _safe_member_path(raw_name: str) -> PurePosixPath:
    if not raw_name or "\x00" in raw_name:
        raise InvalidIPAError("The IPA contains an empty or NUL-containing archive path")
    normalized_name = raw_name.replace("\\", "/")
    if normalized_name.startswith("/") or DRIVE_PREFIX.match(normalized_name):
        raise InvalidIPAError(f"The IPA contains an absolute archive path: {raw_name!r}")
    path = PurePosixPath(normalized_name)
    if any(part in ("", ".", "..") for part in path.parts):
        raise InvalidIPAError(f"The IPA contains an unsafe archive path: {raw_name!r}")
    return path


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(unix_mode) == stat.S_IFLNK


def _resolve_relative_link(path: PurePosixPath, target: str) -> PurePosixPath:
    normalized = target.replace("\\", "/")
    if (
        not normalized
        or "\x00" in normalized
        or any(ord(character) < 32 for character in normalized)
        or normalized.startswith("/")
        or DRIVE_PREFIX.match(normalized)
    ):
        raise InvalidIPAError(f"IPA symbolic link has an unsafe target: {path.as_posix()}")
    parts = list(path.parent.parts)
    for part in PurePosixPath(normalized).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise InvalidIPAError(
                    f"IPA symbolic link target escapes the archive root: {path.as_posix()}"
                )
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise InvalidIPAError(
            f"IPA symbolic link target escapes the archive root: {path.as_posix()}"
        )
    return PurePosixPath(*parts)


def _validate_members(archive: zipfile.ZipFile) -> list[ArchiveMember]:
    members = archive.infolist()
    if len(members) > MAX_ENTRIES:
        raise InvalidIPAError(f"IPA has {len(members)} entries; safety limit is {MAX_ENTRIES}")
    total = 0
    seen: set[str] = set()
    indexed: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
    by_name: dict[str, tuple[zipfile.ZipInfo, PurePosixPath]] = {}
    for info in members:
        path = _safe_member_path(info.filename)
        canonical = path.as_posix().rstrip("/")
        if canonical in seen:
            raise InvalidIPAError(f"IPA contains a duplicate archive path: {canonical}")
        seen.add(canonical)
        if info.flag_bits & 0x1:
            raise InvalidIPAError(f"IPA contains an encrypted ZIP entry: {canonical}")
        total += info.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise InvalidIPAError("IPA exceeds the safe uncompressed-size limit")
        if info.compress_size and info.file_size > info.compress_size * MAX_COMPRESSION_RATIO:
            raise InvalidIPAError(f"IPA entry has an unsafe compression ratio: {canonical}")
        indexed.append((info, path))
        by_name[canonical] = (info, path)

    resolved: dict[str, tuple[zipfile.ZipInfo, PurePosixPath, str | None, str | None]] = {}

    def resolve(
        canonical: str,
        trail: tuple[str, ...],
    ) -> tuple[zipfile.ZipInfo, PurePosixPath, str | None, str | None]:
        if canonical in resolved:
            return resolved[canonical]
        if canonical in trail:
            chain = " -> ".join((*trail, canonical))
            raise InvalidIPAError(f"IPA contains a cyclic symbolic link chain: {chain}")
        info, path = by_name[canonical]
        if not _is_symlink(info):
            result = (info, path, None, None)
            resolved[canonical] = result
            return result
        if info.file_size > MAX_SYMLINK_TARGET_BYTES:
            raise InvalidIPAError(
                f"IPA symbolic link target exceeds {MAX_SYMLINK_TARGET_BYTES} bytes: {canonical}"
            )
        try:
            raw_target = archive.read(info)
            target = raw_target.decode("utf-8")
        except (KeyError, OSError, RuntimeError, UnicodeDecodeError) as exc:
            raise InvalidIPAError(f"Cannot read IPA symbolic link target {canonical}: {exc}") from exc
        target_path = _resolve_relative_link(path, target)
        target_name = target_path.as_posix()
        target_member = by_name.get(target_name)
        if target_member is None:
            result = (info, target_path, target, "target_missing")
            resolved[canonical] = result
            return result
        if target_member[0].is_dir():
            raise InvalidIPAError(
                f"IPA symbolic link targets a directory, which is unsupported: {canonical} -> {target_name}"
            )
        content_info, content_path, _nested_target, _nested_status = resolve(
            target_name, (*trail, canonical)
        )
        result = (content_info, content_path, target, "materialized")
        resolved[canonical] = result
        return result

    validated: list[ArchiveMember] = []
    materialized_total = 0
    for info, path in indexed:
        canonical = path.as_posix().rstrip("/")
        content_info, content_path, link_target, link_status = resolve(canonical, ())
        if not info.is_dir():
            materialized_total += content_info.file_size
            if materialized_total > MAX_UNCOMPRESSED_BYTES:
                raise InvalidIPAError("IPA exceeds the safe materialized-size limit")
        validated.append(ArchiveMember(
            archive_info=info,
            path=path,
            content_info=content_info,
            link_target=link_target,
            resolved_archive_path=content_path.as_posix() if link_target is not None else None,
            link_status=link_status,
        ))
    return validated


def _load_plist(
    archive: zipfile.ZipFile,
    path: str,
    content_members: dict[str, zipfile.ZipInfo] | None = None,
) -> dict[str, Any]:
    try:
        value = plistlib.loads(archive.read((content_members or {}).get(path, path)))
    except (KeyError, plistlib.InvalidFileException, ValueError, OSError) as exc:
        raise InvalidIPAError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InvalidIPAError(f"Expected a dictionary in {path}")
    return value


def locate_bundle(
    archive: zipfile.ZipFile,
    member_names: set[str],
    content_members: dict[str, zipfile.ZipInfo] | None = None,
) -> Bundle:
    candidates = sorted(
        name for name in member_names
        if name.startswith("Payload/") and name.count("/") == 2 and name.endswith(".app/Info.plist")
    )
    if not candidates:
        raise InvalidIPAError("IPA does not contain Payload/<name>.app/Info.plist")
    valid: list[Bundle] = []
    for info_path in candidates:
        plist = _load_plist(archive, info_path, content_members)
        executable = plist.get("CFBundleExecutable")
        if not isinstance(executable, str) or not executable.strip():
            continue
        root = info_path.rsplit("/", 1)[0]
        executable_path = f"{root}/{executable}"
        if executable_path not in member_names:
            continue
        valid.append(
            Bundle(
                archive_root=root,
                bundle_name=PurePosixPath(root).name,
                info_path=info_path,
                executable_name=executable,
                executable_path=executable_path,
                plist=plist,
            )
        )
    if not valid:
        raise InvalidIPAError("No application bundle has a valid CFBundleExecutable")
    if len(valid) > 1:
        names = ", ".join(bundle.bundle_name for bundle in valid)
        raise InvalidIPAError(f"Multiple application bundles are ambiguous: {names}")
    return valid[0]


def _classify_asset(path: PurePosixPath, bundle: Bundle) -> str | None:
    relative = path.as_posix()
    if not relative.startswith(bundle.archive_root + "/"):
        return None
    name = path.name
    if relative == bundle.executable_path or name in NON_ASSET_NAMES:
        return None
    if "/_CodeSignature/" in relative or name.startswith("."):
        return None
    suffix = path.suffix.lower()
    if suffix in ASSET_CATEGORIES:
        return ASSET_CATEGORIES[suffix]
    if suffix in {".dylib", ".framework", ".appex"}:
        return None
    return "other"


def _write_evidence_file(archive: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> str:
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    if target.exists():
        if not target.is_file():
            raise InvalidIPAError(f"Evidence path collides with a non-file: {target}")
        existing_hash = sha256_file(target)
        with archive.open(info, "r") as source:
            archive_hash = hashlib.sha256()
            size = 0
            while True:
                block = source.read(COPY_CHUNK_SIZE)
                if not block:
                    break
                archive_hash.update(block)
                size += len(block)
        if size != info.file_size or archive_hash.hexdigest() != existing_hash:
            raise InvalidIPAError(f"Refusing to overwrite conflicting extracted evidence: {target}")
        return existing_hash

    temporary = target.with_name(f".{target.name}.extracting-{os.getpid()}")
    try:
        with archive.open(info, "r") as source, temporary.open("xb") as destination:
            size = 0
            while True:
                block = source.read(COPY_CHUNK_SIZE)
                if not block:
                    break
                destination.write(block)
                digest.update(block)
                size += len(block)
            destination.flush()
            os.fsync(destination.fileno())
        if size != info.file_size:
            raise InvalidIPAError(f"Extracted size mismatch for {info.filename}")
        os.replace(temporary, target)
        return digest.hexdigest()
    finally:
        if temporary.exists():
            temporary.unlink()


def extract_and_inventory(ipa_path: Path, output_root: Path) -> ExtractionResult:
    source = SourceIdentity.capture(ipa_path)
    evidence_root = output_root / "evidence" / "extracted"
    try:
        with zipfile.ZipFile(source.path, "r") as archive:
            validated = _validate_members(archive)
            file_member_names = {
                member.path.as_posix()
                for member in validated
                if not member.archive_info.is_dir()
            }
            content_members = {
                member.path.as_posix(): member.content_info
                for member in validated
                if not member.archive_info.is_dir()
            }
            bundle = locate_bundle(archive, file_member_names, content_members)
            files: list[dict[str, Any]] = []
            assets: list[dict[str, Any]] = []
            issues: list[dict[str, Any]] = []
            for member in sorted(validated, key=lambda item: item.path.as_posix()):
                info = member.archive_info
                member_path = member.path
                if info.is_dir():
                    (evidence_root.joinpath(*member_path.parts)).mkdir(parents=True, exist_ok=True)
                    continue
                target = evidence_root.joinpath(*member_path.parts)
                digest = _write_evidence_file(archive, member.content_info, target)
                category = _classify_asset(member_path, bundle)
                record = {
                    "path": member_path.as_posix(),
                    "bundle_relative_path": (
                        member_path.as_posix()[len(bundle.archive_root) + 1:]
                        if member_path.as_posix().startswith(bundle.archive_root + "/") else None
                    ),
                    "size": member.content_info.file_size,
                    "compressed_size": member.content_info.compress_size,
                    "crc32": f"{member.content_info.CRC:08x}",
                    "sha256": digest,
                    "extension": member_path.suffix.lower(),
                    "asset_category": category,
                }
                if member.link_target is not None:
                    record.update({
                        "archive_entry_type": "symbolic_link",
                        "link_target": member.link_target,
                        "resolved_archive_path": member.resolved_archive_path,
                        "link_status": member.link_status,
                        "archive_entry_size": info.file_size,
                        "archive_entry_compressed_size": info.compress_size,
                        "archive_entry_crc32": f"{info.CRC:08x}",
                    })
                    if member.link_status == "target_missing":
                        issues.append({
                            "code": "archive_symbolic_link_target_missing",
                            "severity": "info",
                            "path": member_path.as_posix(),
                            "target": member.resolved_archive_path,
                            "message": (
                                "An internal symbolic-link target is absent; the inert link payload "
                                "was preserved as a regular evidence file"
                            ),
                        })
                files.append(record)
                if category is not None:
                    assets.append(record.copy())
    except zipfile.BadZipFile as exc:
        raise InvalidIPAError(f"Input is not a valid ZIP/IPA archive: {exc}") from exc
    except (RuntimeError, OSError) as exc:
        if isinstance(exc, InvalidIPAError):
            raise
        raise InvalidIPAError(f"Failed to extract IPA safely: {exc}") from exc

    source.assert_unchanged()
    return ExtractionResult(
        source=source,
        bundle=bundle,
        files=files,
        assets=assets,
        total_uncompressed_bytes=sum(record["size"] for record in files),
        evidence_root=evidence_root,
        issues=issues,
    )


def bundle_metadata(bundle: Bundle) -> dict[str, Any]:
    plist = bundle.plist
    return {
        "archive_root": bundle.archive_root,
        "bundle_name": bundle.bundle_name,
        "bundle_identifier": plist.get("CFBundleIdentifier"),
        "display_name": plist.get("CFBundleDisplayName") or plist.get("CFBundleName"),
        "bundle_version": plist.get("CFBundleVersion"),
        "short_version": plist.get("CFBundleShortVersionString"),
        "package_type": plist.get("CFBundlePackageType"),
        "executable_name": bundle.executable_name,
        "executable_path": bundle.executable_path,
        "minimum_os_version": plist.get("MinimumOSVersion"),
        "supported_platforms": normalize_json(plist.get("CFBundleSupportedPlatforms", [])),
        "device_families": normalize_json(plist.get("UIDeviceFamily", [])),
        "url_types": normalize_json(plist.get("CFBundleURLTypes", [])),
        "orientations": normalize_json(plist.get("UISupportedInterfaceOrientations", [])),
        "required_capabilities": normalize_json(plist.get("UIRequiredDeviceCapabilities", [])),
        "info_plist": normalize_json(plist),
    }
