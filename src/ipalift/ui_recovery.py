"""Deterministic, evidence-linked user-interface recovery."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import plistlib
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .errors import IPALiftError
from .ui_archives import InterfaceDecodeError, decode_interface_artifact
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class UIRecoveryError(IPALiftError):
    """A workspace cannot support trustworthy UI recovery."""


@dataclass(frozen=True)
class UIRecoveryResult:
    workspace: Path
    ui_model: dict[str, Any]
    ui_model_path: Path
    report_path: Path


REQUIRED_REPORTS = (
    "application",
    "assets",
    "functions",
    "recovered-code-index",
    "objc-dispatch",
    "objc-type-flow",
    "platform-api-map",
    "native-type-flow",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
_INTERFACE_SUFFIXES = {".nib", ".storyboard", ".xib"}
_LOCALIZATION_SUFFIXES = {".strings", ".stringsdict"}
_IMAGE_CATEGORIES = {"image", "texture"}
_IMAGE_FIELDS = {
    "backgroundimage",
    "highlightedimage",
    "image",
    "selectedimage",
}
_TEXT_FIELDS = {
    "accessibilitylabel",
    "placeholder",
    "prompt",
    "text",
    "title",
}
_FONT_FIELDS = {"font", "fontdescription", "fontname"}
_COLOR_FIELDS = {
    "backgroundcolor",
    "color",
    "textcolor",
    "tintcolor",
}
_SCALE_SUFFIX = re.compile(r"@(?P<scale>[1-9][0-9]*)x$", re.IGNORECASE)
_ADDRESS = re.compile(r"^0x[0-9a-f]+$")
_STRING_PAIR = re.compile(
    r'"(?P<key>(?:\\.|[^"\\])*)"\s*=\s*"(?P<value>(?:\\.|[^"\\])*)"\s*;',
    re.DOTALL,
)


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise UIRecoveryError(f"Analysis workspace is missing analysis/{name}.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise UIRecoveryError(f"Cannot read {path}: {exc}") from exc
    if (
        document.get("schema_version") != 1
        or document.get("artifact") != name
        or not isinstance(document.get("facts"), dict)
    ):
        raise UIRecoveryError(f"Invalid IPALift {name} report: {path}")
    return document


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = relative.replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise UIRecoveryError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise UIRecoveryError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _address_key(value: str | None) -> tuple[int, str]:
    if value and _ADDRESS.match(value):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _evidence(
    kind: str,
    source: str,
    *,
    basis: str,
    confidence: str = "high",
    source_object: str | None = None,
    field: str | None = None,
    source_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "source": source,
        "source_object": source_object,
        "field": field,
        "source_address": source_address,
        "confidence": confidence,
        "basis": basis,
        "details": details or {},
    }


def _load_catalog() -> tuple[dict[str, Any], str]:
    resource = importlib.resources.files("ipalift").joinpath("catalogs/ui-apis-v1.json")
    try:
        data = resource.read_bytes()
        document = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UIRecoveryError(f"Cannot load the UI API catalog: {exc}") from exc
    required = {
        "catalog_id",
        "catalog_version",
        "description",
        "controller_classes",
        "element_tags",
        "selectors",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise UIRecoveryError("UI API catalog has an invalid top-level shape")
    if document["catalog_id"] != "ipalift-ui-apis":
        raise UIRecoveryError("UI API catalog has an unexpected identity")
    controllers = [str(value) for value in document["controller_classes"]]
    selectors = [str(item.get("selector") or "") for item in document["selectors"]]
    if (
        not all(controllers)
        or len(controllers) != len(set(controllers))
        or not all(selectors)
        or len(selectors) != len(set(selectors))
    ):
        raise UIRecoveryError("UI API catalog has duplicate or empty records")
    return document, hashlib.sha256(data).hexdigest()


def _read_evidence_file(
    workspace: Path,
    file_record: dict[str, Any],
) -> tuple[str, Path, bytes]:
    archive_path = str(file_record.get("path") or "")
    relative = f"evidence/extracted/{archive_path}"
    path = _relative_file(workspace, relative)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UIRecoveryError(f"Cannot read extracted evidence {archive_path}: {exc}") from exc
    digest = hashlib.sha256(data).hexdigest()
    expected = str(file_record.get("sha256") or "")
    if expected and digest != expected:
        raise UIRecoveryError(f"Extracted evidence hash changed after analysis: {archive_path}")
    if file_record.get("size") is not None and len(data) != int(file_record["size"]):
        raise UIRecoveryError(f"Extracted evidence size changed after analysis: {archive_path}")
    return relative, path, data


def _plist_bundle_entrypoints(
    workspace: Path,
    application: dict[str, Any],
    file_by_path: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    bundle = application["facts"].get("bundle", {})
    archive_root = str(bundle.get("archive_root") or "")
    info_path = f"{archive_root}/Info.plist" if archive_root else ""
    record = file_by_path.get(info_path)
    if not record:
        return {"main_storyboards": [], "main_nibs": [], "launch_storyboards": []}
    _, _, data = _read_evidence_file(workspace, record)
    try:
        document = plistlib.loads(data)
    except plistlib.InvalidFileException as exc:
        raise UIRecoveryError(f"Cannot decode extracted application Info.plist: {exc}") from exc
    if not isinstance(document, dict):
        raise UIRecoveryError("Extracted application Info.plist has a non-dictionary root")

    def values(keys: Iterable[str]) -> list[str]:
        result: set[str] = set()
        for key in keys:
            value = document.get(key)
            if isinstance(value, str) and value:
                result.add(value)
        return sorted(result)

    return {
        "main_storyboards": values(("UIMainStoryboardFile", "UIMainStoryboardFile~ipad")),
        "main_nibs": values(("NSMainNibFile", "NSMainNibFile~ipad")),
        "launch_storyboards": values(("UILaunchStoryboardName", "UILaunchStoryboardName~ipad")),
    }


def _unescape_strings(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        simple = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
        if token in simple:
            return simple[token]
        if token.startswith(("U", "u")) and len(token) in {5, 9}:
            try:
                return chr(int(token[1:], 16))
            except ValueError:
                return "\\" + token
        return token

    return re.sub(r"\\(U[0-9A-Fa-f]{4,8}|u[0-9A-Fa-f]{4}|.)", replace, value)


def _decode_strings(data: bytes) -> dict[str, Any]:
    try:
        document = plistlib.loads(data)
    except plistlib.InvalidFileException:
        document = None
    if isinstance(document, dict):
        return {str(key): document[key] for key in sorted(document, key=str)}
    encodings = ("utf-8-sig", "utf-16") if data.startswith((b"\xff\xfe", b"\xfe\xff")) else ("utf-8-sig", "utf-16")
    text = None
    for encoding in encodings:
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise InterfaceDecodeError("Localization file is not valid UTF-8 or UTF-16")
    without_comments = re.sub(r"/\*.*?\*/|//[^\r\n]*", "", text, flags=re.DOTALL)
    pairs = list(_STRING_PAIR.finditer(without_comments))
    if not pairs and without_comments.strip():
        raise InterfaceDecodeError("Localization file is not a property list or quoted .strings table")
    result: dict[str, Any] = {}
    for match in pairs:
        key = _unescape_strings(match.group("key"))
        if key in result:
            raise InterfaceDecodeError(f"Localization table contains duplicate key: {key}")
        result[key] = _unescape_strings(match.group("value"))
    return result


def _locale_for_path(path: str) -> str | None:
    for part in PurePosixPath(path).parts:
        if part.lower().endswith(".lproj"):
            return part[:-6]
    return None


def _image_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) >= 24 and data.startswith(b"\x89PNG\r\n\x1a\n") and data[12:16] == b"IHDR":
        return struct.unpack(">II", data[16:24])
    if len(data) >= 10 and data[:6] in {b"GIF87a", b"GIF89a"}:
        return struct.unpack("<HH", data[6:10])
    if len(data) >= 26 and data.startswith(b"BM"):
        width, height = struct.unpack("<ii", data[18:26])
        return abs(width), abs(height)
    if len(data) >= 4 and data.startswith(b"\xff\xd8"):
        position = 2
        while position + 4 <= len(data):
            if data[position] != 0xFF:
                position += 1
                continue
            marker = data[position + 1]
            position += 2
            if marker in {0xD8, 0xD9}:
                continue
            if position + 2 > len(data):
                break
            length = struct.unpack(">H", data[position:position + 2])[0]
            if length < 2 or position + length > len(data):
                break
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF} and length >= 7:
                height, width = struct.unpack(">HH", data[position + 3:position + 7])
                return width, height
            position += length
    return None


def _asset_record(
    workspace: Path,
    item: dict[str, Any],
) -> dict[str, Any]:
    relative = str(item.get("bundle_relative_path") or item.get("path") or "")
    name = PurePosixPath(relative).name
    stem = PurePosixPath(name).stem
    scale_match = _SCALE_SUFFIX.search(stem)
    scale = int(scale_match.group("scale")) if scale_match else 1
    logical_stem = _SCALE_SUFFIX.sub("", stem)
    pixel_size = None
    if item.get("asset_category") in _IMAGE_CATEGORIES:
        _, _, data = _read_evidence_file(workspace, item)
        dimensions = _image_dimensions(data)
        if dimensions:
            pixel_size = {"width": dimensions[0], "height": dimensions[1]}
    logical_size = None
    if pixel_size:
        logical_size = {
            "width": pixel_size["width"] / scale,
            "height": pixel_size["height"] / scale,
        }
    asset_id = _stable_id("ui-asset", item.get("path"), item.get("sha256"))
    source = f"evidence/extracted/{item.get('path')}"
    return {
        "id": asset_id,
        "path": str(item.get("path") or ""),
        "bundle_relative_path": relative,
        "name": name,
        "logical_name": logical_stem,
        "category": str(item.get("asset_category") or "other"),
        "sha256": str(item.get("sha256") or ""),
        "size": int(item.get("size") or 0),
        "scale": scale,
        "pixel_size": pixel_size,
        "logical_size": logical_size,
        "evidence": [_evidence(
            "bundle_asset",
            source,
            basis="The extracted bundle inventory records this resource and its content hash",
            details={"asset_category": item.get("asset_category")},
        )],
    }


def _field_values(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            path = f"{prefix}.{key}" if prefix else str(key)
            result.extend(_field_values(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_field_values(item, f"{prefix}[{index}]"))
    else:
        result.append((prefix, value))
    return result


def _field_role(path: str) -> str | None:
    leaf = re.split(r"[.\[]", path)[-1].rstrip("]").lower()
    compact = re.sub(r"[^a-z]", "", leaf)
    if compact in _IMAGE_FIELDS or compact.endswith("image"):
        return "image"
    if compact in _TEXT_FIELDS or compact.endswith(("text", "title", "placeholder")):
        return "text"
    if compact in _FONT_FIELDS or "font" in compact:
        return "font"
    if compact in _COLOR_FIELDS or compact.endswith("color"):
        return "color"
    return None


def _asset_candidates(requested: str, assets: list[dict[str, Any]]) -> list[str]:
    portable = requested.replace("\\", "/")
    requested_name = PurePosixPath(portable).name
    requested_stem = _SCALE_SUFFIX.sub("", PurePosixPath(requested_name).stem)
    exact_path = [item["id"] for item in assets if item["bundle_relative_path"] == portable]
    if exact_path:
        return sorted(exact_path)
    exact_name = [item["id"] for item in assets if item["name"] == requested_name]
    if exact_name:
        return sorted(exact_name)
    logical = [item["id"] for item in assets if item["logical_name"] == requested_stem]
    return sorted(logical)


def _class_superclass(item: dict[str, Any]) -> str | None:
    value = item.get("superclass")
    if isinstance(value, dict):
        name = value.get("name")
        return str(name) if name else None
    return str(value) if value else None


def _controller_class_names(
    classes: list[dict[str, Any]],
    controller_bases: set[str],
) -> set[str]:
    parent_by_name: dict[str, str | None] = {}
    for item in classes:
        name = str(item.get("name") or "")
        if name:
            parent_by_name.setdefault(name, _class_superclass(item))
    result = set(controller_bases)
    changed = True
    while changed:
        changed = False
        for name, parent in sorted(parent_by_name.items()):
            if parent in result and name not in result:
                result.add(name)
                changed = True
    return result


def _attribute_value(node: dict[str, Any], names: Iterable[str]) -> Any:
    lowered: dict[str, Any] = {}
    for collection in (node.get("attributes", {}), node.get("properties", {})):
        if isinstance(collection, dict):
            lowered.update({str(key).lower(): value for key, value in collection.items()})
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    for key, value in sorted(lowered.items()):
        if any(name.lower() in key for name in names):
            if isinstance(value, (str, int, float, bool)):
                return value
    return None


def _source_storyboard_name(path: str) -> str:
    parts = PurePosixPath(path).parts
    for part in reversed(parts):
        if part.lower().endswith(".storyboardc"):
            return part[:-12]
    return PurePosixPath(path).stem


def _classification_counts(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("classification") or "unresolved") for item in records)
    return {name: counts.get(name, 0) for name in CLASSIFICATIONS}


def _render_ui_report(facts: dict[str, Any]) -> str:
    summary = facts["summary"]
    lines = [
        "# IPALift UI reconstruction report",
        "",
        "> Evidence-linked reconstruction guidance. This is not an original Interface Builder document or a pixel-perfect rendering claim.",
        "",
        "## Summary",
        "",
        f"- Interface artifacts: {summary['interface_artifact_count']}",
        f"- Screens: {summary['screen_count']}",
        f"- Elements: {summary['element_count']}",
        f"- Connections: {summary['connection_count']}",
        f"- Constraints: {summary['constraint_count']}",
        f"- Navigation edges: {summary['navigation_edge_count']}",
        f"- UIKit code operations: {summary['code_operation_count']}",
        f"- Resource references: {summary['resource_reference_count']}",
        "",
    ]
    screen_by_id = {item["id"]: item for item in facts["screens"]}
    element_by_id = {item["id"]: item for item in facts["elements"]}
    connection_by_id = {item["id"]: item for item in facts["connections"]}
    operation_by_id = {item["id"]: item for item in facts["code_operations"]}
    resource_by_id = {item["id"]: item for item in facts["resource_references"]}
    navigation_by_id = {item["id"]: item for item in facts["navigation_edges"]}
    lines.extend(["## Screen-by-screen reconstruction", ""])
    if not facts["screens"]:
        lines.extend(["No screen could be recovered from interface or controller evidence.", ""])
    for screen in facts["screens"]:
        entry = f"; entry point: {screen['entry_point_kind']}" if screen["entry_point_kind"] != "none" else ""
        lines.extend([
            f"### {screen['name']}",
            "",
            f"- Classification: {screen['classification']}{entry}",
            f"- Source: `{screen['source_path']}`",
            f"- Controller: {screen['controller_class_name'] or 'unresolved'}",
            f"- Storyboard identifier: {screen['storyboard_identifier'] or 'none'}",
            f"- Root element: {screen['root_element_id'] or 'unresolved'}",
            "",
            "#### View hierarchy",
            "",
        ])
        elements = [element_by_id[value] for value in screen["element_ids"] if value in element_by_id]
        if not elements:
            lines.append("No concrete view hierarchy was decoded for this screen.")
        for element in elements:
            frame = element.get("frame")
            frame_text = ""
            if frame:
                frame_text = (
                    f" frame=({frame['x']}, {frame['y']}, {frame['width']}, {frame['height']})"
                )
            lines.append(
                f"- `{element['id']}` {element['class_name']} parent={element['parent_id'] or 'none'}{frame_text}"
            )
            for reference_id in element["resource_reference_ids"]:
                reference = resource_by_id.get(reference_id)
                if reference:
                    lines.append(
                        f"  - {reference['kind']} `{reference['requested_value']}`: {reference['classification']}"
                    )
        lines.extend(["", "#### Connections and navigation", ""])
        connection_records = [
            connection_by_id[value] for value in screen["connection_ids"] if value in connection_by_id
        ]
        navigation_records = [
            navigation_by_id[value] for value in screen["navigation_edge_ids"] if value in navigation_by_id
        ]
        if not connection_records and not navigation_records:
            lines.append("No connections or navigation edges were recovered.")
        for connection in connection_records:
            detail = connection["selector"] or connection["label"] or connection["subkind"]
            lines.append(f"- {connection['kind']}: {detail or 'unnamed'} ({connection['classification']})")
        for edge in navigation_records:
            destination = screen_by_id.get(edge["destination_screen_id"] or "")
            lines.append(
                f"- navigation {edge['subkind']}: {destination['name'] if destination else 'unresolved destination'} ({edge['classification']})"
            )
        lines.extend(["", "#### Correlated UIKit code", ""])
        operations = [operation_by_id[value] for value in screen["code_operation_ids"] if value in operation_by_id]
        if not operations:
            lines.append("No UIKit callsite was safely associated with this screen.")
        for operation in operations:
            lines.append(
                f"- `{operation['selector']}` [{operation['category']}] at {operation['call_site'] or 'unknown address'} ({operation['classification']})"
            )
        if screen["failure_reasons"]:
            lines.extend(["", "#### Remaining uncertainty", ""])
            lines.extend(f"- {reason}" for reason in screen["failure_reasons"])
        lines.append("")
    lines.extend([
        "## Evidence boundary",
        "",
        "- Interface archive fields, Objective-C metadata, hashes, and exact platform callsites are facts.",
        "- Programmatic screen existence and function-level resource associations remain candidate sets.",
        "- Names and visual similarity never invent layout, navigation, ownership, or behavior.",
        "- No upstream report, call graph, dispatch result, or type-flow artifact is rewritten.",
        "",
        "The complete evidence graph is in `analysis/ui-model.json`.",
        "",
    ])
    return "\n".join(lines)


def recover_ui(workspace: Path) -> UIRecoveryResult:
    """Decode and correlate deterministic UI evidence from a completed workspace."""
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise UIRecoveryError(f"Analysis workspace does not exist: {workspace}") from exc
    if not workspace.is_dir():
        raise UIRecoveryError(f"Analysis workspace is not a directory: {workspace}")

    reports = {name: _load_report(workspace, name) for name in REQUIRED_REPORTS}
    catalog, catalog_sha256 = _load_catalog()
    assets_facts = reports["assets"]["facts"]
    files = list(assets_facts.get("files", []))
    assets_inventory = list(assets_facts.get("assets", []))
    if len(files) != assets_facts.get("file_count"):
        raise UIRecoveryError("assets.json file count does not match its inventory")
    if len(assets_inventory) != assets_facts.get("asset_count"):
        raise UIRecoveryError("assets.json asset count does not match its inventory")
    file_by_path = {str(item.get("path") or ""): item for item in files}
    if len(file_by_path) != len(files):
        raise UIRecoveryError("assets.json contains duplicate file paths")

    bundle_entrypoints = _plist_bundle_entrypoints(
        workspace, reports["application"], file_by_path
    )
    input_artifacts = [
        {
            "artifact": name,
            "path": f"analysis/{name}.json",
            "sha256": sha256_file(workspace / "analysis" / f"{name}.json"),
        }
        for name in REQUIRED_REPORTS
    ]

    interface_records = [
        item for item in files
        if PurePosixPath(str(item.get("path") or "")).suffix.lower() in _INTERFACE_SUFFIXES
        or str(item.get("path") or "").replace("\\", "/").lower().endswith(".storyboardc/info.plist")
    ]
    decoded_documents: list[dict[str, Any]] = []
    interface_artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for file_record in sorted(interface_records, key=lambda item: str(item.get("path") or "")):
        archive_path = str(file_record.get("path") or "")
        source, _, data = _read_evidence_file(workspace, file_record)
        try:
            decoded = decode_interface_artifact(archive_path, data, catalog)
        except InterfaceDecodeError as exc:
            errors.append({
                "code": "interface_decode_failed",
                "path": archive_path,
                "message": str(exc),
            })
            interface_artifacts.append({
                "path": archive_path,
                "bundle_relative_path": file_record.get("bundle_relative_path"),
                "sha256": file_record.get("sha256"),
                "format": "unknown",
                "source_kind": "unknown",
                "status": "unresolved",
                "object_count": 0,
                "connection_count": 0,
                "constraint_count": 0,
                "screen_ids": [],
                "issue_codes": ["interface_decode_failed"],
            })
            continue
        decoded["path"] = archive_path
        decoded["source"] = source
        decoded_documents.append(decoded)
        for issue in decoded["issues"]:
            errors.append({
                "code": str(issue.get("code") or "interface_decode_issue"),
                "path": archive_path,
                "message": str(issue.get("message") or "Interface decoder reported an issue"),
            })
        interface_artifacts.append({
            "path": archive_path,
            "bundle_relative_path": file_record.get("bundle_relative_path"),
            "sha256": file_record.get("sha256"),
            "format": decoded["format"],
            "source_kind": decoded["source_kind"],
            "status": "decoded" if decoded["nodes"] and not decoded["issues"] else "partial" if decoded["nodes"] else "unresolved" if decoded["issues"] else "decoded",
            "object_count": len(decoded["nodes"]),
            "connection_count": len(decoded["connections"]),
            "constraint_count": len(decoded["constraints"]),
            "screen_ids": [],
            "issue_codes": sorted(str(item.get("code")) for item in decoded["issues"]),
        })

    localizations: list[dict[str, Any]] = []
    for file_record in sorted(files, key=lambda item: str(item.get("path") or "")):
        archive_path = str(file_record.get("path") or "")
        if PurePosixPath(archive_path).suffix.lower() not in _LOCALIZATION_SUFFIXES:
            continue
        source, _, data = _read_evidence_file(workspace, file_record)
        try:
            table = _decode_strings(data)
        except InterfaceDecodeError as exc:
            errors.append({
                "code": "localization_decode_failed",
                "path": archive_path,
                "message": str(exc),
            })
            continue
        locale = _locale_for_path(archive_path)
        table_name = PurePosixPath(archive_path).stem
        for key, value in sorted(table.items()):
            localizations.append({
                "id": _stable_id("ui-localization", archive_path, key),
                "source_path": archive_path,
                "locale": locale,
                "table": table_name,
                "key": key,
                "value": value,
                "evidence": [_evidence(
                    "localization_entry",
                    source,
                    source_object=key,
                    basis="The localization key and value were decoded directly from the extracted table",
                )],
            })
    localizations.sort(key=lambda item: (item["source_path"], item["key"], item["id"]))

    ui_assets = [
        _asset_record(workspace, item)
        for item in sorted(assets_inventory, key=lambda record: str(record.get("path") or ""))
        if item.get("asset_category") in _IMAGE_CATEGORIES | {"font"}
    ]
    asset_by_id = {item["id"]: item for item in ui_assets}

    screens: list[dict[str, Any]] = []
    elements: list[dict[str, Any]] = []
    connections: list[dict[str, Any]] = []
    constraints: list[dict[str, Any]] = []
    navigation_edges: list[dict[str, Any]] = []
    resource_references: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    object_id_by_source_native: dict[tuple[str, str], str] = {}
    screen_id_by_source_controller: dict[tuple[str, str], str] = {}
    screen_id_by_source_object: dict[tuple[str, str], str] = {}
    document_by_path = {item["path"]: item for item in decoded_documents}

    for document in decoded_documents:
        source_path = document["path"]
        for node in document["nodes"]:
            object_id_by_source_native[(source_path, node["native_id"])] = _stable_id(
                "ui-object", source_path, node["native_id"]
            )

    for document in decoded_documents:
        source_path = document["path"]
        source = document["source"]
        nodes = document["nodes"]
        controller_nodes = [item for item in nodes if item["role"] == "controller"]
        roots = [item for item in nodes if item["role"] == "element" and item["parent_native_id"] is None]
        screen_sources = controller_nodes or roots
        for position, node in enumerate(sorted(screen_sources, key=lambda item: item["native_id"]), 1):
            controller_native_id = node["native_id"] if node["role"] == "controller" else None
            screen_id = _stable_id("ui-screen", source_path, node["native_id"])
            if controller_native_id:
                screen_id_by_source_controller[(source_path, controller_native_id)] = screen_id
            screen_id_by_source_object[(source_path, node["native_id"])] = screen_id
            storyboard_identifier = _attribute_value(
                node, ("storyboardIdentifier", "UIStoryboardIdentifier", "restorationIdentifier")
            )
            controller_class = node["class_name"] if node["role"] == "controller" else None
            name = str(storyboard_identifier or controller_class or f"{_source_storyboard_name(source_path)} screen {position}")
            source_name = _source_storyboard_name(source_path)
            entry_kind = "none"
            entry_basis: list[str] = []
            if document.get("initial_controller_native_id") == node["native_id"]:
                entry_kind = "main"
                entry_basis.append("interface_archive_initial_controller")
            if source_name in bundle_entrypoints["main_storyboards"] or source_name in bundle_entrypoints["main_nibs"]:
                entry_kind = "main"
                entry_basis.append("application_info_plist_main_interface")
            elif source_name in bundle_entrypoints["launch_storyboards"]:
                entry_kind = "launch"
                entry_basis.append("application_info_plist_launch_interface")
            screens.append({
                "id": screen_id,
                "name": name,
                "classification": "exact",
                "source_kind": document["source_kind"],
                "source_path": source_path,
                "source_object_id": node["native_id"],
                "controller_object_id": (
                    object_id_by_source_native[(source_path, controller_native_id)] if controller_native_id else None
                ),
                "controller_class_name": controller_class,
                "storyboard_identifier": str(storyboard_identifier) if storyboard_identifier is not None else None,
                "root_element_id": None,
                "element_ids": [],
                "connection_ids": [],
                "constraint_ids": [],
                "navigation_edge_ids": [],
                "code_operation_ids": [],
                "entry_point_kind": entry_kind,
                "entry_point_basis": sorted(entry_basis),
                "evidence": [_evidence(
                    "interface_object",
                    source,
                    source_object=node["native_id"],
                    basis="A controller or top-level view was decoded directly from the interface artifact",
                )],
                "failure_reasons": [],
            })

    screen_by_id = {item["id"]: item for item in screens}
    for document in decoded_documents:
        source_path = document["path"]
        source = document["source"]
        nodes_by_native = {item["native_id"]: item for item in document["nodes"]}
        root_screen_by_native: dict[str, str] = {
            native: screen_id
            for (path, native), screen_id in screen_id_by_source_object.items()
            if path == source_path
        }
        for node in sorted(document["nodes"], key=lambda item: item["native_id"]):
            if node["role"] != "element":
                continue
            screen_id = None
            controller_native = node.get("controller_native_id")
            if controller_native:
                screen_id = screen_id_by_source_controller.get((source_path, controller_native))
            if screen_id is None:
                current = node
                visited: set[str] = set()
                while current["native_id"] not in visited:
                    visited.add(current["native_id"])
                    if current["native_id"] in root_screen_by_native:
                        screen_id = root_screen_by_native[current["native_id"]]
                        break
                    parent_native = current.get("parent_native_id")
                    if not parent_native or parent_native not in nodes_by_native:
                        break
                    current = nodes_by_native[parent_native]
            if screen_id is None:
                continue
            element_id = object_id_by_source_native[(source_path, node["native_id"])]
            screen_id_by_source_object[(source_path, node["native_id"])] = screen_id
            parent_id = object_id_by_source_native.get((source_path, str(node.get("parent_native_id") or "")))
            child_ids = sorted(
                object_id_by_source_native[(source_path, child)]
                for child in node["child_native_ids"]
                if (source_path, child) in object_id_by_source_native
                and nodes_by_native.get(child, {}).get("role") == "element"
            )
            element = {
                "id": element_id,
                "screen_id": screen_id,
                "source_object_id": node["native_id"],
                "class_name": node["class_name"],
                "base_class_name": node.get("base_class_name"),
                "custom_class": node.get("custom_class"),
                "tag": node.get("tag"),
                "classification": "exact",
                "parent_id": parent_id,
                "child_ids": child_ids,
                "frame": node.get("frame"),
                "bounds": node.get("bounds"),
                "attributes": node.get("attributes", {}),
                "properties": node.get("properties", {}),
                "resource_reference_ids": [],
                "evidence": [_evidence(
                    "interface_object",
                    source,
                    source_object=node["native_id"],
                    basis="The view/control object and its serialized properties were decoded directly",
                )],
                "failure_reasons": [],
            }
            elements.append(element)
            screen = screen_by_id[screen_id]
            screen["element_ids"].append(element_id)
            if screen["root_element_id"] is None and (
                parent_id == screen.get("controller_object_id") or parent_id is None
            ):
                screen["root_element_id"] = element_id

            combined = {
                "attributes": node.get("attributes", {}),
                "properties": node.get("properties", {}),
            }
            for field_path, value in _field_values(combined):
                role = _field_role(field_path)
                if role is None or not isinstance(value, (str, int, float, bool)):
                    continue
                requested = str(value)
                if not requested:
                    continue
                candidates: list[str] = []
                localization_ids: list[str] = []
                classification = "unresolved"
                failure_reasons: list[str] = []
                if role in {"image", "font"}:
                    candidates = _asset_candidates(requested, ui_assets)
                    if len(candidates) == 1:
                        classification = "exact"
                    elif candidates:
                        classification = "candidate_set"
                        failure_reasons.append("resource_name_matches_multiple_bundle_assets")
                    else:
                        failure_reasons.append("resource_name_has_no_bundle_asset_match")
                elif role == "text":
                    localization_ids = sorted({
                        item["id"] for item in localizations
                        if item["key"] in {
                            requested,
                            f"{node['native_id']}.{field_path.rsplit('.', 1)[-1]}",
                        }
                    })
                    if localization_ids:
                        classification = "exact"
                    else:
                        classification = "exact"
                elif role == "color":
                    classification = "exact"
                reference_id = _stable_id("ui-resource-reference", element_id, field_path, requested)
                resource_references.append({
                    "id": reference_id,
                    "screen_id": screen_id,
                    "element_id": element_id,
                    "kind": role,
                    "field": field_path,
                    "requested_value": requested,
                    "classification": classification,
                    "asset_candidate_ids": candidates,
                    "localization_entry_ids": localization_ids,
                    "evidence": [_evidence(
                        "interface_property",
                        source,
                        source_object=node["native_id"],
                        field=field_path,
                        basis="The serialized interface property contains this resource or presentation value",
                    )],
                    "failure_reasons": failure_reasons,
                })
                element["resource_reference_ids"].append(reference_id)
                if classification == "candidate_set":
                    hypotheses.append({
                        "id": _stable_id("ui-hypothesis", reference_id),
                        "kind": "candidate_ui_resource",
                        "subject_id": reference_id,
                        "candidate_ids": candidates or localization_ids,
                        "confidence": "medium",
                        "basis": failure_reasons[0] if failure_reasons else "Multiple resource candidates remain",
                    })

    elements.sort(key=lambda item: (item["screen_id"], item["id"]))
    element_by_id = {item["id"]: item for item in elements}
    for screen in screens:
        screen["element_ids"].sort()
        if screen["root_element_id"] is None and screen["element_ids"]:
            screen["root_element_id"] = screen["element_ids"][0]

    recovered = reports["recovered-code-index"]["facts"]
    methods = list(recovered.get("methods", []))
    classes = list(recovered.get("classes", []))
    recovered_functions = list(recovered.get("functions", []))
    methods_by_selector: dict[str, list[dict[str, Any]]] = defaultdict(list)
    methods_by_class_selector: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for method in methods:
        selector = str(method.get("selector") or "")
        class_name = str(method.get("class_name") or "")
        if selector:
            methods_by_selector[selector].append(method)
            if class_name:
                methods_by_class_selector[(class_name, selector)].append(method)
    class_records_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in classes:
        if item.get("name"):
            class_records_by_name[str(item["name"])].append(item)

    for document in decoded_documents:
        source_path = document["path"]
        source = document["source"]
        for item in document["connections"]:
            source_object_id = object_id_by_source_native.get((source_path, str(item.get("source_native_id") or "")))
            destination_object_id = object_id_by_source_native.get((source_path, str(item.get("destination_native_id") or "")))
            screen_id = screen_id_by_source_object.get((source_path, str(item.get("source_native_id") or "")))
            if screen_id is None:
                screen_id = screen_id_by_source_object.get((source_path, str(item.get("destination_native_id") or "")))
            screen = screen_by_id.get(screen_id or "")
            connection_id = _stable_id("ui-connection", source_path, item["native_id"])
            code_matches: list[dict[str, Any]] = []
            failure_reasons: list[str] = []
            controller_class = screen.get("controller_class_name") if screen else None
            if item["kind"] == "action" and item.get("selector"):
                exact = methods_by_class_selector.get((str(controller_class), str(item["selector"])), []) if controller_class else []
                candidates = exact or methods_by_selector.get(str(item["selector"]), [])
                classification = "exact" if len(exact) == 1 else "candidate_set" if candidates else "unresolved"
                code_matches.append({
                    "kind": "objective_c_action_method",
                    "classification": classification,
                    "candidate_ids": sorted(str(value["id"]) for value in candidates),
                    "evidence": [_evidence(
                        "objective_c_method_metadata",
                        "analysis/recovered-code-index.json",
                        field=str(item["selector"]),
                        basis="The serialized action selector was matched to recovered Objective-C method metadata",
                        confidence="high" if classification == "exact" else "medium" if candidates else "low",
                    )],
                })
                if classification != "exact":
                    failure_reasons.append("action_selector_does_not_map_to_one_controller_method")
            elif item["kind"] == "outlet" and item.get("label"):
                candidates: list[str] = []
                if controller_class:
                    for class_record in class_records_by_name.get(str(controller_class), []):
                        for property_record in class_record.get("properties", []):
                            if str(property_record.get("name") or "") == str(item["label"]):
                                candidates.append(f"property:{controller_class}:{item['label']}")
                        for ivar in class_record.get("ivars", []):
                            name = str(ivar.get("name") or "").lstrip("_")
                            if name == str(item["label"]).lstrip("_"):
                                candidates.append(f"ivar:{controller_class}:{ivar.get('name')}")
                classification = "exact" if len(set(candidates)) == 1 else "candidate_set" if candidates else "unresolved"
                code_matches.append({
                    "kind": "objective_c_outlet_storage",
                    "classification": classification,
                    "candidate_ids": sorted(set(candidates)),
                    "evidence": [_evidence(
                        "objective_c_storage_metadata",
                        "analysis/recovered-code-index.json",
                        field=str(item["label"]),
                        basis="The serialized outlet name was matched to recovered property or ivar metadata",
                        confidence="high" if classification == "exact" else "medium" if candidates else "low",
                    )],
                })
                if classification != "exact":
                    failure_reasons.append("outlet_name_does_not_map_to_one_controller_storage_record")
            connection = {
                "id": connection_id,
                "screen_id": screen_id,
                "source_object_id": source_object_id,
                "destination_object_id": destination_object_id,
                "kind": item["kind"],
                "subkind": str(item.get("subkind") or item["kind"]),
                "label": str(item["label"]) if item.get("label") is not None else None,
                "selector": str(item["selector"]) if item.get("selector") is not None else None,
                "event": str(item["event"]) if item.get("event") is not None else None,
                "classification": "exact",
                "code_matches": code_matches,
                "evidence": [_evidence(
                    "interface_connection",
                    source,
                    source_object=item["native_id"],
                    basis="The outlet, action, or segue was decoded directly from the interface artifact",
                )],
                "failure_reasons": sorted(set(failure_reasons)),
            }
            connections.append(connection)
            if screen:
                screen["connection_ids"].append(connection_id)
            for match in code_matches:
                if match["classification"] == "candidate_set":
                    hypotheses.append({
                        "id": _stable_id("ui-hypothesis", connection_id, match["kind"]),
                        "kind": "candidate_ui_code_match",
                        "subject_id": connection_id,
                        "candidate_ids": match["candidate_ids"],
                        "confidence": "medium",
                        "basis": failure_reasons[0] if failure_reasons else "Multiple code matches remain",
                    })

            if item["kind"] == "segue":
                destination_screen_id = screen_id_by_source_object.get(
                    (source_path, str(item.get("destination_native_id") or ""))
                )
                classification = "exact" if screen_id and destination_screen_id else "unresolved"
                edge_id = _stable_id("ui-navigation", source_path, item["native_id"])
                edge = {
                    "id": edge_id,
                    "source_screen_id": screen_id,
                    "destination_screen_id": destination_screen_id,
                    "connection_id": connection_id,
                    "subkind": str(item.get("subkind") or "segue"),
                    "identifier": str(item["label"]) if item.get("label") is not None else None,
                    "classification": classification,
                    "evidence": [_evidence(
                        "interface_navigation",
                        source,
                        source_object=item["native_id"],
                        basis="The serialized segue or relationship identifies the source and destination objects",
                        confidence="high" if classification == "exact" else "low",
                    )],
                    "failure_reasons": [] if classification == "exact" else ["navigation_destination_screen_not_decoded"],
                }
                navigation_edges.append(edge)
                if screen:
                    screen["navigation_edge_ids"].append(edge_id)

        for item in document["constraints"]:
            first_id = object_id_by_source_native.get((source_path, str(item.get("first_item_native_id") or "")))
            second_id = object_id_by_source_native.get((source_path, str(item.get("second_item_native_id") or "")))
            owner_id = object_id_by_source_native.get((source_path, str(item.get("owner_native_id") or "")))
            screen_id = None
            for native in (item.get("owner_native_id"), item.get("first_item_native_id"), item.get("second_item_native_id")):
                if native and (source_path, str(native)) in screen_id_by_source_object:
                    screen_id = screen_id_by_source_object[(source_path, str(native))]
                    break
            constraint_id = _stable_id("ui-constraint", source_path, item["native_id"])
            classification = "exact" if first_id else "unresolved"
            constraints.append({
                "id": constraint_id,
                "screen_id": screen_id,
                "owner_object_id": owner_id,
                "first_item_id": first_id,
                "second_item_id": second_id,
                "first_attribute": str(item["first_attribute"]) if item.get("first_attribute") is not None else None,
                "second_attribute": str(item["second_attribute"]) if item.get("second_attribute") is not None else None,
                "relation": str(item["relation"]) if item.get("relation") is not None else "equal",
                "constant": item.get("constant"),
                "multiplier": item.get("multiplier"),
                "priority": item.get("priority"),
                "classification": classification,
                "evidence": [_evidence(
                    "interface_constraint",
                    source,
                    source_object=item["native_id"],
                    basis="The Auto Layout relation and serialized item references were decoded directly",
                    confidence="high" if classification == "exact" else "low",
                )],
                "failure_reasons": [] if classification == "exact" else ["constraint_first_item_not_decoded"],
            })
            if screen_id in screen_by_id:
                screen_by_id[screen_id]["constraint_ids"].append(constraint_id)

    controller_bases = {str(value) for value in catalog["controller_classes"]}
    controller_classes = _controller_class_names(classes, controller_bases)
    existing_controller_classes = {
        str(item["controller_class_name"])
        for item in screens
        if item.get("controller_class_name")
    }
    for class_name in sorted(controller_classes - controller_bases - existing_controller_classes):
        records = class_records_by_name.get(class_name, [])
        if not records:
            continue
        screen_id = _stable_id("ui-screen-programmatic", class_name)
        screens.append({
            "id": screen_id,
            "name": class_name,
            "classification": "candidate_set",
            "source_kind": "programmatic_controller_candidate",
            "source_path": "analysis/recovered-code-index.json",
            "source_object_id": None,
            "controller_object_id": None,
            "controller_class_name": class_name,
            "storyboard_identifier": None,
            "root_element_id": None,
            "element_ids": [],
            "connection_ids": [],
            "constraint_ids": [],
            "navigation_edge_ids": [],
            "code_operation_ids": [],
            "entry_point_kind": "none",
            "entry_point_basis": [],
            "evidence": [_evidence(
                "objective_c_class_hierarchy",
                "analysis/recovered-code-index.json",
                source_object=class_name,
                basis="Recovered class hierarchy identifies a UIViewController subclass but does not prove runtime presentation",
                confidence="medium",
            )],
            "failure_reasons": ["controller_class_does_not_prove_a_runtime_screen_instance"],
        })
        hypotheses.append({
            "id": _stable_id("ui-hypothesis", screen_id),
            "kind": "candidate_programmatic_screen",
            "subject_id": screen_id,
            "candidate_ids": [class_name],
            "confidence": "medium",
            "basis": "Recovered UIViewController subclass may construct or represent a screen at runtime",
        })
    screens.sort(key=lambda item: (item["source_path"], item["name"].casefold(), item["id"]))
    screen_by_id = {item["id"]: item for item in screens}
    screens_by_controller: dict[str, list[str]] = defaultdict(list)
    for screen in screens:
        if screen.get("controller_class_name"):
            screens_by_controller[str(screen["controller_class_name"])].append(screen["id"])

    function_by_id = {
        str(item.get("function_id") or ""): item for item in recovered_functions
        if item.get("function_id")
    }
    selector_catalog = {
        str(item["selector"]): str(item["category"]) for item in catalog["selectors"]
    }
    code_operations: list[dict[str, Any]] = []
    platform_callsites = reports["platform-api-map"]["facts"].get("message_callsites", [])
    for callsite in sorted(
        platform_callsites,
        key=lambda item: (_address_key(str(item.get("call_site") or "")), str(item.get("id") or "")),
    ):
        selector = str(callsite.get("selector") or "")
        if selector not in selector_catalog:
            continue
        external_classes = {str(value) for value in callsite.get("external_class_candidates", [])}
        frameworks = {str(value) for value in callsite.get("frameworks", [])}
        categories = {str(value) for value in callsite.get("categories", [])}
        if not ("UIKit" in frameworks or "ui" in categories or external_classes & controller_classes):
            continue
        affected_classes = sorted(str(value) for value in callsite.get("affected_class_names", []))
        screen_candidates = sorted({
            screen_id for class_name in affected_classes for screen_id in screens_by_controller.get(class_name, [])
        })
        classification = str(callsite.get("classification") or "unresolved")
        if classification == "exact" and len(screen_candidates) != 1:
            classification = "candidate_set" if screen_candidates else "unresolved"
        caller_function_id = str(callsite.get("caller_function_id") or "")
        function = function_by_id.get(caller_function_id, {})
        resource_candidates: list[dict[str, Any]] = []
        for asset in function.get("referenced_assets", []):
            asset_path = str(asset.get("path") or "")
            matches = [item["id"] for item in ui_assets if item["path"] == asset_path]
            resource_candidates.append({
                "kind": "asset",
                "value": asset_path,
                "candidate_ids": sorted(matches),
                "classification": "candidate_set",
                "failure_reason": "function_level_asset_reference_does_not_prove_call_argument",
            })
        for string_record in function.get("referenced_strings", []):
            value = string_record.get("value") if isinstance(string_record, dict) else string_record
            if value is not None:
                resource_candidates.append({
                    "kind": "string",
                    "value": str(value),
                    "candidate_ids": [],
                    "classification": "candidate_set",
                    "failure_reason": "function_level_string_reference_does_not_prove_call_argument",
                })
        operation_id = _stable_id("ui-code-operation", callsite.get("id"), selector)
        code_operations.append({
            "id": operation_id,
            "selector": selector,
            "category": selector_catalog[selector],
            "classification": classification,
            "call_site": callsite.get("call_site"),
            "caller_function_id": caller_function_id or None,
            "affected_method_ids": sorted(str(value) for value in callsite.get("affected_method_ids", [])),
            "affected_class_names": affected_classes,
            "screen_candidate_ids": screen_candidates,
            "resource_candidates": sorted(resource_candidates, key=lambda item: (item["kind"], item["value"])),
            "evidence": [_evidence(
                "platform_message_callsite",
                "analysis/platform-api-map.json",
                source_object=str(callsite.get("id") or ""),
                field=selector,
                source_address=str(callsite.get("call_site") or "") or None,
                basis="The platform map identifies a UIKit-owned Objective-C message callsite and selector",
                confidence="high" if callsite.get("classification") == "exact" else "medium" if callsite.get("classification") == "candidate_set" else "low",
            )],
            "failure_reasons": (
                [] if classification == "exact"
                else ["uikit_callsite_does_not_map_to_one_exact_screen"]
            ),
        })
        for screen_id in screen_candidates:
            screen_by_id[screen_id]["code_operation_ids"].append(operation_id)
        if classification == "candidate_set":
            hypotheses.append({
                "id": _stable_id("ui-hypothesis", operation_id),
                "kind": "candidate_ui_code_operation",
                "subject_id": operation_id,
                "candidate_ids": screen_candidates,
                "confidence": "medium",
                "basis": "The UIKit callsite is exact or bounded, but its runtime screen instance is not unique",
            })

    connections.sort(key=lambda item: (item.get("screen_id") or "", item["id"]))
    constraints.sort(key=lambda item: (item.get("screen_id") or "", item["id"]))
    navigation_edges.sort(key=lambda item: (item.get("source_screen_id") or "", item["id"]))
    resource_references.sort(key=lambda item: (item["screen_id"], item["element_id"], item["field"], item["id"]))
    code_operations.sort(key=lambda item: (_address_key(item.get("call_site")), item["id"]))
    hypotheses.sort(key=lambda item: (item["kind"], item["subject_id"], item["id"]))
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))
    for screen in screens:
        for key in ("connection_ids", "constraint_ids", "navigation_edge_ids", "code_operation_ids"):
            screen[key] = sorted(set(screen[key]))
    artifact_by_path = {item["path"]: item for item in interface_artifacts}
    for screen in screens:
        if screen["source_path"] in artifact_by_path:
            artifact_by_path[screen["source_path"]]["screen_ids"].append(screen["id"])
    for item in interface_artifacts:
        item["screen_ids"] = sorted(set(item["screen_ids"]))

    classified_records = [
        *screens,
        *elements,
        *connections,
        *constraints,
        *navigation_edges,
        *resource_references,
        *code_operations,
    ]
    failure_counts = Counter(
        reason
        for item in classified_records
        for reason in item.get("failure_reasons", [])
    )
    summary = {
        "interface_artifact_count": len(interface_artifacts),
        "decoded_interface_artifact_count": sum(item["status"] == "decoded" for item in interface_artifacts),
        "partial_interface_artifact_count": sum(item["status"] == "partial" for item in interface_artifacts),
        "unresolved_interface_artifact_count": sum(item["status"] == "unresolved" for item in interface_artifacts),
        "screen_count": len(screens),
        "element_count": len(elements),
        "connection_count": len(connections),
        "constraint_count": len(constraints),
        "navigation_edge_count": len(navigation_edges),
        "localization_entry_count": len(localizations),
        "ui_asset_count": len(ui_assets),
        "resource_reference_count": len(resource_references),
        "code_operation_count": len(code_operations),
        "classified_record_count": len(classified_records),
        "classification_counts": _classification_counts(classified_records),
        "failure_reason_counts": dict(sorted(failure_counts.items())),
        "error_count": len(errors),
    }
    facts = {
        "catalog": {
            "catalog_id": catalog["catalog_id"],
            "catalog_version": catalog["catalog_version"],
            "sha256": catalog_sha256,
            "controller_class_count": len(catalog["controller_classes"]),
            "element_tag_count": len(catalog["element_tags"]),
            "selector_count": len(catalog["selectors"]),
        },
        "input_artifacts": input_artifacts,
        "bundle_entrypoints": bundle_entrypoints,
        "summary": summary,
        "interface_artifacts": sorted(interface_artifacts, key=lambda item: item["path"]),
        "screens": screens,
        "elements": elements,
        "connections": connections,
        "constraints": constraints,
        "navigation_edges": navigation_edges,
        "localizations": localizations,
        "assets": sorted(ui_assets, key=lambda item: (item["bundle_relative_path"], item["id"])),
        "resource_references": resource_references,
        "code_operations": code_operations,
        "indexes": {
            "screens_by_controller": [
                {"controller_class_name": name, "screen_ids": sorted(values)}
                for name, values in sorted(screens_by_controller.items())
            ],
            "screens_by_source": [
                {"source_path": path, "screen_ids": sorted(item["screen_ids"])}
                for path, item in sorted(artifact_by_path.items())
            ],
            "assets_by_logical_name": [
                {"logical_name": name, "asset_ids": sorted(item["id"] for item in values)}
                for name, values in sorted(
                    (
                        (name, [item for item in ui_assets if item["logical_name"] == name])
                        for name in sorted({item["logical_name"] for item in ui_assets})
                    ),
                    key=lambda pair: pair[0],
                )
            ],
        },
        "evidence_boundary": {
            "application_specific_rules_used": False,
            "visual_similarity_used_as_evidence": False,
            "names_used_to_invent_behavior": False,
            "programmatic_screen_candidates_marked_as_hypotheses": True,
            "function_level_resources_promoted_to_call_arguments": False,
            "upstream_artifacts_preserved": True,
        },
    }
    ui_model = report_envelope("ui-model", facts, hypotheses=hypotheses, errors=errors)
    ui_model_path = workspace / "analysis" / "ui-model.json"
    report_path = workspace / "reports" / "ui-reconstruction-report.md"
    write_json_atomic(ui_model_path, ui_model)
    write_text_atomic(report_path, _render_ui_report(facts))
    return UIRecoveryResult(workspace, ui_model, ui_model_path, report_path)
