"""Deterministic, evidence-linked platform API dependency mapping."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .report import render_platform_api_map_report
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class PlatformAPIMapError(IPALiftError):
    """A workspace cannot support trustworthy platform API mapping."""


@dataclass(frozen=True)
class PlatformAPIMapResult:
    workspace: Path
    platform_map: dict[str, Any]
    platform_map_path: Path
    report_path: Path


REQUIRED_REPORTS = (
    "architectures",
    "frameworks",
    "functions",
    "callgraph",
    "recovered-code-index",
    "objc-dispatch",
    "objc-type-flow",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
MESSAGE_STATUSES = (
    "external_exact",
    "external_candidate",
    "application_local",
    "unresolved",
)
DYLIB_COMMANDS = {
    "LC_LOAD_DYLIB",
    "LC_LOAD_WEAK_DYLIB",
    "LC_REEXPORT_DYLIB",
    "LC_LOAD_UPWARD_DYLIB",
}
_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-f]+$")
_PSEUDO_CALL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$])(?P<callee>_?objc_msg(?:send|lookup)[A-Za-z0-9_$]*)\s*\(",
    re.IGNORECASE,
)
_EXPLICIT_CLASS_PATTERNS = (
    re.compile(r"&?\s*objc::class_t::([A-Za-z_$][A-Za-z0-9_$]*)\s*$"),
    re.compile(r"&?\s*_OBJC_CLASS___([A-Za-z_$][A-Za-z0-9_$]*)\s*$"),
    re.compile(r"&?\s*_OBJC_CLASS_\$_([A-Za-z_$][A-Za-z0-9_$]*)\s*$"),
)
_CLASS_IMPORT_PREFIX = "_OBJC_CLASS_$_"
_METACLASS_IMPORT_PREFIX = "_OBJC_METACLASS_$_"
_PROTOCOL_IMPORT_PREFIX = "_OBJC_PROTOCOL_$_"
_EXTERNAL_PREFIX = "<EXTERNAL>::"


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PlatformAPIMapError(
            f"Analysis workspace is missing analysis/{name}.json"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise PlatformAPIMapError(f"Cannot read {path}: {exc}") from exc
    if (
        report.get("schema_version") != 1
        or report.get("artifact") != name
        or not isinstance(report.get("facts"), dict)
    ):
        raise PlatformAPIMapError(f"Invalid IPALift {name} report: {path}")
    return report


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = relative.replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise PlatformAPIMapError(
            f"Artifact path escapes the analysis workspace: {relative}"
        )
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise PlatformAPIMapError(
            f"Artifact path escapes the analysis workspace: {relative}"
        ) from exc
    return candidate


def _address(value: Any) -> str | None:
    if value is None:
        return None
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return f"0x{number:08x}"


def _address_key(value: str | None) -> tuple[int, str]:
    if value and _ADDRESS_PATTERN.match(value):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return f"{kind}:{digest}"


def _load_catalog() -> tuple[dict[str, Any], str]:
    resource = importlib.resources.files("ipalift").joinpath(
        "catalogs/platform-apis-v1.json"
    )
    try:
        data = resource.read_bytes()
        catalog = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlatformAPIMapError(f"Cannot load the platform API catalog: {exc}") from exc
    required = {
        "catalog_id",
        "catalog_version",
        "description",
        "categories",
        "libraries",
        "classes",
        "protocols",
    }
    if not isinstance(catalog, dict) or set(catalog) != required:
        raise PlatformAPIMapError("Platform API catalog has an invalid top-level shape")
    category_ids = [str(item.get("id") or "") for item in catalog["categories"]]
    if not all(category_ids) or len(category_ids) != len(set(category_ids)):
        raise PlatformAPIMapError("Platform API catalog has duplicate or empty categories")
    valid_categories = set(category_ids)
    for collection_name in ("libraries", "classes", "protocols"):
        if not isinstance(catalog[collection_name], list):
            raise PlatformAPIMapError(
                f"Platform API catalog {collection_name} must be an array"
            )
        for item in catalog[collection_name]:
            if not isinstance(item, dict):
                raise PlatformAPIMapError(
                    f"Platform API catalog {collection_name} contains a non-object"
                )
            categories = item.get("default_categories", item.get("categories", []))
            if (
                not isinstance(categories, list)
                or len(categories) != len(set(categories))
                or not set(categories).issubset(valid_categories)
            ):
                raise PlatformAPIMapError(
                    f"Platform API catalog {collection_name} has invalid categories"
                )
    library_names = [
        str(name)
        for item in catalog["libraries"]
        for name in item.get("match_names", [])
    ]
    class_names = [str(item.get("name") or "") for item in catalog["classes"]]
    protocol_names = [str(item.get("name") or "") for item in catalog["protocols"]]
    if (
        not all(library_names)
        or len(library_names) != len(set(library_names))
        or not all(class_names)
        or len(class_names) != len(set(class_names))
        or not all(protocol_names)
        or len(protocol_names) != len(set(protocol_names))
    ):
        raise PlatformAPIMapError("Platform API catalog has duplicate or empty names")
    return catalog, hashlib.sha256(data).hexdigest()


class _CatalogIndex:
    def __init__(self, catalog: dict[str, Any]):
        self.catalog = catalog
        self.categories = {
            str(item["id"]): item for item in catalog["categories"]
        }
        self.libraries: dict[str, dict[str, Any]] = {}
        for item in catalog["libraries"]:
            for name in item["match_names"]:
                self.libraries[str(name)] = item
        self.classes = {
            str(item["name"]): item for item in catalog["classes"]
        }
        self.protocols = {
            str(item["name"]): item for item in catalog["protocols"]
        }

    def library(self, name: str | None) -> dict[str, Any] | None:
        return self.libraries.get(str(name)) if name else None

    def class_record(self, name: str) -> dict[str, Any] | None:
        return self.classes.get(name)

    def protocol_record(self, name: str) -> dict[str, Any] | None:
        return self.protocols.get(name)


def _balanced_end(value: str, start: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(value)):
        char = value[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_arguments(value: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    pairs = {")": "(", "]": "[", "}": "{"}
    for index, char in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}" and stack and stack[-1] == pairs[char]:
            stack.pop()
        elif char == "," and not stack:
            arguments.append(value[start:index].strip())
            start = index + 1
    arguments.append(value[start:].strip())
    return arguments


def _string_literal(value: str) -> str | None:
    match = re.fullmatch(r'\s*"((?:\\.|[^"\\])*)"\s*', value, re.DOTALL)
    if not match:
        return None
    try:
        decoded = bytes(match.group(1), "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return None
    return decoded


def _explicit_class(value: str) -> str | None:
    rendered = value.strip()
    for pattern in _EXPLICIT_CLASS_PATTERNS:
        match = pattern.fullmatch(rendered)
        if match:
            return match.group(1)
    return None


def _parse_explicit_class_messages(code: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for match in _PSEUDO_CALL_PATTERN.finditer(code):
        opening = match.end() - 1
        closing = _balanced_end(code, opening)
        if closing is None:
            continue
        arguments = _split_arguments(code[opening + 1:closing])
        if len(arguments) < 2:
            continue
        selector = _string_literal(arguments[1])
        class_name = _explicit_class(arguments[0])
        if not selector or not class_name:
            continue
        result.append({
            "family": "super" if "super" in match.group("callee").lower() else "normal",
            "selector": selector,
            "class_name": class_name,
            "receiver_expression": arguments[0].strip()[:240],
        })
    return result


def _frameworks_for_class(
    architecture: str,
    class_name: str,
    class_imports: dict[tuple[str, str], dict[str, Any]],
    catalog: _CatalogIndex,
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    frameworks: set[str] = set()
    categories: set[str] = set()
    ownership: list[dict[str, Any]] = []
    imported = class_imports.get((architecture, class_name))
    if imported and imported.get("linkage"):
        linkage = imported["linkage"]
        frameworks.add(str(linkage["name"]))
        ownership.append({
            "kind": "macho_linkage",
            "framework": linkage["name"],
            "path": linkage["path"],
            "confidence": "high",
            "source": "analysis/architectures.json",
        })
        library_catalog = catalog.library(str(linkage["name"]))
        if library_catalog:
            frameworks.add(str(library_catalog["framework"]))
            categories.update(str(value) for value in library_catalog["default_categories"])
    class_catalog = catalog.class_record(class_name)
    if class_catalog:
        frameworks.add(str(class_catalog["framework"]))
        categories.update(str(value) for value in class_catalog["categories"])
        ownership.append({
            "kind": "catalog_api_owner",
            "framework": class_catalog["framework"],
            "path": None,
            "confidence": "high",
            "source": "ipalift/catalogs/platform-apis-v1.json",
        })
    ownership.sort(key=lambda item: (item["kind"], item["framework"], item["path"] or ""))
    return sorted(frameworks), sorted(categories), ownership


def _component_context(
    function_id: str,
    raw_function_by_id: dict[str, dict[str, Any]],
    recovered_function_by_id: dict[str, dict[str, Any]],
    methods_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    raw = raw_function_by_id.get(function_id) or {}
    recovered = recovered_function_by_id.get(function_id) or {}
    method_ids = sorted(
        str(value)
        for value in recovered.get("method_ids", [])
        if str(value) in methods_by_id
    )
    class_names = sorted({
        str(methods_by_id[method_id].get("class_name"))
        for method_id in method_ids
        if methods_by_id[method_id].get("class_name")
    })
    return {
        "function_id": function_id,
        "function_address": raw.get("address"),
        "function_name": raw.get("name"),
        "method_ids": method_ids,
        "class_names": class_names,
    }


def _dependency(
    *,
    dependency_id: str,
    kind: str,
    classification: str,
    architecture: str,
    symbol: str | None = None,
    selector: str | None = None,
    class_names: Iterable[str] = (),
    protocol_name: str | None = None,
    callback_contract: str | None = None,
    frameworks: Iterable[str] = (),
    categories: Iterable[str] = (),
    source_addresses: Iterable[str] = (),
    call_sites: Iterable[str] = (),
    affected_function_ids: Iterable[str] = (),
    affected_method_ids: Iterable[str] = (),
    affected_class_names: Iterable[str] = (),
    provenance: Iterable[str] = (),
    evidence: Iterable[dict[str, Any]] = (),
    failure_reasons: Iterable[str] = (),
) -> dict[str, Any]:
    return {
        "id": dependency_id,
        "kind": kind,
        "classification": classification,
        "architecture": architecture,
        "symbol": symbol,
        "selector": selector,
        "class_names": sorted(set(class_names)),
        "protocol_name": protocol_name,
        "callback_contract": callback_contract,
        "frameworks": sorted(set(frameworks)),
        "categories": sorted(set(categories)),
        "source_addresses": sorted(
            {value for value in source_addresses if value},
            key=_address_key,
        ),
        "call_sites": sorted(
            {value for value in call_sites if value},
            key=_address_key,
        ),
        "affected_function_ids": sorted(set(affected_function_ids)),
        "affected_method_ids": sorted(set(affected_method_ids)),
        "affected_class_names": sorted(set(affected_class_names)),
        "confidence": {
            "exact": "high",
            "candidate_set": "medium",
            "unresolved": "low",
        }[classification],
        "provenance": sorted(set(provenance)),
        "evidence": sorted(
            list(evidence),
            key=lambda item: (
                str(item.get("kind") or ""),
                str(item.get("source") or ""),
                _address_key(_address(item.get("source_address"))),
                json.dumps(item.get("details") or {}, sort_keys=True),
            ),
        ),
        "failure_reasons": sorted(set(failure_reasons)),
    }


def _evidence(
    kind: str,
    source: str,
    *,
    source_address: str | None,
    confidence: str,
    provenance: Iterable[str],
    basis: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "source": source,
        "source_address": source_address,
        "confidence": confidence,
        "provenance": sorted(set(provenance)),
        "basis": basis,
        "details": details or {},
    }


def _external_symbol_name(edge: dict[str, Any]) -> str | None:
    thunk = str(edge.get("thunk_target_name") or "")
    if thunk.startswith(_EXTERNAL_PREFIX):
        return thunk[len(_EXTERNAL_PREFIX):]
    return None


def _method_sort_key(item: dict[str, Any]) -> tuple[str, str, str, tuple[int, str], str]:
    return (
        str(item.get("architecture") or "unknown"),
        str(item.get("class_name") or "").casefold(),
        str(item.get("selector") or ""),
        _address_key(_address(item.get("canonical_address"))),
        str(item.get("id") or ""),
    )


def map_platform_apis(workspace: Path) -> PlatformAPIMapResult:
    """Build the workspace's deterministic platform dependency inventory."""
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise PlatformAPIMapError(
            f"Analysis workspace does not exist: {workspace}"
        ) from exc
    if not workspace.is_dir():
        raise PlatformAPIMapError(
            f"Analysis workspace is not a directory: {workspace}"
        )

    reports = {name: _load_report(workspace, name) for name in REQUIRED_REPORTS}
    catalog_document, catalog_sha256 = _load_catalog()
    catalog = _CatalogIndex(catalog_document)

    architecture_facts = reports["architectures"]["facts"]
    architectures = list(architecture_facts.get("architectures", []))
    if len(architectures) != architecture_facts.get("architecture_count"):
        raise PlatformAPIMapError(
            "architectures.json count does not match its architecture inventory"
        )
    framework_facts = reports["frameworks"]["facts"]
    linked_libraries = list(framework_facts.get("linked_libraries", []))
    if len(linked_libraries) != framework_facts.get("linked_library_count"):
        raise PlatformAPIMapError(
            "frameworks.json count does not match its linked-library inventory"
        )
    function_facts = reports["functions"]["facts"]
    raw_functions = list(function_facts.get("functions", []))
    if len(raw_functions) != function_facts.get("discovered_function_count"):
        raise PlatformAPIMapError(
            "functions.json count does not match its function inventory"
        )
    callgraph_facts = reports["callgraph"]["facts"]
    call_edges = list(callgraph_facts.get("edges", []))
    if len(call_edges) != callgraph_facts.get("edge_count"):
        raise PlatformAPIMapError(
            "callgraph.json count does not match its edge inventory"
        )
    recovered = reports["recovered-code-index"]["facts"]
    recovered_functions = list(recovered.get("functions", []))
    methods = list(recovered.get("methods", []))
    classes = list(recovered.get("classes", []))
    categories = list(recovered.get("categories", []))
    if len(recovered_functions) != recovered.get("function_count"):
        raise PlatformAPIMapError(
            "recovered-code-index.json function count does not match its inventory"
        )
    if len(methods) != recovered.get("objective_c_method_count"):
        raise PlatformAPIMapError(
            "recovered-code-index.json method count does not match its inventory"
        )
    dispatch_facts = reports["objc-dispatch"]["facts"]
    dispatch_callsites = list(dispatch_facts.get("callsites", []))
    if len(dispatch_callsites) != dispatch_facts.get("dispatch_callsite_count"):
        raise PlatformAPIMapError(
            "objc-dispatch.json count does not match its callsite inventory"
        )
    type_flow_facts = reports["objc-type-flow"]["facts"]
    type_refinements = list(type_flow_facts.get("dispatch_refinements", []))
    if len(type_refinements) != type_flow_facts.get("dispatch_refinement_count"):
        raise PlatformAPIMapError(
            "objc-type-flow.json count does not match its refinement inventory"
        )

    raw_function_by_id = {str(item["id"]): item for item in raw_functions}
    recovered_function_by_id = {
        str(item["function_id"]): item for item in recovered_functions
    }
    methods_by_id = {str(item["id"]): item for item in methods}
    if len(raw_function_by_id) != len(raw_functions):
        raise PlatformAPIMapError("functions.json contains duplicate function IDs")
    if len(recovered_function_by_id) != len(recovered_functions):
        raise PlatformAPIMapError(
            "recovered-code-index.json contains duplicate function IDs"
        )
    if len(methods_by_id) != len(methods):
        raise PlatformAPIMapError(
            "recovered-code-index.json contains duplicate method IDs"
        )

    known_architectures = sorted(
        str(item.get("architecture") or "unknown") for item in architectures
    )
    sole_architecture = known_architectures[0] if len(known_architectures) == 1 else None
    function_architectures: dict[str, list[str]] = {}
    for function_id in sorted(raw_function_by_id):
        values = {
            str(methods_by_id[method_id].get("architecture") or "unknown")
            for method_id in recovered_function_by_id.get(function_id, {}).get("method_ids", [])
            if method_id in methods_by_id
        }
        if values:
            function_architectures[function_id] = sorted(values)
        elif sole_architecture:
            function_architectures[function_id] = [sole_architecture]
        else:
            function_architectures[function_id] = known_architectures

    import_records: list[dict[str, Any]] = []
    import_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    class_imports: dict[tuple[str, str], dict[str, Any]] = {}
    library_loads_by_architecture: dict[str, list[dict[str, Any]]] = {}
    for architecture in sorted(
        architectures, key=lambda item: str(item.get("architecture") or "unknown")
    ):
        architecture_name = str(architecture.get("architecture") or "unknown")
        dylibs = sorted(
            [
                item
                for item in architecture.get("load_commands", [])
                if item.get("command") in DYLIB_COMMANDS
            ],
            key=lambda item: int(item.get("index") or 0),
        )
        library_loads_by_architecture[architecture_name] = dylibs
        for imported in sorted(
            architecture.get("imports", []),
            key=lambda item: (
                str(item.get("name") or ""),
                int(item.get("library_ordinal") or 0),
                bool(item.get("weak_reference")),
            ),
        ):
            name = str(imported.get("name") or "")
            ordinal = int(imported.get("library_ordinal") or 0)
            linkage = None
            failure_reasons: list[str] = []
            if 1 <= ordinal <= len(dylibs):
                library = dylibs[ordinal - 1]
                linkage = {
                    "name": str(library.get("name") or ""),
                    "path": str(library.get("path") or ""),
                    "kind": str(library.get("kind") or "unknown"),
                    "load_command_index": int(library.get("index") or 0),
                }
            else:
                failure_reasons.append("macho_library_ordinal_does_not_name_a_loaded_library")
            if name.startswith(_CLASS_IMPORT_PREFIX):
                symbol_kind = "objective_c_class"
                class_name = name[len(_CLASS_IMPORT_PREFIX):]
            elif name.startswith(_METACLASS_IMPORT_PREFIX):
                symbol_kind = "objective_c_metaclass"
                class_name = name[len(_METACLASS_IMPORT_PREFIX):]
            elif name.startswith(_PROTOCOL_IMPORT_PREFIX):
                symbol_kind = "objective_c_protocol"
                class_name = None
            else:
                symbol_kind = "unknown"
                class_name = None
            library_catalog = catalog.library(linkage["name"]) if linkage else None
            record = {
                "id": _stable_id(
                    "platform-import",
                    architecture_name,
                    name,
                    ordinal,
                    bool(imported.get("weak_reference")),
                ),
                "architecture": architecture_name,
                "name": name,
                "symbol_kind": symbol_kind,
                "weak_reference": bool(imported.get("weak_reference")),
                "library_ordinal": ordinal,
                "linkage": linkage,
                "catalog_framework": (
                    str(library_catalog["framework"]) if library_catalog else None
                ),
                "categories": (
                    sorted(str(value) for value in library_catalog["default_categories"])
                    if library_catalog
                    else []
                ),
                "external_function_ids": [],
                "direct_call_sites": [],
                "classification": "exact" if linkage else "unresolved",
                "failure_reasons": failure_reasons,
            }
            key = (architecture_name, name)
            if key in import_by_key:
                raise PlatformAPIMapError(
                    f"Duplicate Mach-O import identity: {architecture_name} {name}"
                )
            import_by_key[key] = record
            import_records.append(record)
            if class_name and symbol_kind == "objective_c_class":
                class_imports[(architecture_name, class_name)] = record

    external_function_ids_by_import: dict[tuple[str, str], set[str]] = defaultdict(set)
    for function in raw_functions:
        if not function.get("external"):
            continue
        function_id = str(function["id"])
        for imported in function.get("macho_imports", []):
            key = (
                str(imported.get("architecture") or "unknown"),
                str(imported.get("name") or ""),
            )
            if key in import_by_key:
                external_function_ids_by_import[key].add(function_id)
    for key, values in external_function_ids_by_import.items():
        import_by_key[key]["external_function_ids"] = sorted(values)
        if import_by_key[key]["symbol_kind"] == "unknown":
            import_by_key[key]["symbol_kind"] = "function"

    direct_calls_by_import: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        if edge.get("objective_c_dispatch"):
            continue
        symbol = _external_symbol_name(edge)
        if not symbol:
            continue
        caller_id = str(edge.get("caller_id") or "")
        for architecture_name in function_architectures.get(
            caller_id, known_architectures
        ):
            key = (architecture_name, symbol)
            if key in import_by_key:
                direct_calls_by_import[key].append(edge)
    for key, edges in direct_calls_by_import.items():
        record = import_by_key[key]
        record["direct_call_sites"] = sorted({
            address
            for edge in edges
            if (address := _address(edge.get("call_site")))
        }, key=_address_key)
        if record["symbol_kind"] == "unknown":
            record["symbol_kind"] = "function"

    import_records.sort(
        key=lambda item: (
            item["architecture"],
            item["name"],
            item["library_ordinal"],
            item["id"],
        )
    )

    dependencies: list[dict[str, Any]] = []

    # Imported native functions are owned only through the Mach-O ordinal. A
    # catalog match adds categories, but never replaces missing linkage.
    for imported in import_records:
        if imported["symbol_kind"] in {
            "objective_c_class",
            "objective_c_metaclass",
            "objective_c_protocol",
        }:
            continue
        key = (imported["architecture"], imported["name"])
        edges = direct_calls_by_import.get(key, [])
        caller_ids = sorted({
            str(edge.get("caller_id") or "")
            for edge in edges
            if edge.get("caller_id")
        })
        contexts = [
            _component_context(
                function_id,
                raw_function_by_id,
                recovered_function_by_id,
                methods_by_id,
            )
            for function_id in caller_ids
        ]
        method_ids = sorted({
            method_id for context in contexts for method_id in context["method_ids"]
        })
        class_names = sorted({
            class_name for context in contexts for class_name in context["class_names"]
        })
        frameworks_for_import: set[str] = set()
        if imported["linkage"]:
            frameworks_for_import.add(str(imported["linkage"]["name"]))
        if imported["catalog_framework"]:
            frameworks_for_import.add(str(imported["catalog_framework"]))
        import_evidence = [
            _evidence(
                "macho_import",
                "analysis/architectures.json",
                source_address=None,
                confidence="high" if imported["linkage"] else "low",
                provenance=("macho_load_commands", "macho_symbol_table"),
                basis="Mach-O import and library ordinal identify the linked owner",
                details={
                    "import_id": imported["id"],
                    "library_ordinal": imported["library_ordinal"],
                    "weak_reference": imported["weak_reference"],
                },
            )
        ]
        for edge in edges:
            import_evidence.append(
                _evidence(
                    "direct_call_edge",
                    "analysis/callgraph.json",
                    source_address=_address(edge.get("call_site")),
                    confidence="high",
                    provenance=("ghidra", "ghidra_callgraph"),
                    basis="Ghidra direct edge reaches a thunk whose external target matches the import",
                    details={
                        "caller_function_id": edge.get("caller_id"),
                        "thunk_target_name": edge.get("thunk_target_name"),
                    },
                )
            )
        dependencies.append(
            _dependency(
                dependency_id=_stable_id(
                    "platform-dependency-imported-function",
                    imported["architecture"],
                    imported["name"],
                    imported["library_ordinal"],
                ),
                kind="imported_function",
                classification=imported["classification"],
                architecture=imported["architecture"],
                symbol=imported["name"],
                frameworks=frameworks_for_import,
                categories=imported["categories"],
                source_addresses=imported["direct_call_sites"],
                call_sites=imported["direct_call_sites"],
                affected_function_ids=caller_ids,
                affected_method_ids=method_ids,
                affected_class_names=class_names,
                provenance=(
                    "macho_load_commands",
                    "macho_symbol_table",
                    *(("ghidra_callgraph",) if edges else ()),
                ),
                evidence=import_evidence,
                failure_reasons=imported["failure_reasons"],
            )
        )

    # Only exact Ghidra references to imported class symbols are class-reference
    # evidence. Pointer aliases and name proximity do not qualify.
    class_reference_groups: dict[
        tuple[str, str], list[tuple[str, dict[str, Any]]]
    ] = defaultdict(list)
    for function in raw_functions:
        if function.get("external"):
            continue
        function_id = str(function["id"])
        for xref in function.get("cross_references", []):
            target_symbol = str(xref.get("target_symbol") or "")
            if not target_symbol.startswith(_CLASS_IMPORT_PREFIX):
                continue
            class_name = target_symbol[len(_CLASS_IMPORT_PREFIX):]
            for architecture_name in function_architectures.get(
                function_id, known_architectures
            ):
                if (architecture_name, class_name) in class_imports:
                    class_reference_groups[(architecture_name, class_name)].append(
                        (function_id, xref)
                    )

    external_class_references: list[dict[str, Any]] = []
    for (architecture_name, class_name), references in sorted(
        class_reference_groups.items()
    ):
        imported = class_imports[(architecture_name, class_name)]
        function_ids = sorted({function_id for function_id, _ in references})
        contexts = [
            _component_context(
                function_id,
                raw_function_by_id,
                recovered_function_by_id,
                methods_by_id,
            )
            for function_id in function_ids
        ]
        method_ids = sorted({
            method_id for context in contexts for method_id in context["method_ids"]
        })
        affected_classes = sorted({
            value for context in contexts for value in context["class_names"]
        })
        source_addresses = sorted({
            value
            for _, xref in references
            if (value := _address(xref.get("from_address")))
        }, key=_address_key)
        class_frameworks, class_categories, ownership = _frameworks_for_class(
            architecture_name, class_name, class_imports, catalog
        )
        classification = "exact" if imported["linkage"] else "unresolved"
        evidence = [
            _evidence(
                "external_class_xref",
                "analysis/functions.json",
                source_address=_address(xref.get("from_address")),
                confidence="high",
                provenance=("ghidra", "macho_symbol_table"),
                basis="Exact Ghidra reference targets an imported Objective-C class symbol",
                details={
                    "function_id": function_id,
                    "target_symbol": xref.get("target_symbol"),
                    "to_address": _address(xref.get("to_address")),
                    "reference_type": xref.get("reference_type"),
                },
            )
            for function_id, xref in references
        ]
        evidence.append(
            _evidence(
                "class_ownership",
                "analysis/architectures.json",
                source_address=None,
                confidence="high" if imported["linkage"] else "low",
                provenance=("macho_load_commands", "macho_symbol_table"),
                basis="The imported class symbol's ordinal identifies its linked owner",
                details={"ownership": ownership, "import_id": imported["id"]},
            )
        )
        dependency = _dependency(
            dependency_id=_stable_id(
                "platform-dependency-external-class",
                architecture_name,
                class_name,
            ),
            kind="external_class_reference",
            classification=classification,
            architecture=architecture_name,
            symbol=f"{_CLASS_IMPORT_PREFIX}{class_name}",
            class_names=(class_name,),
            frameworks=class_frameworks,
            categories=class_categories,
            source_addresses=source_addresses,
            affected_function_ids=function_ids,
            affected_method_ids=method_ids,
            affected_class_names=affected_classes,
            provenance=("ghidra", "macho_load_commands", "macho_symbol_table"),
            evidence=evidence,
            failure_reasons=imported["failure_reasons"],
        )
        dependencies.append(dependency)
        external_class_references.append(dependency)

    # Pseudocode is used only to recognize an explicit imported class-object
    # receiver. A mapping is accepted only for a one-to-one
    # caller/runtime-family/selector group.
    pseudocode_artifacts: list[dict[str, Any]] = []
    explicit_messages: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for recovered_function in sorted(
        recovered_functions, key=lambda item: str(item.get("function_id") or "")
    ):
        decompilation = recovered_function.get("decompilation") or {}
        relative = decompilation.get("output_path")
        if decompilation.get("status") != "success" or not relative:
            continue
        path = _relative_file(workspace, str(relative))
        try:
            code = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PlatformAPIMapError(
                f"Cannot read pseudocode artifact {path}: {exc}"
            ) from exc
        digest = sha256_file(path)
        expected_digest = str(decompilation.get("sha256") or "")
        if expected_digest and digest != expected_digest:
            raise PlatformAPIMapError(
                "Pseudocode artifact hash does not match "
                f"recovered-code-index.json: {relative}"
            )
        parsed = _parse_explicit_class_messages(code)
        pseudocode_artifacts.append({
            "function_id": str(recovered_function["function_id"]),
            "path": str(relative).replace("\\", "/"),
            "sha256": digest,
            "explicit_class_message_count": len(parsed),
        })
        for message in parsed:
            explicit_messages[
                (
                    str(recovered_function["function_id"]),
                    message["family"],
                    message["selector"],
                )
            ].append(message)

    dispatch_groups: Counter[tuple[str, str, str]] = Counter()
    for callsite in dispatch_callsites:
        selector_record = callsite.get("selector") or {}
        if (
            selector_record.get("status") != "resolved"
            or not selector_record.get("value")
        ):
            continue
        dispatch_groups[
            (
                str((callsite.get("caller") or {}).get("function_id") or ""),
                "super"
                if (callsite.get("direct_runtime_edge") or {}).get("super_dispatch")
                else "normal",
                str(selector_record["value"]),
            )
        ] += 1

    refinement_by_callsite = {
        str(item.get("callsite_id") or ""): item for item in type_refinements
    }
    internal_class_names = {str(item.get("name") or "") for item in classes}
    message_callsites: list[dict[str, Any]] = []
    for callsite in sorted(
        dispatch_callsites,
        key=lambda item: (
            str(item.get("architecture") or "unknown"),
            _address_key(_address(item.get("call_site"))),
            str(item.get("id") or ""),
        ),
    ):
        architecture_name = str(
            callsite.get("architecture") or sole_architecture or "unknown"
        )
        caller = callsite.get("caller") or {}
        caller_id = str(caller.get("function_id") or "")
        call_site = _address(callsite.get("call_site"))
        selector_record = callsite.get("selector") or {}
        selector = (
            str(selector_record.get("value"))
            if selector_record.get("status") == "resolved"
            and selector_record.get("value")
            else None
        )
        super_dispatch = bool(
            (callsite.get("direct_runtime_edge") or {}).get("super_dispatch")
        )
        family = "super" if super_dispatch else "normal"
        explicit_class_name: str | None = None
        pseudocode_evidence: dict[str, Any] | None = None
        group_key = (caller_id, family, selector or "")
        parsed_matches = explicit_messages.get(group_key, []) if selector else []
        if (
            selector
            and dispatch_groups[group_key] == 1
            and len(parsed_matches) == 1
        ):
            parsed_class = parsed_matches[0]["class_name"]
            if (architecture_name, parsed_class) in class_imports:
                explicit_class_name = parsed_class
                artifact = next(
                    (
                        item
                        for item in pseudocode_artifacts
                        if item["function_id"] == caller_id
                    ),
                    None,
                )
                pseudocode_evidence = _evidence(
                    "explicit_class_receiver",
                    str(artifact["path"])
                    if artifact
                    else "decompiled/functions",
                    source_address=call_site,
                    confidence="high",
                    provenance=(
                        "ghidra",
                        "ghidra_pseudocode",
                        "macho_symbol_table",
                    ),
                    basis=(
                        "One explicit imported class receiver maps to one dispatch "
                        "callsite for the caller, runtime family, and selector"
                    ),
                    details={
                        "class_name": parsed_class,
                        "receiver_expression": parsed_matches[0][
                            "receiver_expression"
                        ],
                        "pseudocode_sha256": (
                            artifact["sha256"] if artifact else None
                        ),
                    },
                )

        refinement = (
            None
            if super_dispatch
            else refinement_by_callsite.get(str(callsite.get("id") or ""))
        )
        refined_receiver = callsite.get("refined_receiver") or {}
        baseline_receiver = callsite.get("receiver") or {}
        receiver_kind = str(
            (refinement or {}).get("receiver_kind")
            or refined_receiver.get("receiver_kind")
            or baseline_receiver.get("receiver_kind")
            or "unknown"
        )
        receiver_candidates = sorted({
            str(value)
            for value in (
                (refinement or {}).get("class_candidates")
                or refined_receiver.get("class_candidates")
                or baseline_receiver.get("class_candidates")
                or []
            )
            if value
        })
        if explicit_class_name:
            receiver_candidates = [explicit_class_name]
            receiver_kind = "class_object"

        super_lookup_paths = list(
            callsite.get("refined_lookup_paths")
            or callsite.get("lookup_paths")
            or []
        )
        super_lookup_start = next(
            (
                str(name)
                for name in super_lookup_paths
                if name
                and str(name) not in internal_class_names
                and (
                    (architecture_name, str(name)) in class_imports
                    or catalog.class_record(str(name)) is not None
                )
            ),
            None,
        ) if super_dispatch else None
        external_candidates = sorted({
            name
            for name in receiver_candidates
            if (
                (architecture_name, name) in class_imports
                or catalog.class_record(name) is not None
            )
            and name not in internal_class_names
        } | ({super_lookup_start} if super_lookup_start else set()))
        possible_targets = list(
            callsite.get("refined_possible_targets")
            or callsite.get("possible_targets")
            or []
        )
        local_target_method_ids = sorted({
            str(target.get("method_id"))
            for target in possible_targets
            if target.get("method_id")
        })
        message_frameworks: set[str] = set()
        message_categories: set[str] = set()
        ownership_evidence: list[dict[str, Any]] = []
        for class_name in external_candidates:
            (
                frameworks_for_class,
                categories_for_class,
                ownership,
            ) = _frameworks_for_class(
                architecture_name, class_name, class_imports, catalog
            )
            message_frameworks.update(frameworks_for_class)
            message_categories.update(categories_for_class)
            ownership_evidence.extend(ownership)

        refinement_classification = str(
            (refinement or {}).get("classification") or ""
        )
        if external_candidates:
            baseline_receiver_exact = (
                baseline_receiver.get("status") == "resolved"
                and receiver_kind in {"class_object", "super"}
            )
            exact_external = bool(
                len(external_candidates) == 1
                and (
                    explicit_class_name
                    or baseline_receiver_exact
                    or (
                        receiver_kind in {"class_object", "super"}
                        and refinement_classification == "exact"
                    )
                )
            )
            platform_status = (
                "external_exact" if exact_external else "external_candidate"
            )
            dependency_classification = (
                "exact" if exact_external else "candidate_set"
            )
        elif local_target_method_ids:
            platform_status = "application_local"
            dependency_classification = "exact"
        else:
            platform_status = "unresolved"
            dependency_classification = "unresolved"

        context = _component_context(
            caller_id,
            raw_function_by_id,
            recovered_function_by_id,
            methods_by_id,
        )
        message_failure_reasons = list(callsite.get("failure_reasons") or [])
        if selector is None:
            message_failure_reasons.append("selector_not_resolved")
        if platform_status == "external_candidate":
            if len(external_candidates) > 1:
                message_failure_reasons.append(
                    "multiple_external_receiver_candidates"
                )
            if any(name in internal_class_names for name in receiver_candidates):
                message_failure_reasons.append(
                    "receiver_candidates_cross_platform_boundary"
                )
            if receiver_kind not in {"class_object", "super"}:
                message_failure_reasons.append(
                    "instance_receiver_allows_dynamic_subclasses"
                )
        if platform_status == "unresolved":
            message_failure_reasons.append("platform_owner_not_proven")
        if platform_status == "external_exact":
            message_failure_reasons = []

        evidence = [
            _evidence(
                "objc_dispatch_callsite",
                "analysis/objc-dispatch.json",
                source_address=call_site,
                confidence=str(callsite.get("confidence") or "low"),
                provenance=callsite.get("provenance") or (),
                basis=(
                    "Objective-C runtime callsite, selector evidence, receiver "
                    "evidence, and local lookup results"
                ),
                details={
                    "dispatch_callsite_id": callsite.get("id"),
                    "dispatch_classification": callsite.get("classification"),
                    "refined_classification": callsite.get(
                        "refined_classification"
                    ),
                    "super_dispatch": super_dispatch,
                    "super_lookup_start": super_lookup_start,
                },
            )
        ]
        if super_lookup_start and baseline_receiver.get("status") == "resolved":
            evidence.append(
                _evidence(
                    "super_lookup_start",
                    "analysis/objc-dispatch.json",
                    source_address=call_site,
                    confidence="high",
                    provenance=(
                        "objective_c_metadata",
                        "objective_c_runtime_abi",
                    ),
                    basis="Exact recovered caller method and superclass hierarchy prove the external super lookup start",
                    details={
                        "class_name": super_lookup_start,
                        "lookup_paths": super_lookup_paths,
                        "caller_method_ids": caller.get(
                            "objective_c_method_ids"
                        ) or [],
                    },
                )
            )
        if (
            receiver_kind == "class_object"
            and baseline_receiver.get("status") == "resolved"
            and external_candidates
            and not pseudocode_evidence
        ):
            evidence.append(
                _evidence(
                    "class_object_receiver",
                    "analysis/objc-dispatch.json",
                    source_address=call_site,
                    confidence="high",
                    provenance=(
                        "ghidra",
                        "objective_c_metadata",
                        "objective_c_runtime_abi",
                    ),
                    basis="Resolved dispatch receiver evidence proves one external class object",
                    details={
                        "class_name": external_candidates[0],
                        "receiver_evidence": baseline_receiver.get("evidence") or [],
                    },
                )
            )
        if refinement:
            evidence.append(
                _evidence(
                    "objc_type_flow",
                    "analysis/objc-type-flow.json",
                    source_address=call_site,
                    confidence=str(refinement.get("confidence") or "low"),
                    provenance=("objective_c_type_flow",),
                    basis=(
                        "Type-flow refinement supplies an evidence-bounded "
                        "receiver candidate set"
                    ),
                    details={
                        "receiver_value_id": refinement.get("receiver_value_id"),
                        "evidence_ids": refinement.get("evidence_ids") or [],
                        "propagation_step_ids": refinement.get(
                            "propagation_step_ids"
                        ) or [],
                    },
                )
            )
        if pseudocode_evidence:
            evidence.append(pseudocode_evidence)
        if ownership_evidence:
            evidence.append(
                _evidence(
                    "class_ownership",
                    "ipalift/catalogs/platform-apis-v1.json",
                    source_address=call_site,
                    confidence="high",
                    provenance=("versioned_platform_api_catalog",),
                    basis=(
                        "Mach-O class linkage and explicit catalog entries supply "
                        "ownership and categories"
                    ),
                    details={
                        "ownership": sorted(
                            ownership_evidence,
                            key=lambda item: (
                                item["kind"], item["framework"]
                            ),
                        )
                    },
                )
            )

        message_id = _stable_id(
            "platform-message",
            architecture_name,
            caller_id,
            call_site,
            selector,
        )
        message_provenance = sorted({
            "objective_c_dispatch",
            *(("objective_c_type_flow",) if refinement else ()),
            *(("ghidra_pseudocode",) if pseudocode_evidence else ()),
            *(("versioned_platform_api_catalog",) if ownership_evidence else ()),
        })
        message_record = {
            "id": message_id,
            "dispatch_callsite_id": str(callsite.get("id") or ""),
            "architecture": architecture_name,
            "call_site": call_site,
            "caller_function_id": caller_id,
            "selector": selector,
            "selector_status": str(
                selector_record.get("status") or "unresolved"
            ),
            "receiver_kind": receiver_kind,
            "super_lookup_start": super_lookup_start,
            "receiver_class_candidates": receiver_candidates,
            "external_class_candidates": external_candidates,
            "local_target_method_ids": local_target_method_ids,
            "platform_status": platform_status,
            "classification": dependency_classification,
            "frameworks": sorted(message_frameworks),
            "categories": sorted(message_categories),
            "affected_method_ids": context["method_ids"],
            "affected_class_names": context["class_names"],
            "confidence": {
                "exact": "high",
                "candidate_set": "medium",
                "unresolved": "low",
            }[dependency_classification],
            "provenance": message_provenance,
            "evidence": sorted(
                evidence,
                key=lambda item: (
                    item["kind"],
                    item["source"],
                    _address_key(item["source_address"]),
                ),
            ),
            "failure_reasons": sorted(set(message_failure_reasons)),
        }
        message_callsites.append(message_record)

        if platform_status == "application_local":
            continue
        dependencies.append(
            _dependency(
                dependency_id=_stable_id(
                    "platform-dependency-objc-message",
                    architecture_name,
                    caller_id,
                    call_site,
                    selector,
                ),
                kind="objective_c_message",
                classification=dependency_classification,
                architecture=architecture_name,
                selector=selector,
                class_names=external_candidates,
                frameworks=message_frameworks,
                categories=message_categories,
                source_addresses=(call_site,) if call_site else (),
                call_sites=(call_site,) if call_site else (),
                affected_function_ids=(caller_id,) if caller_id else (),
                affected_method_ids=context["method_ids"],
                affected_class_names=context["class_names"],
                provenance=message_provenance,
                evidence=evidence,
                failure_reasons=message_failure_reasons,
            )
        )

    def protocol_names(values: Iterable[Any]) -> set[str]:
        return {
            str(value.get("name") if isinstance(value, dict) else value)
            for value in values
            if (value.get("name") if isinstance(value, dict) else value)
        }

    class_by_name = {
        str(item.get("name") or ""): item
        for item in classes
        if item.get("name")
    }
    category_protocols: dict[str, set[str]] = defaultdict(set)
    for category in categories:
        target = category.get("target_class") or {}
        target_name = str(target.get("name") or "")
        if target_name:
            category_protocols[target_name].update(
                protocol_names(category.get("protocols") or [])
            )

    callback_dependencies: list[dict[str, Any]] = []
    for method in sorted(methods, key=_method_sort_key):
        if method.get("kind") != "instance" or method.get("mapping_status") != "mapped":
            continue
        class_name = str(method.get("class_name") or "")
        selector = str(method.get("selector") or "")
        if not class_name or not selector or class_name not in class_by_name:
            continue
        architecture_name = str(method.get("architecture") or sole_architecture or "unknown")
        inherited_protocols: set[str] = set()
        external_superclass: str | None = None
        chain: list[str] = []
        current_name = class_name
        visited: set[str] = set()
        while current_name in class_by_name and current_name not in visited:
            visited.add(current_name)
            chain.append(current_name)
            current = class_by_name[current_name]
            inherited_protocols.update(protocol_names(current.get("protocols") or []))
            inherited_protocols.update(category_protocols.get(current_name, set()))
            superclass = current.get("superclass") or {}
            next_name = str(superclass.get("name") or "")
            if not next_name:
                break
            if next_name not in class_by_name:
                external_superclass = next_name
                break
            current_name = next_name

        source_address = _address(method.get("canonical_address"))
        common_evidence = [
            _evidence(
                "recovered_method",
                "analysis/recovered-code-index.json",
                source_address=source_address,
                confidence=str(method.get("confidence") or "high"),
                provenance=method.get("provenance") or (),
                basis="Recovered Objective-C metadata maps this selector to the application method",
                details={
                    "method_id": method.get("id"),
                    "class_name": class_name,
                    "selector": selector,
                    "hierarchy_path": chain,
                },
            )
        ]

        superclass_catalog = (
            catalog.class_record(external_superclass)
            if external_superclass
            else None
        )
        if (
            superclass_catalog
            and selector in superclass_catalog.get("instance_overrides", [])
        ):
            evidence = [
                *common_evidence,
                _evidence(
                    "superclass_override_contract",
                    "ipalift/catalogs/platform-apis-v1.json",
                    source_address=source_address,
                    confidence="high",
                    provenance=(
                        "objective_c_metadata",
                        "versioned_platform_api_catalog",
                    ),
                    basis="Recovered superclass chain reaches an external class whose cataloged override selector matches exactly",
                    details={
                        "external_superclass": external_superclass,
                        "catalog_version": catalog_document["catalog_version"],
                    },
                ),
            ]
            dependency = _dependency(
                dependency_id=_stable_id(
                    "platform-dependency-superclass-override",
                    architecture_name,
                    method["id"],
                    external_superclass,
                    selector,
                ),
                kind="superclass_override",
                classification="exact",
                architecture=architecture_name,
                selector=selector,
                class_names=(external_superclass,),
                callback_contract=f"{external_superclass}::{selector}",
                frameworks=(str(superclass_catalog["framework"]),),
                categories=superclass_catalog["categories"],
                source_addresses=(source_address,) if source_address else (),
                affected_function_ids=(str(method["function_id"]),),
                affected_method_ids=(str(method["id"]),),
                affected_class_names=(class_name,),
                provenance=(
                    "objective_c_metadata",
                    "versioned_platform_api_catalog",
                ),
                evidence=evidence,
            )
            dependencies.append(dependency)
            callback_dependencies.append(dependency)

        for protocol_name in sorted(inherited_protocols):
            protocol_catalog = catalog.protocol_record(protocol_name)
            if (
                not protocol_catalog
                or selector not in protocol_catalog.get("instance_callbacks", [])
            ):
                continue
            evidence = [
                *common_evidence,
                _evidence(
                    "protocol_callback_contract",
                    "ipalift/catalogs/platform-apis-v1.json",
                    source_address=source_address,
                    confidence="high",
                    provenance=(
                        "objective_c_metadata",
                        "versioned_platform_api_catalog",
                    ),
                    basis="Recovered protocol conformance and exact cataloged callback selector identify the contract",
                    details={
                        "protocol_name": protocol_name,
                        "catalog_version": catalog_document["catalog_version"],
                    },
                ),
            ]
            dependency = _dependency(
                dependency_id=_stable_id(
                    "platform-dependency-protocol-callback",
                    architecture_name,
                    method["id"],
                    protocol_name,
                    selector,
                ),
                kind="protocol_callback",
                classification="exact",
                architecture=architecture_name,
                selector=selector,
                protocol_name=protocol_name,
                callback_contract=f"{protocol_name}::{selector}",
                frameworks=(str(protocol_catalog["framework"]),),
                categories=protocol_catalog["categories"],
                source_addresses=(source_address,) if source_address else (),
                affected_function_ids=(str(method["function_id"]),),
                affected_method_ids=(str(method["id"]),),
                affected_class_names=(class_name,),
                provenance=(
                    "objective_c_metadata",
                    "versioned_platform_api_catalog",
                ),
                evidence=evidence,
            )
            dependencies.append(dependency)
            callback_dependencies.append(dependency)

    dependencies.sort(
        key=lambda item: (
            item["architecture"],
            item["kind"],
            item["symbol"] or "",
            item["selector"] or "",
            item["id"],
        )
    )
    if len({item["id"] for item in dependencies}) != len(dependencies):
        raise PlatformAPIMapError("Generated platform dependencies contain duplicate IDs")

    function_index: dict[str, dict[str, Any]] = {}
    method_index: dict[str, dict[str, Any]] = {}
    class_index: dict[str, dict[str, Any]] = {}
    framework_index: dict[str, dict[str, Any]] = {}
    category_index: dict[str, dict[str, Any]] = {}

    def add_dependency_to_index(
        index: dict[str, dict[str, Any]],
        key: str,
        *,
        base: dict[str, Any],
        dependency: dict[str, Any],
    ) -> None:
        record = index.setdefault(
            key,
            {
                **base,
                "dependency_ids": set(),
                "frameworks": set(),
                "categories": set(),
            },
        )
        record["dependency_ids"].add(dependency["id"])
        record["frameworks"].update(dependency["frameworks"])
        record["categories"].update(dependency["categories"])

    for dependency in dependencies:
        for function_id in dependency["affected_function_ids"]:
            raw = raw_function_by_id.get(function_id) or {}
            add_dependency_to_index(
                function_index,
                function_id,
                base={
                    "function_id": function_id,
                    "address": _address(raw.get("address")),
                    "name": raw.get("full_name") or raw.get("name"),
                },
                dependency=dependency,
            )
        for method_id in dependency["affected_method_ids"]:
            method = methods_by_id.get(method_id) or {}
            add_dependency_to_index(
                method_index,
                method_id,
                base={
                    "method_id": method_id,
                    "address": _address(method.get("canonical_address")),
                    "exact_name": method.get("exact_name"),
                    "class_name": method.get("class_name"),
                },
                dependency=dependency,
            )
        for affected_class_name in dependency["affected_class_names"]:
            add_dependency_to_index(
                class_index,
                affected_class_name,
                base={"class_name": affected_class_name},
                dependency=dependency,
            )
        for framework in dependency["frameworks"]:
            record = framework_index.setdefault(
                framework,
                {
                    "framework": framework,
                    "dependency_ids": set(),
                    "function_ids": set(),
                    "method_ids": set(),
                    "class_names": set(),
                    "categories": set(),
                },
            )
            record["dependency_ids"].add(dependency["id"])
            record["function_ids"].update(dependency["affected_function_ids"])
            record["method_ids"].update(dependency["affected_method_ids"])
            record["class_names"].update(dependency["affected_class_names"])
            record["categories"].update(dependency["categories"])
        for category_name in dependency["categories"]:
            record = category_index.setdefault(
                category_name,
                {
                    "category": category_name,
                    "dependency_ids": set(),
                    "frameworks": set(),
                    "function_ids": set(),
                    "method_ids": set(),
                    "class_names": set(),
                },
            )
            record["dependency_ids"].add(dependency["id"])
            record["frameworks"].update(dependency["frameworks"])
            record["function_ids"].update(dependency["affected_function_ids"])
            record["method_ids"].update(dependency["affected_method_ids"])
            record["class_names"].update(dependency["affected_class_names"])

    def freeze_index(index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for key in sorted(index, key=str.casefold):
            item = index[key]
            result.append({
                name: sorted(value)
                if isinstance(value, set)
                else value
                for name, value in item.items()
            })
        return result

    normalized_libraries = []
    for library in sorted(
        linked_libraries,
        key=lambda item: (
            str(item.get("name") or ""),
            str(item.get("path") or ""),
            str(item.get("command") or ""),
        ),
    ):
        library_catalog = catalog.library(str(library.get("name") or ""))
        normalized_libraries.append({
            "architectures": sorted(
                str(value) for value in library.get("architectures", [])
            ),
            "command": str(library.get("command") or ""),
            "compatibility_version": library.get("compatibility_version"),
            "current_version": library.get("current_version"),
            "kind": str(library.get("kind") or "unknown"),
            "name": str(library.get("name") or ""),
            "path": str(library.get("path") or ""),
            "timestamp": library.get("timestamp"),
            "catalog_framework": (
                str(library_catalog["framework"]) if library_catalog else None
            ),
            "categories": (
                sorted(str(value) for value in library_catalog["default_categories"])
                if library_catalog
                else []
            ),
        })

    classification_counts = Counter(
        item["classification"] for item in dependencies
    )
    dependency_kind_counts = Counter(item["kind"] for item in dependencies)
    message_status_counts = Counter(
        item["platform_status"] for item in message_callsites
    )
    failure_reason_counts = Counter(
        reason
        for item in dependencies
        for reason in item["failure_reasons"]
    )
    input_artifacts = [
        {
            "artifact": name,
            "path": f"analysis/{name}.json",
            "sha256": sha256_file(workspace / "analysis" / f"{name}.json"),
        }
        for name in REQUIRED_REPORTS
    ]
    input_artifacts.append({
        "artifact": "platform-api-catalog",
        "path": "ipalift/catalogs/platform-apis-v1.json",
        "sha256": catalog_sha256,
    })

    facts = {
        "catalog": {
            "catalog_id": catalog_document["catalog_id"],
            "catalog_version": catalog_document["catalog_version"],
            "sha256": catalog_sha256,
            "category_count": len(catalog_document["categories"]),
            "library_record_count": len(catalog_document["libraries"]),
            "class_record_count": len(catalog_document["classes"]),
            "protocol_record_count": len(catalog_document["protocols"]),
        },
        "input_artifacts": input_artifacts,
        "summary": {
            "linked_library_count": len(normalized_libraries),
            "imported_symbol_count": len(import_records),
            "external_class_reference_count": len(external_class_references),
            "message_callsite_count": len(message_callsites),
            "callback_dependency_count": len(callback_dependencies),
            "dependency_count": len(dependencies),
            "classification_counts": {
                name: classification_counts.get(name, 0)
                for name in CLASSIFICATIONS
            },
            "dependency_kind_counts": {
                name: dependency_kind_counts[name]
                for name in sorted(dependency_kind_counts)
            },
            "message_status_counts": {
                name: message_status_counts.get(name, 0)
                for name in MESSAGE_STATUSES
            },
            "failure_reason_counts": {
                name: failure_reason_counts[name]
                for name in sorted(failure_reason_counts)
            },
        },
        "category_catalog": [
            {
                "id": str(item["id"]),
                "title": str(item["title"]),
                "description": str(item["description"]),
            }
            for item in catalog_document["categories"]
        ],
        "linked_libraries": normalized_libraries,
        "imported_symbols": import_records,
        "external_class_references": external_class_references,
        "message_callsites": message_callsites,
        "callback_dependencies": callback_dependencies,
        "dependencies": dependencies,
        "pseudocode_artifacts": pseudocode_artifacts,
        "indexes": {
            "frameworks": freeze_index(framework_index),
            "categories": freeze_index(category_index),
            "application_functions": freeze_index(function_index),
            "application_methods": freeze_index(method_index),
            "application_classes": freeze_index(class_index),
        },
        "evidence_boundary": {
            "gameplay_semantics_inferred": False,
            "selectors_or_names_used_as_behavior_evidence": False,
            "windows_shims_or_reconstructed_implementations_emitted": False,
            "direct_callgraph_preserved": True,
            "objc_dispatch_preserved": True,
            "objc_type_flow_preserved": True,
        },
    }
    hypotheses = [
        {
            "id": _stable_id("platform-hypothesis", dependency["id"]),
            "kind": "candidate_platform_dependency",
            "dependency_id": dependency["id"],
            "confidence": dependency["confidence"],
            "basis": "The dependency is retained as a candidate set because exact ownership or receiver identity is not statically proven",
        }
        for dependency in dependencies
        if dependency["classification"] == "candidate_set"
    ]
    errors = [
        {
            "code": reason,
            "count": count,
            "message": "One or more platform dependency records retain this unresolved or uncertainty reason",
        }
        for reason, count in sorted(failure_reason_counts.items())
    ]
    platform_map = report_envelope(
        "platform-api-map",
        facts,
        hypotheses=hypotheses,
        errors=errors,
    )
    platform_map_path = workspace / "analysis" / "platform-api-map.json"
    report_path = workspace / "reports" / "platform-api-map-report.md"
    write_json_atomic(platform_map_path, platform_map)
    write_text_atomic(report_path, render_platform_api_map_report(facts))
    return PlatformAPIMapResult(
        workspace=workspace,
        platform_map=platform_map,
        platform_map_path=platform_map_path,
        report_path=report_path,
    )
