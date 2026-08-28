"""Deterministic Objective-C recovered-code organization."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import IPALiftError
from .report import render_objc_recovery_report
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class RecoveryError(IPALiftError):
    """An existing workspace cannot be organized without losing evidence."""


@dataclass(frozen=True)
class RecoveryResult:
    workspace: Path
    index: dict[str, Any]
    index_path: Path
    report_path: Path
    generated_files: tuple[str, ...]


REQUIRED_REPORTS = ("classes", "functions", "strings", "decompilation")
CLASSIFICATIONS = (
    "objective_c_method",
    "native_internal_function",
    "thunk",
    "external_function",
)
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RecoveryError(f"Analysis workspace is missing analysis/{name}.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"Cannot read {path}: {exc}") from exc
    if (
        report.get("schema_version") != 1
        or report.get("artifact") != name
        or not isinstance(report.get("facts"), dict)
    ):
        raise RecoveryError(f"Invalid IPALift {name} report: {path}")
    return report


def _address(value: Any) -> str | None:
    if value is None:
        return None
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return f"0x{number:08x}"


def _address_key(value: str | None) -> tuple[int, str]:
    if value and value.startswith("0x"):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _canonical_method_address(pointer: str, architecture: str) -> tuple[str, bool]:
    value = int(pointer, 16)
    lowered = architecture.lower()
    thumb = lowered.startswith("arm") and "64" not in lowered and bool(value & 1)
    return (f"0x{value & ~1:08x}" if thumb else pointer, thumb)


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _comment(value: Any) -> str:
    return str(value).replace("*/", "* /").replace("\r", " ").replace("\n", " ")


def _table(value: Any) -> str:
    return _comment(value).replace("|", "\\|")


def _safe_stem(value: str) -> str:
    rendered = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value)
    rendered = re.sub(r"\s+", "_", rendered).strip(" ._") or "unnamed"
    if rendered.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES:
        rendered = "_" + rendered
    return rendered[:100].rstrip(" .") or "unnamed"


def _assign_paths(entities: list[dict[str, Any]], directory: str) -> None:
    used: set[str] = set()
    for entity in sorted(entities, key=lambda item: (item["display_name"].casefold(), item["id"])):
        base = _safe_stem(entity["display_name"])
        candidate = base
        if candidate.casefold() in used:
            digest = hashlib.sha256(entity["id"].encode("utf-8")).hexdigest()
            for length in range(10, 65, 2):
                suffix = "--" + digest[:length]
                candidate = base[: max(1, 100 - len(suffix))] + suffix
                if candidate.casefold() not in used:
                    break
            else:
                raise RecoveryError(f"Cannot create a collision-safe filename for {entity['display_name']!r}")
        used.add(candidate.casefold())
        entity["header_path"] = f"recovered/objc/{directory}/{candidate}.h"
        entity["source_path"] = f"recovered/objc/{directory}/{candidate}.m"


def _protocol_names(records: list[Any]) -> list[str]:
    names = []
    for record in records:
        name = record.get("name") if isinstance(record, dict) else record
        if name:
            names.append(str(name))
    return sorted(set(names))


def _entity_key(kind: str, architecture: str, name: str, target_class: str | None = None) -> tuple[str, ...]:
    return (kind, architecture, target_class or "", name)


def _collect_entities(classes: dict[str, Any]) -> tuple[dict[tuple[str, ...], dict[str, Any]], list[dict[str, Any]]]:
    entities: dict[tuple[str, ...], dict[str, Any]] = {}
    source_methods: list[dict[str, Any]] = []
    for architecture_record in classes.get("architectures", []):
        architecture = str(architecture_record.get("architecture") or "unknown")
        for record in architecture_record.get("classes", []):
            name = str(record["name"])
            key = _entity_key("class", architecture, name)
            entity = {
                "id": _stable_id("objc-class", architecture, name, record.get("address")),
                "kind": "class",
                "architecture": architecture,
                "name": name,
                "display_name": name,
                "metadata_present": True,
                "address": _address(record.get("address")),
                "metaclass_address": _address(record.get("metaclass_address")),
                "superclass": record.get("superclass"),
                "protocols": _protocol_names(record.get("protocols", [])),
                "ivars": sorted(record.get("ivars", []), key=lambda item: (item.get("offset", -1), item.get("name", ""))),
                "properties": sorted(record.get("properties", []), key=lambda item: item.get("name", "")),
                "flags": record.get("flags"),
                "instance_start": record.get("instance_start"),
                "instance_size": record.get("instance_size"),
                "method_ids": [],
            }
            if key in entities:
                raise RecoveryError(f"Duplicate Objective-C class record for {architecture} {name}")
            entities[key] = entity
            source_methods.extend(_metadata_methods(entity, record))
        for record in architecture_record.get("categories", []):
            name = str(record["name"])
            target = record.get("target_class") or {}
            target_name = str(target.get("name") or "UnknownClass")
            key = _entity_key("category", architecture, name, target_name)
            entity = {
                "id": _stable_id("objc-category", architecture, target_name, name, record.get("address")),
                "kind": "category",
                "architecture": architecture,
                "name": name,
                "target_class": target,
                "display_name": f"{target_name}+{name}",
                "metadata_present": True,
                "address": _address(record.get("address")),
                "protocols": _protocol_names(record.get("protocols", [])),
                "properties": sorted(record.get("properties", []), key=lambda item: item.get("name", "")),
                "method_ids": [],
            }
            if key in entities:
                raise RecoveryError(f"Duplicate Objective-C category record for {architecture} {target_name}({name})")
            entities[key] = entity
            source_methods.extend(_metadata_methods(entity, record))
        for record in architecture_record.get("protocols", []):
            name = str(record["name"])
            key = _entity_key("protocol", architecture, name)
            protocol_address = _address(record.get("address"))
            declarations = []
            for method in record.get("methods", []):
                declarations.append({
                    "id": _stable_id(
                        "objc-protocol-method", architecture, name, method.get("kind"),
                        method.get("required"), method.get("selector"), method.get("type_encoding"),
                    ),
                    "kind": method.get("kind"),
                    "required": bool(method.get("required")),
                    "selector": method.get("selector"),
                    "type_encoding": method.get("type_encoding"),
                    "occurrence_count": 1,
                    "source_protocol_addresses": [protocol_address],
                })
            declarations.sort(key=lambda item: (not item["required"], str(item["kind"]), str(item["selector"])))
            if key in entities:
                entity = entities[key]
                entity["metadata_record_count"] += 1
                entity["metadata_addresses"] = sorted(
                    set([*entity["metadata_addresses"], protocol_address]), key=_address_key
                )
                entity["address"] = entity["metadata_addresses"][0]
                entity["inherited_protocols"] = sorted(set([
                    *entity["inherited_protocols"], *record.get("inherited_protocols", [])
                ]))
                entity["inherited_protocol_addresses"] = sorted(
                    set([
                        *entity["inherited_protocol_addresses"],
                        *(_address(item) for item in record.get("inherited_protocol_addresses", [])),
                    ]),
                    key=_address_key,
                )
                properties = {
                    json.dumps(item, sort_keys=True, ensure_ascii=False): item
                    for item in [*entity["properties"], *record.get("properties", [])]
                }
                entity["properties"] = sorted(
                    properties.values(), key=lambda item: (item.get("name", ""), item.get("attributes", ""))
                )
                by_id = {item["id"]: item for item in entity["declarations"]}
                for declaration in declarations:
                    existing = by_id.get(declaration["id"])
                    if existing is None:
                        entity["declarations"].append(declaration)
                        by_id[declaration["id"]] = declaration
                    else:
                        existing["occurrence_count"] += 1
                        existing["source_protocol_addresses"] = sorted(
                            set([*existing["source_protocol_addresses"], protocol_address]), key=_address_key
                        )
                entity["declarations"].sort(
                    key=lambda item: (not item["required"], str(item["kind"]), str(item["selector"]))
                )
                continue
            entity = {
                "id": _stable_id("objc-protocol", architecture, name),
                "kind": "protocol",
                "architecture": architecture,
                "name": name,
                "display_name": name,
                "metadata_present": True,
                "address": protocol_address,
                "metadata_record_count": 1,
                "metadata_addresses": [protocol_address],
                "inherited_protocols": sorted(set(record.get("inherited_protocols", []))),
                "inherited_protocol_addresses": sorted(
                    (_address(item) for item in record.get("inherited_protocol_addresses", [])),
                    key=_address_key,
                ),
                "properties": sorted(record.get("properties", []), key=lambda item: item.get("name", "")),
                "declarations": declarations,
                "method_ids": [],
            }
            entities[key] = entity
    return entities, sorted(source_methods, key=_method_sort_key)


def _metadata_methods(entity: dict[str, Any], record: dict[str, Any]) -> list[dict[str, Any]]:
    methods = []
    for list_name, marker, kind in (
        ("instance_methods", "-", "instance"),
        ("class_methods", "+", "class"),
    ):
        for method in record.get(list_name, []):
            pointer = _address(method.get("implementation_address"))
            if not pointer:
                continue
            address, thumb = _canonical_method_address(pointer, entity["architecture"])
            if entity["kind"] == "category":
                target_name = str((entity.get("target_class") or {}).get("name") or "UnknownClass")
                owner = f"{target_name}({entity['name']})"
            else:
                owner = entity["name"]
            selector = str(method["selector"])
            methods.append({
                "entity_id": entity["id"],
                "entity_kind": entity["kind"],
                "architecture": entity["architecture"],
                "class_name": owner.split("(", 1)[0],
                "category_name": entity["name"] if entity["kind"] == "category" else None,
                "kind": kind,
                "selector": selector,
                "exact_name": f"{marker}[{owner} {selector}]",
                "implementation_pointer": pointer,
                "address": address,
                "thumb_entrypoint": thumb,
                "metadata_address": _address(method.get("metadata_address")),
                "type_encoding": method.get("type_encoding"),
                "source_metadata_present": True,
            })
    return methods


def _method_sort_key(method: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(method.get("architecture") or ""),
        _address_key(method.get("address")),
        str(method.get("exact_name") or ""),
        str(method.get("entity_id") or ""),
    )


def _ensure_method_entities(
    entities: dict[tuple[str, ...], dict[str, Any]],
    functions: list[dict[str, Any]],
) -> None:
    for function in functions:
        for method in function.get("objective_c_methods", []):
            architecture = str(method.get("architecture") or "unknown")
            class_name = str(method.get("class_name") or "UnknownClass")
            category_name = method.get("category_name")
            if category_name:
                key = _entity_key("category", architecture, str(category_name), class_name)
                kind = "category"
                display_name = f"{class_name}+{category_name}"
                name = str(category_name)
            else:
                key = _entity_key("class", architecture, class_name)
                kind = "class"
                display_name = class_name
                name = class_name
            if key in entities:
                continue
            entity = {
                "id": _stable_id(f"objc-{kind}", architecture, class_name, category_name or "", "method-only"),
                "kind": kind,
                "architecture": architecture,
                "name": name,
                "display_name": display_name,
                "metadata_present": False,
                "address": None,
                "protocols": [],
                "properties": [],
                "method_ids": [],
            }
            if kind == "class":
                entity.update({
                    "metaclass_address": None,
                    "superclass": None,
                    "ivars": [],
                    "flags": None,
                    "instance_start": None,
                    "instance_size": None,
                })
            else:
                entity["target_class"] = {"name": class_name, "address": None, "source": "method_metadata"}
            entities[key] = entity


def _entity_lists(entities: dict[tuple[str, ...], dict[str, Any]]) -> tuple[list[dict[str, Any]], ...]:
    classes = sorted((item for item in entities.values() if item["kind"] == "class"), key=_entity_sort_key)
    categories = sorted((item for item in entities.values() if item["kind"] == "category"), key=_entity_sort_key)
    protocols = sorted((item for item in entities.values() if item["kind"] == "protocol"), key=_entity_sort_key)
    _assign_paths(classes, "classes")
    _assign_paths(categories, "categories")
    _assign_paths(protocols, "protocols")
    return classes, categories, protocols


def _entity_sort_key(entity: dict[str, Any]) -> tuple[str, str, str]:
    return (entity["architecture"], entity["display_name"].casefold(), entity["id"])


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = relative.replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise RecoveryError(f"Artifact path escapes the analysis workspace: {relative}")
    normalized = Path(*parts)
    candidate = (workspace / normalized).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise RecoveryError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _decompilation_by_function(workspace: Path, facts: dict[str, Any]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for item in facts.get("functions", []):
        function_id = str(item["function_id"])
        if function_id in results:
            raise RecoveryError(f"Duplicate decompilation record for {function_id}")
        status = str(item.get("status") or "failure")
        output_path = item.get("output_path")
        normalized = {
            "status": status,
            "message": item.get("message"),
            "output_path": output_path,
            "sha256": None,
        }
        if status == "success":
            if not output_path:
                raise RecoveryError(f"Successful decompilation has no output path: {function_id}")
            path = _relative_file(workspace, str(output_path))
            if not path.is_file():
                raise RecoveryError(f"Successful decompilation file is missing: {output_path}")
            normalized["sha256"] = sha256_file(path)
        results[function_id] = normalized
    return results


def _function_status(function: dict[str, Any], results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    function_id = str(function["id"])
    if function_id in results:
        return dict(results[function_id])
    if function.get("external"):
        reason = "External functions are not eligible for decompilation"
    elif function.get("thunk"):
        reason = "Thunk functions are not eligible for decompilation"
    else:
        raise RecoveryError(f"Eligible function is missing decompilation status: {function_id}")
    return {"status": "not_eligible", "message": reason, "output_path": None, "sha256": None}


def _mapped_method_key(method: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(method.get("architecture") or "unknown"),
        str(method.get("address") or ""),
        str(method.get("exact_name") or ""),
    )


def _source_method_key(method: dict[str, Any]) -> tuple[str, str, str]:
    return (method["architecture"], method["address"], method["exact_name"])


def _build_methods(
    workspace: Path,
    entities: dict[tuple[str, ...], dict[str, Any]],
    source_methods: list[dict[str, Any]],
    functions: list[dict[str, Any]],
    decompilation: dict[str, dict[str, Any]],
    strings: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    entity_by_id = {item["id"]: item for item in entities.values()}
    entity_id_by_key = {key: value["id"] for key, value in entities.items()}
    mapped: dict[tuple[str, str, str], list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for function in functions:
        for method in function.get("objective_c_methods", []):
            mapped[_mapped_method_key(method)].append((function, method))
    for records in mapped.values():
        records.sort(key=lambda pair: str(pair[0]["id"]))

    methods: list[dict[str, Any]] = []
    consumed: set[tuple[str, str, str, str]] = set()
    for source in source_methods:
        key = _source_method_key(source)
        candidates = mapped.get(key, [])
        pair = candidates.pop(0) if candidates else None
        methods.append(_complete_method(workspace, source, pair, entity_by_id[source["entity_id"]], decompilation, strings))
        if pair:
            consumed.add((*key, str(pair[0]["id"])))

    for function in functions:
        for mapped_method in function.get("objective_c_methods", []):
            key = _mapped_method_key(mapped_method)
            consumed_key = (*key, str(function["id"]))
            if consumed_key in consumed:
                continue
            architecture = str(mapped_method.get("architecture") or "unknown")
            class_name = str(mapped_method.get("class_name") or "UnknownClass")
            category_name = mapped_method.get("category_name")
            if category_name:
                entity_key = _entity_key("category", architecture, str(category_name), class_name)
            else:
                entity_key = _entity_key("class", architecture, class_name)
            source = {
                **mapped_method,
                "entity_id": entity_id_by_key[entity_key],
                "entity_kind": "category" if category_name else "class",
                "source_metadata_present": False,
            }
            methods.append(
                _complete_method(workspace, source, (function, mapped_method), entity_by_id[source["entity_id"]], decompilation, strings)
            )
    methods.sort(key=_method_sort_key)
    seen_ids: set[str] = set()
    for method in methods:
        if method["id"] in seen_ids:
            raise RecoveryError(f"Duplicate recovered method identity: {method['exact_name']}")
        seen_ids.add(method["id"])
        entity_by_id[method["entity_id"]]["method_ids"].append(method["id"])
    for entity in entity_by_id.values():
        entity["method_ids"].sort()
    return methods


def _complete_method(
    workspace: Path,
    source: dict[str, Any],
    mapped_pair: tuple[dict[str, Any], dict[str, Any]] | None,
    entity: dict[str, Any],
    decompilation: dict[str, dict[str, Any]],
    strings: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    method_id = _stable_id(
        "objc-method", source["architecture"], source["implementation_pointer"],
        source["address"], source["exact_name"], entity["id"],
    )
    if mapped_pair:
        function, mapped_method = mapped_pair
        function_id = str(function["id"])
        referenced_strings = []
        for address in function.get("referenced_string_addresses", []):
            record = strings.get(str(address))
            referenced_strings.append({
                "address": str(address),
                "value": record.get("value") if record else None,
                "data_type": record.get("data_type") if record else None,
                "is_selector": bool(record.get("is_selector")) if record else False,
                "asset_matches": record.get("asset_matches", []) if record else [],
            })
        record = {
            "id": method_id,
            "entity_id": entity["id"],
            "entity_kind": entity["kind"],
            "mapping_status": "mapped",
            "mapping_reason": "Exact architecture, canonical address, and Objective-C method name match",
            "source_metadata_present": bool(source.get("source_metadata_present")),
            "architecture": source["architecture"],
            "class_name": mapped_method.get("class_name"),
            "category_name": mapped_method.get("category_name"),
            "kind": mapped_method.get("kind"),
            "selector": mapped_method.get("selector"),
            "exact_name": mapped_method.get("exact_name"),
            "canonical_address": mapped_method.get("address"),
            "implementation_pointer": mapped_method.get("implementation_pointer"),
            "thumb_entrypoint": bool(mapped_method.get("thumb_entrypoint")),
            "metadata_address": mapped_method.get("metadata_address"),
            "type_encoding": mapped_method.get("type_encoding"),
            "function_id": function_id,
            "decompilation": _function_status(function, decompilation),
            "callers": sorted(set(function.get("callers", []))),
            "callees": sorted(set(function.get("callees", []))),
            "referenced_strings": referenced_strings,
            "referenced_selectors": sorted(set(function.get("referenced_selectors", []))),
            "referenced_classes": sorted(set(function.get("referenced_classes", []))),
            "referenced_assets": sorted(function.get("referenced_assets", []), key=lambda item: item.get("path", "")),
            "provenance": list(function.get("provenance", [])),
            "confidence": function.get("confidence"),
            "confidence_basis": list(function.get("confidence_basis", [])),
            "recovered_header_path": entity["header_path"],
            "recovered_source_path": entity["source_path"],
        }
    else:
        record = {
            "id": method_id,
            "entity_id": entity["id"],
            "entity_kind": entity["kind"],
            "mapping_status": "unresolved",
            "mapping_reason": "No discovered function carries this exact Objective-C metadata record",
            "source_metadata_present": True,
            "architecture": source["architecture"],
            "class_name": source.get("class_name"),
            "category_name": source.get("category_name"),
            "kind": source.get("kind"),
            "selector": source.get("selector"),
            "exact_name": source.get("exact_name"),
            "canonical_address": source.get("address"),
            "implementation_pointer": source.get("implementation_pointer"),
            "thumb_entrypoint": bool(source.get("thumb_entrypoint")),
            "metadata_address": source.get("metadata_address"),
            "type_encoding": source.get("type_encoding"),
            "function_id": None,
            "decompilation": {
                "status": "unresolved", "message": "No mapped function", "output_path": None, "sha256": None,
            },
            "callers": [],
            "callees": [],
            "referenced_strings": [],
            "referenced_selectors": [],
            "referenced_classes": [],
            "referenced_assets": [],
            "provenance": ["objective_c_metadata"],
            "confidence": "high",
            "confidence_basis": ["Method declaration and implementation pointer are present in Objective-C metadata"],
            "recovered_header_path": entity["header_path"],
            "recovered_source_path": entity["source_path"],
        }
    return record


def _classification(function: dict[str, Any], method_ids: list[str]) -> str:
    if method_ids:
        return "objective_c_method"
    if function.get("external"):
        return "external_function"
    if function.get("thunk"):
        return "thunk"
    return "native_internal_function"


def _build_function_index(
    functions: list[dict[str, Any]],
    methods: list[dict[str, Any]],
    decompilation: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    method_ids: dict[str, list[str]] = defaultdict(list)
    source_paths: dict[str, set[str]] = defaultdict(set)
    for method in methods:
        if method.get("function_id"):
            function_id = str(method["function_id"])
            method_ids[function_id].append(method["id"])
            source_paths[function_id].add(method["recovered_source_path"])
    records = []
    for function in functions:
        function_id = str(function["id"])
        ids = sorted(method_ids.get(function_id, []))
        records.append({
            "function_id": function_id,
            "address": function.get("address"),
            "classification": _classification(function, ids),
            "name": function.get("name"),
            "full_name": function.get("full_name"),
            "namespace": function.get("namespace"),
            "signature": function.get("signature"),
            "external": bool(function.get("external")),
            "thunk": bool(function.get("thunk")),
            "entrypoint": bool(function.get("entrypoint")),
            "method_ids": ids,
            "recovered_source_paths": sorted(source_paths.get(function_id, set())),
            "decompilation": _function_status(function, decompilation),
            "callers": sorted(set(function.get("callers", []))),
            "callees": sorted(set(function.get("callees", []))),
            "referenced_string_addresses": sorted(set(function.get("referenced_string_addresses", [])), key=_address_key),
            "referenced_selectors": sorted(set(function.get("referenced_selectors", []))),
            "referenced_classes": sorted(set(function.get("referenced_classes", []))),
            "referenced_assets": sorted(function.get("referenced_assets", []), key=lambda item: item.get("path", "")),
            "macho_imports": sorted(function.get("macho_imports", []), key=lambda item: item.get("name", "")),
            "macho_exports": sorted(set(function.get("macho_exports", []))),
            "provenance": list(function.get("provenance", [])),
            "confidence": function.get("confidence"),
            "confidence_basis": list(function.get("confidence_basis", [])),
        })
    records.sort(key=lambda item: (item["external"], _address_key(item.get("address")), item["function_id"]))
    return records


def _method_declaration(method: dict[str, Any]) -> str:
    marker = "+" if method.get("kind") == "class" else "-"
    selector = str(method.get("selector") or "unknown")
    encoding = _comment(method.get("type_encoding") or "unknown")
    if ":" not in selector:
        declaration = f"{marker} (unknown){selector};"
    else:
        components = selector.split(":")[:-1]
        declaration = marker + " (unknown)" + " ".join(
            f"{component}:(unknown)arg{index + 1}" for index, component in enumerate(components)
        ) + ";"
    return f"{declaration} /* raw type encoding: {encoding} */"


def _banner(entity: dict[str, Any], view: str) -> list[str]:
    return [
        "/*",
        " * IPALift RECOVERED METADATA AND PSEUDOCODE VIEW",
        " * NOT ORIGINAL SOURCE. NOT INTENDED OR EXPECTED TO COMPILE.",
        f" * View: {_comment(view)}",
        f" * Entity: {_comment(entity['display_name'])}",
        f" * Architecture: {_comment(entity['architecture'])}",
        " * Facts retain their evidence addresses, provenance, confidence, and unresolved state.",
        " */",
        "",
    ]


def _render_header(entity: dict[str, Any], methods: dict[str, dict[str, Any]]) -> str:
    lines = _banner(entity, "Objective-C declarations")
    if entity["kind"] == "class":
        superclass = entity.get("superclass") or {}
        superclass_name = superclass.get("name") if isinstance(superclass, dict) else superclass
        inheritance = f" : {superclass_name}" if superclass_name else ""
        protocols = f" <{', '.join(entity['protocols'])}>" if entity.get("protocols") else ""
        lines.extend([f"@interface {entity['name']}{inheritance}{protocols}", "", "/* Recovered ivars */"])
        if entity.get("ivars"):
            for ivar in entity["ivars"]:
                lines.append(
                    f"/* offset={ivar.get('offset')} size={ivar.get('size')} "
                    f"type_encoding={_comment(ivar.get('type_encoding'))} name={_comment(ivar.get('name'))} */"
                )
        else:
            lines.append("/* none recovered */")
    elif entity["kind"] == "category":
        target = entity.get("target_class") or {}
        target_name = target.get("name") if isinstance(target, dict) else target
        protocols = f" <{', '.join(entity['protocols'])}>" if entity.get("protocols") else ""
        lines.extend([f"@interface {target_name or 'UnknownClass'} ({entity['name']}){protocols}", ""])
    else:
        inherited = entity.get("inherited_protocols", [])
        inheritance = f" <{', '.join(inherited)}>" if inherited else ""
        lines.extend([f"@protocol {entity['name']}{inheritance}", ""])

    lines.extend(["", "/* Recovered properties */"])
    properties = entity.get("properties", [])
    if properties:
        for property_record in properties:
            lines.append(
                f"/* @property {_comment(property_record.get('name'))}; "
                f"raw attributes: {_comment(property_record.get('attributes'))} */"
            )
    else:
        lines.append("/* none recovered */")

    if entity["kind"] == "protocol":
        declarations = entity.get("declarations", [])
        required_groups = ((True, "@required"), (False, "@optional"))
        for required, heading in required_groups:
            selected = [item for item in declarations if item["required"] is required]
            if not selected:
                continue
            lines.extend(["", heading])
            for declaration in selected:
                lines.append(_method_declaration(declaration))
    else:
        lines.extend(["", "/* Recovered methods */"])
        selected = [methods[method_id] for method_id in entity.get("method_ids", [])]
        selected.sort(key=_method_sort_key)
        if selected:
            for method in selected:
                lines.append(f"/* {method['exact_name']} canonical={method['canonical_address']} */")
                lines.append(_method_declaration(method))
        else:
            lines.append("/* none recovered */")
    lines.extend(["", "@end", ""])
    return "\n".join(lines)


def _render_source(
    workspace: Path,
    entity: dict[str, Any],
    methods: dict[str, dict[str, Any]],
    code_cache: dict[str, str],
) -> str:
    lines = _banner(entity, "Non-buildable Ghidra pseudocode organization")
    if entity["kind"] == "protocol":
        lines.extend([
            "/* Protocol metadata contains declarations, not implementation addresses.",
            " * No pseudocode bodies are assigned to this protocol view.",
            " */",
            "",
        ])
        for declaration in entity.get("declarations", []):
            lines.extend([
                f"/* Protocol declaration: {_comment(declaration.get('selector'))}",
                f" * required: {'yes' if declaration.get('required') else 'no'}",
                f" * kind: {_comment(declaration.get('kind'))}",
                f" * raw type encoding: {_comment(declaration.get('type_encoding'))}",
                f" * metadata occurrences: {declaration.get('occurrence_count', 1)}",
                f" * source protocol addresses: {_comment(', '.join(item or 'unknown' for item in declaration.get('source_protocol_addresses', [])))}",
                " */",
                "",
            ])
        return "\n".join(lines)

    selected = [methods[method_id] for method_id in entity.get("method_ids", [])]
    selected.sort(key=_method_sort_key)
    if not selected:
        lines.extend(["/* No Objective-C method implementations were recovered for this entity. */", ""])
        return "\n".join(lines)
    for method in selected:
        decompilation = method["decompilation"]
        lines.extend([
            f"/* ===== IPALIFT METHOD {method['id']} =====",
            f" * Exact runtime name: {_comment(method['exact_name'])}",
            f" * Mapping: {_comment(method['mapping_status'])} — {_comment(method['mapping_reason'])}",
            f" * Canonical function address: {_comment(method['canonical_address'])}",
            f" * Original implementation pointer: {_comment(method['implementation_pointer'])}",
            f" * Thumb entrypoint: {'yes' if method['thumb_entrypoint'] else 'no'}",
            f" * Metadata address: {_comment(method['metadata_address'])}",
            f" * Selector: {_comment(method['selector'])}",
            f" * Raw type encoding: {_comment(method['type_encoding'])}",
            f" * Function id: {_comment(method['function_id'])}",
            f" * Decompilation status: {_comment(decompilation['status'])}",
            f" * Original pseudocode artifact: {_comment(decompilation.get('output_path'))}",
            f" * Pseudocode SHA-256: {_comment(decompilation.get('sha256'))}",
            f" * Callers: {_comment(', '.join(method['callers']) or 'none')}",
            f" * Callees: {_comment(', '.join(method['callees']) or 'none')}",
            f" * Referenced strings: {_comment(json.dumps(method['referenced_strings'], sort_keys=True, ensure_ascii=False))}",
            f" * Referenced selectors: {_comment(', '.join(method['referenced_selectors']) or 'none')}",
            f" * Referenced classes: {_comment(', '.join(method['referenced_classes']) or 'none')}",
            f" * Referenced assets: {_comment(json.dumps(method['referenced_assets'], sort_keys=True, ensure_ascii=False))}",
            f" * Provenance: {_comment(', '.join(method['provenance']) or 'none')}",
            f" * Confidence: {_comment(method['confidence'])}",
            f" * Confidence basis: {_comment(' | '.join(method['confidence_basis']) or 'none')}",
        ])
        if decompilation.get("message"):
            lines.append(f" * Diagnostic: {_comment(decompilation['message'])}")
        lines.extend([" */", ""])
        output_path = decompilation.get("output_path")
        if decompilation["status"] == "success" and output_path:
            if output_path not in code_cache:
                path = _relative_file(workspace, output_path)
                try:
                    code_cache[output_path] = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
                except OSError as exc:
                    raise RecoveryError(f"Cannot read decompiled pseudocode {output_path}: {exc}") from exc
            lines.extend([
                "/* BEGIN GHIDRA PSEUDOCODE — EVIDENCE VIEW ONLY */",
                code_cache[output_path].rstrip("\n"),
                "/* END GHIDRA PSEUDOCODE — EVIDENCE VIEW ONLY */",
                "",
            ])
        else:
            lines.extend(["/* No pseudocode body is available for this method. */", ""])
    return "\n".join(lines)


def _render_native_functions(functions: list[dict[str, Any]]) -> str:
    native = [item for item in functions if item["classification"] == "native_internal_function"]
    lines = [
        "# IPALift unassociated native functions",
        "",
        "> Recovered evidence index. This is not original source and is not a claim about gameplay behavior.",
        "",
        f"Count: {len(native)}",
        "",
        "| Address | Function ID | Recovered name | Decompilation | Exports | Confidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for function in native:
        lines.append(
            f"| {_table(function.get('address'))} | {_table(function['function_id'])} | "
            f"{_table(function.get('full_name'))} | {_table(function['decompilation']['status'])} | "
            f"{_table(', '.join(function['macho_exports']))} | {_table(function.get('confidence'))} |"
        )
    lines.append("")
    return "\n".join(lines)


def _prior_generated_files(workspace: Path) -> set[str]:
    path = workspace / "analysis" / "recovered-code-index.json"
    if not path.is_file():
        return set()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if document.get("artifact") != "recovered-code-index":
        return set()
    return {str(item) for item in document.get("facts", {}).get("generated_files", [])}


def _remove_stale(workspace: Path, prior: set[str], current: set[str]) -> None:
    for relative in sorted(prior - current):
        if not relative.startswith("recovered/"):
            continue
        path = _relative_file(workspace, relative)
        if path.is_file():
            path.unlink()


def recover_objc_workspace(workspace: Path) -> RecoveryResult:
    """Create deterministic, non-buildable Objective-C evidence views."""
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise RecoveryError(f"Analysis workspace does not exist: {workspace}") from exc
    if not workspace.is_dir():
        raise RecoveryError(f"Analysis workspace is not a directory: {workspace}")

    reports = {name: _load_report(workspace, name) for name in REQUIRED_REPORTS}
    class_facts = reports["classes"]["facts"]
    function_facts = reports["functions"]["facts"]
    string_facts = reports["strings"]["facts"]
    decompilation_facts = reports["decompilation"]["facts"]
    functions = list(function_facts.get("functions", []))
    if len(functions) != function_facts.get("discovered_function_count"):
        raise RecoveryError("functions.json count does not match its function inventory")

    entities, source_methods = _collect_entities(class_facts)
    _ensure_method_entities(entities, functions)
    classes, categories, protocols = _entity_lists(entities)
    strings = {str(item["address"]): item for item in string_facts.get("strings", [])}
    decompilation = _decompilation_by_function(workspace, decompilation_facts)
    methods = _build_methods(workspace, entities, source_methods, functions, decompilation, strings)
    methods_by_id = {item["id"]: item for item in methods}
    function_index = _build_function_index(functions, methods, decompilation)
    classifications = Counter(item["classification"] for item in function_index)
    if set(classifications) - set(CLASSIFICATIONS):
        raise RecoveryError("Recovered function index contains an unknown classification")
    if sum(classifications.values()) != len(functions):
        raise RecoveryError("Not every discovered function received exactly one classification")

    generated: dict[str, str] = {}
    code_cache: dict[str, str] = {}
    for entity in [*classes, *categories, *protocols]:
        generated[entity["header_path"]] = _render_header(entity, methods_by_id)
        generated[entity["source_path"]] = _render_source(workspace, entity, methods_by_id, code_cache)
    native_path = "recovered/native-functions.md"
    generated[native_path] = _render_native_functions(function_index)
    generated_paths = sorted(generated)

    unresolved_methods = [item for item in methods if item["mapping_status"] == "unresolved"]
    method_statuses = Counter(item["decompilation"]["status"] for item in methods)
    failed_functions = [
        item for item in function_index if item["decompilation"]["status"] in {"failure", "timeout"}
    ]
    input_paths = {name: f"analysis/{name}.json" for name in REQUIRED_REPORTS}
    facts = {
        "input_artifacts": {
            name: {"path": relative, "sha256": sha256_file(_relative_file(workspace, relative))}
            for name, relative in sorted(input_paths.items())
        },
        "function_count": len(function_index),
        "classification_counts": {name: classifications.get(name, 0) for name in CLASSIFICATIONS},
        "objective_c_method_count": len(methods),
        "mapped_objective_c_method_count": len(methods) - len(unresolved_methods),
        "unresolved_objective_c_method_count": len(unresolved_methods),
        "method_decompilation_status_counts": dict(sorted(method_statuses.items())),
        "class_count": len(classes),
        "category_count": len(categories),
        "protocol_count": len(protocols),
        "protocol_metadata_record_count": sum(item.get("metadata_record_count", 1) for item in protocols),
        "unassociated_native_function_count": classifications.get("native_internal_function", 0),
        "failed_or_timed_out_function_count": len(failed_functions),
        "generated_file_count": len(generated_paths),
        "generated_files": generated_paths,
        "functions": function_index,
        "methods": methods,
        "classes": classes,
        "categories": categories,
        "protocols": protocols,
        "unresolved_methods": unresolved_methods,
        "unassociated_native_function_ids": [
            item["function_id"] for item in function_index
            if item["classification"] == "native_internal_function"
        ],
        "failed_or_timed_out_functions": failed_functions,
    }
    errors = [
        {
            "code": "objc_method_function_unresolved",
            "method_id": item["id"],
            "exact_name": item["exact_name"],
            "canonical_address": item["canonical_address"],
            "message": item["mapping_reason"],
        }
        for item in unresolved_methods
    ]
    index = report_envelope("recovered-code-index", facts, errors=errors)

    prior = _prior_generated_files(workspace)
    for relative, content in sorted(generated.items()):
        write_text_atomic(_relative_file(workspace, relative), content)
    _remove_stale(workspace, prior, set(generated_paths))
    index_path = workspace / "analysis" / "recovered-code-index.json"
    report_path = workspace / "reports" / "objc-recovery-report.md"
    write_json_atomic(index_path, index)
    write_text_atomic(report_path, render_objc_recovery_report(facts))
    return RecoveryResult(workspace, index, index_path, report_path, tuple(generated_paths))
