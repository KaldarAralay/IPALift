"""Deterministic, evidence-bounded C++ ABI object-model recovery."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import IPALiftError
from .macho import MachOSlice, parse_macho_file
from .report import render_cpp_object_model_report
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class CppModelError(IPALiftError):
    """A workspace cannot support trustworthy C++ ABI recovery."""


@dataclass(frozen=True)
class CppModelResult:
    workspace: Path
    cpp_model: dict[str, Any]
    cpp_model_path: Path
    report_path: Path


REQUIRED_REPORTS = (
    "application",
    "architectures",
    "functions",
    "callgraph",
    "recovered-code-index",
    "objc-dispatch",
    "objc-type-flow",
    "platform-api-map",
)
PRESERVED_REPORTS = (
    "callgraph",
    "objc-dispatch",
    "objc-type-flow",
    "platform-api-map",
)
CLASSIFICATIONS = ("exact", "candidate_set", "unresolved")
ITANIUM_ABI_URL = "https://itanium-cxx-abi.github.io/cxx-abi/abi.html"
RTTI_RELOCATION_KINDS = {
    "__ZTVN10__cxxabiv117__class_type_infoE": "class_type_info",
    "__ZTVN10__cxxabiv120__si_class_type_infoE": "si_class_type_info",
    "__ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi_class_type_info",
}
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]+$")
_SPECIAL_RE = re.compile(r"(?P<variant>C[123]|D[012])E")
_PTR_ASSIGN_RE = re.compile(
    r"(?P<lhs>[^;\n=]{1,240})=\s*(?:\([^;\n]{0,100}?\)\s*)?"
    r"PTR_[A-Za-z0-9_$]*?(?P<cell>[0-9A-Fa-f]{8,16})\s*"
    r"(?:\+\s*(?P<offset>0x[0-9A-Fa-f]+|[0-9]+))?\s*;"
)
_VIRTUAL_OFFSET_RE = re.compile(
    r"\*\*\s*\(\s*code\s*\*\*\s*\)\s*\([^;\n]{0,220}?"
    r"\+\s*(?P<offset>0x[0-9A-Fa-f]+|[0-9]+)\s*\)"
)
_VIRTUAL_INDEX_RE = re.compile(
    r"field0_0x0\s*\[\s*(?P<index>[0-9]+)\s*\]"
)
_VIRTUAL_ZERO_RE = re.compile(
    r"(?:\*\*\s*\(\s*code\s*\*\*\s*\)\s*\*|"
    r"\*\s*\(\s*code\s*\*\s*\)\s*\*\*)"
)


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CppModelError(f"Analysis workspace is missing analysis/{name}.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CppModelError(f"Cannot read {path}: {exc}") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("artifact") != name
        or not isinstance(value.get("facts"), dict)
    ):
        raise CppModelError(f"Invalid IPALift {name} report: {path}")
    return value


def _relative_file(workspace: Path, relative: str) -> Path:
    portable = str(relative).replace("\\", "/")
    parts = portable.split("/")
    if (
        not portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise CppModelError(f"Artifact path escapes the analysis workspace: {relative}")
    candidate = (workspace / Path(*parts)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise CppModelError(f"Artifact path escapes the analysis workspace: {relative}") from exc
    return candidate


def _address(value: int | str | None, width: int = 8) -> str | None:
    if value is None:
        return None
    try:
        number = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return f"0x{number:0{width}x}"


def _address_key(value: str | None) -> tuple[int, str]:
    if value and _ADDRESS_RE.match(value):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _stable_id(kind: str, *parts: Any) -> str:
    identity = "\0".join([kind, *(str(part) for part in parts)])
    return f"{kind}:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def _confidence(classification: str) -> str:
    return {"exact": "high", "candidate_set": "medium", "unresolved": "low"}[classification]


def _function_architecture(
    function_facts: dict[str, Any], slices: Iterable[MachOSlice]
) -> str:
    """Identify the one Mach-O slice represented by the Ghidra function corpus."""
    candidates = sorted(slices, key=lambda item: item.architecture_name)
    if len(candidates) == 1:
        return candidates[0].architecture_name

    ghidra = function_facts.get("ghidra") or {}
    language_id = str(ghidra.get("language_id") or "")
    parts = language_id.split(":")
    if len(parts) < 4:
        raise CppModelError(
            "Cannot attribute Ghidra functions to one Mach-O architecture: "
            f"invalid or missing language_id {language_id!r}"
        )

    processor, endian_name, bits_text, variant = parts[:4]
    try:
        bits = int(bits_text)
    except ValueError as exc:
        raise CppModelError(
            "Cannot attribute Ghidra functions to one Mach-O architecture: "
            f"invalid language bit width in {language_id!r}"
        ) from exc
    endian = {"LE": "<", "BE": ">"}.get(endian_name.upper())
    cpu_types = {
        "arm": {12},
        "aarch64": {0x0100000C},
        "x86": {7, 0x01000007},
        "powerpc": {18, 0x01000012},
    }.get(processor.casefold(), set())
    matched = [
        item
        for item in candidates
        if item.bits == bits
        and endian is not None
        and item.endian == endian
        and item.cpu_type in cpu_types
    ]
    if len(matched) == 1:
        return matched[0].architecture_name

    if processor.casefold() == "arm":
        expected_name = f"arm{variant.casefold().removeprefix('v')}"
        variant_matches = [
            item for item in matched if item.architecture_name.casefold() == expected_name
        ]
        if len(variant_matches) == 1:
            return variant_matches[0].architecture_name

    matched_names = ", ".join(item.architecture_name for item in matched) or "none"
    raise CppModelError(
        "Cannot attribute Ghidra functions to one Mach-O architecture from "
        f"language_id {language_id!r}; matching slices: {matched_names}"
    )


def _defined_symbols(macho_slice: MachOSlice) -> list[dict[str, Any]]:
    return sorted(
        (
            item
            for item in macho_slice.symbols_by_index
            if item
            and int(item.get("value") or 0) > 0
            and int(item.get("type_kind") or 0) in (0x02, 0x0E)
        ),
        key=lambda item: (int(item["value"]), str(item["name"])),
    )


def _type_encoding(symbol_name: str, prefix: str) -> str | None:
    marker = f"__Z{prefix}"
    if not symbol_name.startswith(marker) or len(symbol_name) == len(marker):
        return None
    return symbol_name[len(marker):]


def _read_number(value: str) -> tuple[int | None, str]:
    match = re.match(r"([0-9]+)", value)
    if not match:
        return None, value
    length = int(match.group(1))
    start = match.end()
    end = start + length
    if length <= 0 or end > len(value):
        return None, value
    return length, value[start:end] + "\0" + value[end:]


def _display_type_name(encoding: str) -> str | None:
    """Decode only simple ABI length components; retain raw encoding otherwise."""
    original = encoding
    nested = encoding.startswith("N") and encoding.endswith("E")
    if nested:
        encoding = encoding[1:-1]
    parts: list[str] = []
    while encoding:
        match = re.match(r"([0-9]+)", encoding)
        if not match:
            return None
        size = int(match.group(1))
        start = match.end()
        if size <= 0 or start + size > len(encoding):
            return None
        parts.append(encoding[start:start + size])
        encoding = encoding[start + size:]
        if encoding.startswith("I"):
            return None
    if not parts or (len(parts) > 1 and not nested):
        return None
    return "::".join(parts) if original else None


def _class_id(architecture: str, type_encoding: str) -> str:
    return _stable_id("cpp-class", architecture, "itanium", type_encoding)


def _section_for(macho_slice: MachOSlice, address: int) -> Any | None:
    for section in macho_slice.sections:
        if section.address <= address < section.address + section.size:
            return section
    return None


def _signed_pointer(macho_slice: MachOSlice, address: int) -> int | None:
    fmt = "q" if macho_slice.bits == 64 else "i"
    value = macho_slice.unpack_vm(fmt, address, "signed ABI pointer")
    return int(value[0]) if value else None


def _record_rtti(
    macho_slice: MachOSlice,
    architecture: str,
    symbol: dict[str, Any],
    rtti_symbols_by_address: dict[int, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    pointer_size = macho_slice.pointer_size
    address = int(symbol["value"])
    type_encoding = _type_encoding(str(symbol["name"]), "TI") or ""
    runtime_symbol = macho_slice.relocations_by_address.get(address)
    layout = RTTI_RELOCATION_KINDS.get(str(runtime_symbol))
    name_pointer = macho_slice.read_pointer_vm(address + pointer_size)
    type_name = macho_slice.read_cstring_vm(name_pointer) if name_pointer else None
    failures: list[str] = []
    if not type_encoding:
        failures.append("missing_itanium_type_encoding")
    if layout is None:
        failures.append("unsupported_rtti_runtime_layout")
    if not name_pointer or type_name is None:
        failures.append("rtti_type_name_pointer_unreadable")
    elif type_name != type_encoding:
        failures.append("rtti_type_name_does_not_match_symbol_encoding")
    relationships: list[dict[str, Any]] = []
    if layout == "si_class_type_info":
        base_address = macho_slice.read_pointer_vm(address + 2 * pointer_size)
        base_symbol = rtti_symbols_by_address.get(int(base_address or 0))
        classification = "exact" if base_symbol else "unresolved"
        reason = [] if base_symbol else ["base_rtti_pointer_not_recovered"]
        base_encoding = (
            _type_encoding(str(base_symbol["name"]), "TI") if base_symbol else None
        )
        relationships.append({
            "id": _stable_id("cpp-inheritance", architecture, address, 0),
            "architecture": architecture,
            "derived_class_id": _class_id(architecture, type_encoding),
            "base_class_id": _class_id(architecture, base_encoding) if base_encoding else None,
            "base_rtti_address": _address(base_address),
            "kind": "single_non_virtual",
            "offset": 0,
            "public": True,
            "virtual": False,
            "classification": classification,
            "confidence": _confidence(classification),
            "provenance": ["itanium_rtti", "macho_pointer"],
            "evidence": [{"source": "executable", "address": _address(address + 2 * pointer_size), "basis": "__si_class_type_info base RTTI pointer"}],
            "failure_reasons": reason,
        })
    elif layout == "vmi_class_type_info":
        header = macho_slice.unpack_vm("II", address + 2 * pointer_size, "VMI RTTI header")
        if not header:
            failures.append("vmi_header_unreadable")
        else:
            flags, base_count = (int(header[0]), int(header[1]))
            section = _section_for(macho_slice, address)
            entry_size = 2 * pointer_size
            entries_start = address + 2 * pointer_size + 8
            available = (
                max(0, section.address + section.size - entries_start) // entry_size
                if section else 0
            )
            if base_count > available or base_count > 4096:
                failures.append("vmi_base_array_out_of_bounds")
            else:
                for index in range(base_count):
                    entry = entries_start + index * entry_size
                    base_address = macho_slice.read_pointer_vm(entry)
                    offset_flags = macho_slice.read_pointer_vm(entry + pointer_size)
                    base_symbol = rtti_symbols_by_address.get(int(base_address or 0))
                    base_encoding = (
                        _type_encoding(str(base_symbol["name"]), "TI") if base_symbol else None
                    )
                    decoded = int(offset_flags or 0)
                    raw_offset = decoded >> 8
                    sign_bit = 1 << (macho_slice.bits - 9)
                    if raw_offset & sign_bit:
                        raw_offset -= 1 << (macho_slice.bits - 8)
                    classification = "exact" if base_symbol and offset_flags is not None else "unresolved"
                    reason = [] if classification == "exact" else ["vmi_base_descriptor_incomplete"]
                    relationships.append({
                        "id": _stable_id("cpp-inheritance", architecture, address, index),
                        "architecture": architecture,
                        "derived_class_id": _class_id(architecture, type_encoding),
                        "base_class_id": _class_id(architecture, base_encoding) if base_encoding else None,
                        "base_rtti_address": _address(base_address),
                        "kind": "virtual_or_multiple",
                        "offset": raw_offset,
                        "public": bool(decoded & 0x2),
                        "virtual": bool(decoded & 0x1),
                        "classification": classification,
                        "confidence": _confidence(classification),
                        "provenance": ["itanium_rtti", "macho_pointer"],
                        "evidence": [{"source": "executable", "address": _address(entry), "basis": "__vmi_class_type_info base descriptor"}],
                        "failure_reasons": reason,
                    })
            if flags:
                failures.append("vmi_hierarchy_flags_recorded")
    classification = "exact" if not [x for x in failures if x != "vmi_hierarchy_flags_recorded"] else "unresolved"
    record = {
        "id": _stable_id("cpp-rtti", architecture, address),
        "architecture": architecture,
        "class_id": _class_id(architecture, type_encoding),
        "address": _address(address),
        "symbol": str(symbol["name"]),
        "mangled_type_encoding": type_encoding,
        "runtime_layout": layout,
        "runtime_vtable_symbol": runtime_symbol,
        "type_name_address": _address(name_pointer),
        "type_name": type_name,
        "classification": classification,
        "confidence": _confidence(classification),
        "provenance": ["itanium_rtti", "macho_symbol_table", "macho_relocation", "macho_pointer"],
        "evidence": [{"source": "executable", "address": _address(address), "basis": "defined _ZTI symbol and documented RTTI layout"}],
        "failure_reasons": sorted(set(failures)),
    }
    return record, relationships


def _function_maps(
    functions: list[dict[str, Any]], architecture: str, bits: int
) -> tuple[dict[int, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    by_address: dict[int, list[dict[str, Any]]] = defaultdict(list)
    by_id: dict[str, dict[str, Any]] = {}
    for function in functions:
        function_id = str(function.get("id") or "")
        by_id[function_id] = function
        address = _address(function.get("address"), bits // 4)
        if address:
            value = int(address, 16)
            by_address[value].append(function)
            if value & 1:
                by_address[value & ~1].append(function)
    return by_address, by_id


def _slot_record(
    macho_slice: MachOSlice,
    architecture: str,
    vtable_id: str,
    address_point_id: str,
    slot_index: int,
    slot_address: int,
    function_by_address: dict[int, list[dict[str, Any]]],
    exact_symbols_by_address: dict[int, list[str]],
) -> dict[str, Any]:
    raw_target = macho_slice.read_pointer_vm(slot_address)
    relocation = macho_slice.relocations_by_address.get(slot_address)
    canonical_target = (int(raw_target) & ~1) if raw_target else None
    functions = sorted(
        {
            str(item["id"]): item
            for item in function_by_address.get(int(canonical_target or 0), [])
        }.values(),
        key=lambda item: str(item["id"]),
    )
    pure_virtual = relocation in {"___cxa_pure_virtual", "__cxa_pure_virtual"}
    target_ids = [str(item["id"]) for item in functions]
    failures: list[str] = []
    if pure_virtual:
        classification = "exact"
    elif len(target_ids) == 1:
        classification = "exact"
    elif len(target_ids) > 1:
        classification = "candidate_set"
        failures.append("multiple_functions_share_slot_target_address")
    else:
        classification = "unresolved"
        failures.append("slot_target_not_mapped_to_function")
    return {
        "id": _stable_id("cpp-vtable-slot", architecture, slot_address),
        "architecture": architecture,
        "vtable_id": vtable_id,
        "address_point_id": address_point_id,
        "slot_index": slot_index,
        "slot_offset": slot_index * macho_slice.pointer_size,
        "slot_address": _address(slot_address),
        "raw_target_address": _address(raw_target),
        "canonical_target_address": _address(canonical_target),
        "target_function_ids": target_ids,
        "target_symbols": sorted(set(exact_symbols_by_address.get(int(canonical_target or 0), []))),
        "pure_virtual": pure_virtual,
        "classification": classification,
        "confidence": _confidence(classification),
        "provenance": ["itanium_virtual_table", "macho_pointer"],
        "evidence": [{"source": "executable", "address": _address(slot_address), "basis": "pointer-sized virtual table slot"}],
        "failure_reasons": failures,
    }


def _record_vtable(
    macho_slice: MachOSlice,
    architecture: str,
    symbol: dict[str, Any],
    bound: int,
    rtti_by_address: dict[int, dict[str, Any]],
    function_by_address: dict[int, list[dict[str, Any]]],
    exact_symbols_by_address: dict[int, list[str]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    pointer_size = macho_slice.pointer_size
    address = int(symbol["value"])
    type_encoding = _type_encoding(str(symbol["name"]), "TV") or ""
    vtable_id = _stable_id("cpp-vtable", architecture, address)
    failures: list[str] = []
    if bound <= address or (bound - address) % pointer_size:
        failures.append("vtable_symbol_extent_not_pointer_aligned")
        bound = address
    headers: list[int] = []
    cursor = address
    while cursor + 2 * pointer_size <= bound:
        offset_to_top = _signed_pointer(macho_slice, cursor)
        rtti_pointer = macho_slice.read_pointer_vm(cursor + pointer_size)
        if offset_to_top is not None and int(rtti_pointer or 0) in rtti_by_address:
            headers.append(cursor)
            cursor += 2 * pointer_size
            continue
        cursor += pointer_size
    if not headers or headers[0] != address:
        failures.append("primary_vtable_header_not_proven")
    address_points: list[dict[str, Any]] = []
    slots: list[dict[str, Any]] = []
    for header_index, header_address in enumerate(headers):
        next_header = headers[header_index + 1] if header_index + 1 < len(headers) else bound
        offset_to_top = _signed_pointer(macho_slice, header_address)
        rtti_pointer = macho_slice.read_pointer_vm(header_address + pointer_size)
        rtti = rtti_by_address.get(int(rtti_pointer or 0))
        address_point = header_address + 2 * pointer_size
        point_id = _stable_id("cpp-address-point", architecture, address_point)
        point_slots: list[str] = []
        for slot_index, slot_address in enumerate(range(address_point, next_header, pointer_size)):
            slot = _slot_record(
                macho_slice,
                architecture,
                vtable_id,
                point_id,
                slot_index,
                slot_address,
                function_by_address,
                exact_symbols_by_address,
            )
            slots.append(slot)
            point_slots.append(slot["id"])
        point_classification = "exact" if rtti and offset_to_top is not None else "unresolved"
        address_points.append({
            "id": point_id,
            "architecture": architecture,
            "vtable_id": vtable_id,
            "class_id": rtti.get("class_id") if rtti else None,
            "header_address": _address(header_address),
            "address": _address(address_point),
            "offset_to_top": offset_to_top,
            "rtti_address": _address(rtti_pointer),
            "primary": header_index == 0,
            "slot_ids": point_slots,
            "classification": point_classification,
            "confidence": _confidence(point_classification),
            "provenance": ["itanium_virtual_table", "macho_pointer"],
            "evidence": [{"source": "executable", "address": _address(header_address), "basis": "offset-to-top and RTTI pointer precede the ABI address point"}],
            "failure_reasons": [] if point_classification == "exact" else ["vtable_header_rtti_not_recovered"],
        })
    classification = "exact" if address_points and not failures else "unresolved"
    record = {
        "id": vtable_id,
        "architecture": architecture,
        "class_id": _class_id(architecture, type_encoding),
        "address": _address(address),
        "end_address": _address(bound),
        "symbol": str(symbol["name"]),
        "mangled_type_encoding": type_encoding,
        "address_point_ids": [item["id"] for item in address_points],
        "slot_ids": [item["id"] for item in slots],
        "classification": classification,
        "confidence": _confidence(classification),
        "provenance": ["itanium_virtual_table", "macho_symbol_table", "macho_pointer"],
        "evidence": [{"source": "executable", "address": _address(address), "basis": "defined _ZTV symbol bounded by the next exact section symbol"}],
        "failure_reasons": failures,
    }
    return record, address_points + slots


def _special_class_encoding(symbol_name: str, variant_start: int) -> str | None:
    if not symbol_name.startswith("__ZN"):
        return None
    inner = symbol_name[4:variant_start]
    if not inner:
        return None
    return inner


def _parse_virtual_forms(code: str, pointer_size: int) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    occupied: list[tuple[int, int]] = []
    for pattern, mode in ((_VIRTUAL_OFFSET_RE, "byte_offset"), (_VIRTUAL_INDEX_RE, "array_index")):
        for match in pattern.finditer(code):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            if mode == "byte_offset":
                offset = int(match.group("offset"), 0)
                if offset % pointer_size:
                    continue
                index = offset // pointer_size
            else:
                index = int(match.group("index"))
                offset = index * pointer_size
            occupied.append(match.span())
            forms.append({
                "slot_index": index,
                "slot_offset": offset,
                "pseudocode_offset": match.start(),
                "line": code.count("\n", 0, match.start()) + 1,
                "form": mode,
                "expression": match.group(0)[:240],
            })
    for match in _VIRTUAL_ZERO_RE.finditer(code):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        forms.append({
            "slot_index": 0,
            "slot_offset": 0,
            "pseudocode_offset": match.start(),
            "line": code.count("\n", 0, match.start()) + 1,
            "form": "zero_offset_dereference",
            "expression": match.group(0)[:240],
        })
    return sorted(forms, key=lambda item: (item["pseudocode_offset"], item["slot_index"]))


def _freeze_index(values: dict[str, dict[str, set[str]]], key_name: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in sorted(values, key=lambda item: (_address_key(item), item)):
        record: dict[str, Any] = {key_name: key}
        for field_name, members in sorted(values[key].items()):
            record[field_name] = sorted(members, key=lambda item: (_address_key(item), item))
        records.append(record)
    return records


def recover_cpp_model(workspace: Path) -> CppModelResult:
    """Recover documented C++ ABI structures without rewriting prior analyses."""
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise CppModelError(f"Analysis workspace does not exist: {workspace}") from exc
    if not workspace.is_dir():
        raise CppModelError(f"Analysis workspace is not a directory: {workspace}")

    reports = {name: _load_report(workspace, name) for name in REQUIRED_REPORTS}
    preserved_hashes = {
        name: sha256_file(workspace / "analysis" / f"{name}.json")
        for name in PRESERVED_REPORTS
    }
    application = reports["application"]["facts"]
    executable_record = application.get("executable") or {}
    archive_path = str(executable_record.get("archive_path") or "")
    executable = _relative_file(workspace, f"evidence/extracted/{archive_path}")
    if not executable.is_file():
        raise CppModelError(f"Extracted executable is missing: {executable}")
    actual_hash = sha256_file(executable)
    if actual_hash != executable_record.get("sha256"):
        raise CppModelError("Extracted executable SHA-256 does not match application.json")
    if executable.stat().st_size != executable_record.get("size"):
        raise CppModelError("Extracted executable size does not match application.json")

    macho = parse_macho_file(executable)
    architecture_records = reports["architectures"]["facts"].get("architectures") or []
    expected_architectures = sorted(str(item.get("architecture")) for item in architecture_records)
    actual_architectures = sorted(item.architecture_name for item in macho.slices)
    if expected_architectures != actual_architectures:
        raise CppModelError("Executable architectures do not match architectures.json")

    function_facts = reports["functions"]["facts"]
    functions = list(function_facts.get("functions") or [])
    call_edges = list(reports["callgraph"]["facts"].get("edges") or [])
    recovered = reports["recovered-code-index"]["facts"]
    recovered_functions = list(recovered.get("functions") or [])
    recovered_by_id = {str(item.get("function_id")): item for item in recovered_functions}
    methods_by_id = {str(item.get("id")): item for item in recovered.get("methods") or []}

    all_rtti: list[dict[str, Any]] = []
    all_relationships: list[dict[str, Any]] = []
    all_vtables: list[dict[str, Any]] = []
    all_address_points: list[dict[str, Any]] = []
    all_slots: list[dict[str, Any]] = []
    all_specials: list[dict[str, Any]] = []
    classes_seed: dict[str, dict[str, Any]] = {}
    slice_contexts: dict[str, dict[str, Any]] = {}

    for macho_slice in sorted(macho.slices, key=lambda item: item.architecture_name):
        architecture = macho_slice.architecture_name
        symbols = _defined_symbols(macho_slice)
        exact_symbols_by_address: dict[int, list[str]] = defaultdict(list)
        for symbol in symbols:
            exact_symbols_by_address[int(symbol["value"])].append(str(symbol["name"]))
        function_by_address, _ = _function_maps(functions, architecture, macho_slice.bits)
        rtti_symbols = [item for item in symbols if _type_encoding(str(item["name"]), "TI")]
        rtti_symbols_by_address = {int(item["value"]): item for item in rtti_symbols}
        rtti_by_address: dict[int, dict[str, Any]] = {}
        for symbol in rtti_symbols:
            record, relationships = _record_rtti(
                macho_slice, architecture, symbol, rtti_symbols_by_address
            )
            all_rtti.append(record)
            rtti_by_address[int(symbol["value"])] = record
            all_relationships.extend(relationships)
            classes_seed.setdefault(record["class_id"], {
                "architecture": architecture,
                "mangled_type_encoding": record["mangled_type_encoding"],
                "rtti_ids": set(), "vtable_ids": set(), "special_member_ids": set(),
                "assignment_ids": set(), "inheritance_ids": set(), "function_ids": set(),
                "method_ids": set(), "objc_class_names": set(), "failure_reasons": set(),
            })["rtti_ids"].add(record["id"])

        section_symbols: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for symbol in symbols:
            section_symbols[int(symbol.get("section_index") or 0)].append(symbol)
        vtable_symbols = [item for item in symbols if _type_encoding(str(item["name"]), "TV")]
        for symbol in vtable_symbols:
            section_items = section_symbols[int(symbol.get("section_index") or 0)]
            following = [int(item["value"]) for item in section_items if int(item["value"]) > int(symbol["value"])]
            section = _section_for(macho_slice, int(symbol["value"]))
            default_bound = section.address + section.size if section else int(symbol["value"])
            bound = min(following) if following else default_bound
            vtable, components = _record_vtable(
                macho_slice,
                architecture,
                symbol,
                bound,
                rtti_by_address,
                function_by_address,
                exact_symbols_by_address,
            )
            all_vtables.append(vtable)
            points = [item for item in components if item["id"].startswith("cpp-address-point:")]
            slots = [item for item in components if item["id"].startswith("cpp-vtable-slot:")]
            all_address_points.extend(points)
            all_slots.extend(slots)
            seed = classes_seed.setdefault(vtable["class_id"], {
                "architecture": architecture,
                "mangled_type_encoding": vtable["mangled_type_encoding"],
                "rtti_ids": set(), "vtable_ids": set(), "special_member_ids": set(),
                "assignment_ids": set(), "inheritance_ids": set(), "function_ids": set(),
                "method_ids": set(), "objc_class_names": set(), "failure_reasons": set(),
            })
            seed["vtable_ids"].add(vtable["id"])
            seed["failure_reasons"].update(vtable["failure_reasons"])

        type_encodings = {seed["mangled_type_encoding"]: class_id for class_id, seed in classes_seed.items() if seed["architecture"] == architecture}
        for symbol in symbols:
            match = _SPECIAL_RE.search(str(symbol["name"]))
            if not match:
                continue
            inner = _special_class_encoding(str(symbol["name"]), match.start())
            candidates = [inner, f"N{inner}E" if inner else None]
            class_ids = sorted({type_encodings[value] for value in candidates if value in type_encodings})
            target_functions = function_by_address.get(int(symbol["value"]) & ~1, [])
            target_ids = sorted({str(item["id"]) for item in target_functions})
            classification = "exact" if len(class_ids) == 1 and len(target_ids) == 1 else ("candidate_set" if class_ids or target_ids else "unresolved")
            failures: list[str] = []
            if len(class_ids) != 1:
                failures.append("special_member_class_not_unique")
            if len(target_ids) != 1:
                failures.append("special_member_function_not_unique")
            special_id = _stable_id("cpp-special-member", architecture, symbol["value"], symbol["name"])
            special = {
                "id": special_id,
                "architecture": architecture,
                "class_ids": class_ids,
                "address": _address(int(symbol["value"]) & ~1),
                "symbol": str(symbol["name"]),
                "kind": "constructor" if match.group("variant").startswith("C") else "destructor",
                "abi_variant": match.group("variant"),
                "function_ids": target_ids,
                "classification": classification,
                "confidence": _confidence(classification),
                "provenance": ["itanium_name_mangling", "macho_symbol_table", "ghidra_function"],
                "evidence": [{"source": "executable", "address": _address(symbol["value"]), "basis": "defined ABI constructor/destructor variant symbol"}],
                "failure_reasons": failures,
            }
            all_specials.append(special)
            for class_id in class_ids:
                classes_seed[class_id]["special_member_ids"].add(special_id)
                classes_seed[class_id]["function_ids"].update(target_ids)
        slice_contexts[architecture] = {
            "slice": macho_slice,
            "points": {int(item["address"], 16): item for item in all_address_points if item["architecture"] == architecture},
        }

    for relationship in all_relationships:
        derived = relationship.get("derived_class_id")
        base = relationship.get("base_class_id")
        if derived in classes_seed:
            classes_seed[derived]["inheritance_ids"].add(relationship["id"])
        if base in classes_seed:
            classes_seed[base]["inheritance_ids"].add(relationship["id"])

    special_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for special in all_specials:
        for function_id in special["function_ids"]:
            special_by_function[function_id].append(special)
    point_by_arch_address = {
        (item["architecture"], int(item["address"], 16)): item for item in all_address_points
    }
    vtable_by_id = {item["id"]: item for item in all_vtables}

    pseudocode_artifacts: list[dict[str, Any]] = []
    code_by_function: dict[str, str] = {}
    function_architecture = _function_architecture(function_facts, macho.slices)
    for recovered_function in sorted(recovered_functions, key=lambda item: str(item.get("function_id"))):
        decompilation = recovered_function.get("decompilation") or {}
        if decompilation.get("status") != "success" or not decompilation.get("output_path"):
            continue
        path = _relative_file(workspace, str(decompilation["output_path"]))
        expected_hash = str(decompilation.get("sha256") or "")
        if not path.is_file() or sha256_file(path) != expected_hash:
            raise CppModelError(f"Pseudocode hash mismatch: {decompilation['output_path']}")
        try:
            code = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CppModelError(f"Cannot read pseudocode {path}: {exc}") from exc
        function_id = str(recovered_function.get("function_id"))
        code_by_function[function_id] = code
        pseudocode_artifacts.append({
            "function_id": function_id,
            "path": str(decompilation["output_path"]).replace("\\", "/"),
            "sha256": expected_hash,
        })

    assignments: list[dict[str, Any]] = []
    for function_id, code in sorted(code_by_function.items()):
        architecture = function_architecture or str(recovered_by_id.get(function_id, {}).get("architecture") or "")
        context = slice_contexts.get(architecture)
        if not context:
            continue
        macho_slice = context["slice"]
        for ordinal, match in enumerate(_PTR_ASSIGN_RE.finditer(code)):
            cell_address = int(match.group("cell"), 16)
            offset = int(match.group("offset") or "0", 0)
            pointer = macho_slice.read_pointer_vm(cell_address)
            target_address = int(pointer or 0) + offset if pointer is not None else None
            point = point_by_arch_address.get((architecture, int(target_address or 0)))
            if not point:
                continue
            vtable = vtable_by_id[point["vtable_id"]]
            special_classes = sorted({class_id for item in special_by_function.get(function_id, []) for class_id in item["class_ids"]})
            exact_special = any(
                item["classification"] == "exact" and vtable["class_id"] in item["class_ids"]
                for item in special_by_function.get(function_id, [])
            )
            classification = "exact" if exact_special else "candidate_set"
            failures = [] if exact_special else ["vptr_store_not_in_exact_matching_constructor_or_destructor"]
            assignment_id = _stable_id("cpp-vtable-assignment", architecture, function_id, match.start(), point["id"])
            record = {
                "id": assignment_id,
                "architecture": architecture,
                "function_id": function_id,
                "class_ids": [vtable["class_id"]],
                "special_member_class_ids": special_classes,
                "vtable_id": vtable["id"],
                "address_point_id": point["id"],
                "pointer_cell_address": _address(cell_address),
                "stored_address": point["address"],
                "object_expression": match.group("lhs").strip()[-240:],
                "pseudocode_line": code.count("\n", 0, match.start()) + 1,
                "classification": classification,
                "confidence": _confidence(classification),
                "provenance": ["ghidra_pseudocode", "macho_pointer", "itanium_virtual_table"],
                "evidence": [{"source": str(recovered_by_id[function_id]["decompilation"]["output_path"]).replace("\\", "/"), "address": None, "basis": "mechanical pointer-cell dereference equals a validated ABI address point"}],
                "failure_reasons": failures,
            }
            assignments.append(record)
            seed = classes_seed[vtable["class_id"]]
            seed["assignment_ids"].add(assignment_id)
            seed["function_ids"].add(function_id)

    slots_by_index: dict[int, list[dict[str, Any]]] = defaultdict(list)
    slots_by_point_index: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for slot in all_slots:
        slots_by_index[int(slot["slot_index"])].append(slot)
        slots_by_point_index[(slot["address_point_id"], int(slot["slot_index"]))].append(slot)
    assignments_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for assignment in assignments:
        assignments_by_function[assignment["function_id"]].append(assignment)

    indirect_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        if edge.get("indirect") and not edge.get("objective_c_dispatch"):
            indirect_by_function[str(edge.get("caller_id") or "")].append(edge)
    callsites: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    for function_id in sorted(indirect_by_function):
        edges = sorted(indirect_by_function[function_id], key=lambda item: _address_key(_address(item.get("call_site"))))
        architecture = function_architecture or str(recovered_by_id.get(function_id, {}).get("architecture") or "")
        pointer_size = slice_contexts[architecture]["slice"].pointer_size if architecture in slice_contexts else 4
        forms = _parse_virtual_forms(code_by_function.get(function_id, ""), pointer_size)
        associated: list[dict[str, Any] | None] = [None] * len(edges)
        association_basis: str | None = None
        if len(edges) == 1 and len(forms) == 1:
            associated[0] = forms[0]
            association_basis = "one indirect call edge and one mechanical virtual-call form in the function"
        elif edges and len(edges) == len(forms) and forms and len({item["slot_index"] for item in forms}) == 1:
            associated = list(forms)
            association_basis = "all indirect calls in the function have the same mechanical slot offset and counts match"
        for index, edge in enumerate(edges):
            form = associated[index]
            target_ids: set[str] = set()
            slot_ids: set[str] = set()
            point_ids: set[str] = set()
            class_ids: set[str] = set()
            exact_receiver = False
            failures: list[str] = []
            if form:
                function_assignments = assignments_by_function.get(function_id, [])
                exact_points = {
                    item["address_point_id"]
                    for item in function_assignments
                    if item["classification"] == "exact"
                }
                candidate_slots: list[dict[str, Any]]
                if len(exact_points) == 1:
                    point_id = next(iter(exact_points))
                    candidate_slots = slots_by_point_index.get((point_id, form["slot_index"]), [])
                    exact_receiver = True
                else:
                    candidate_slots = slots_by_index.get(form["slot_index"], [])
                    if len(exact_points) > 1:
                        failures.append("multiple_exact_vptr_assignments_in_caller")
                    else:
                        failures.append("receiver_vtable_not_statically_proven")
                for slot in candidate_slots:
                    slot_ids.add(slot["id"])
                    point_ids.add(slot["address_point_id"])
                    target_ids.update(slot["target_function_ids"])
                    vtable = vtable_by_id[slot["vtable_id"]]
                    class_ids.add(vtable["class_id"])
                if exact_receiver and len(target_ids) == 1:
                    classification = "exact"
                    failures = []
                elif target_ids:
                    classification = "candidate_set"
                    if len(target_ids) > 1:
                        failures.append("multiple_abi_slot_targets")
                    elif not exact_receiver:
                        failures.append("unique_slot_target_not_promoted_without_receiver_proof")
                else:
                    classification = "unresolved"
                    failures.append("no_recovered_target_for_virtual_slot")
            else:
                classification = "unresolved"
                failures.append("indirect_call_not_uniquely_associated_with_virtual_form")
            caller_record = recovered_by_id.get(function_id) or {}
            method_ids = sorted(str(value) for value in caller_record.get("method_ids") or [])
            objc_classes = sorted({str(methods_by_id[item].get("class_name")) for item in method_ids if item in methods_by_id and methods_by_id[item].get("class_name")})
            callsite_id = _stable_id("cpp-indirect-callsite", architecture, function_id, edge.get("call_site"))
            record = {
                "id": callsite_id,
                "architecture": architecture,
                "call_site": _address(edge.get("call_site")),
                "caller_function_id": function_id,
                "caller_method_ids": method_ids,
                "caller_objc_class_names": objc_classes,
                "kind": "virtual" if form else "other_indirect",
                "slot_index": form["slot_index"] if form else None,
                "slot_offset": form["slot_offset"] if form else None,
                "candidate_class_ids": sorted(class_ids),
                "candidate_address_point_ids": sorted(point_ids),
                "candidate_slot_ids": sorted(slot_ids),
                "possible_target_function_ids": sorted(target_ids),
                "classification": classification,
                "confidence": _confidence(classification),
                "provenance": sorted({"ghidra_callgraph", *( ["ghidra_pseudocode", "itanium_virtual_table"] if form else [])}),
                "evidence": ([{
                    "source": str(caller_record.get("decompilation", {}).get("output_path") or "analysis/callgraph.json").replace("\\", "/"),
                    "address": _address(edge.get("call_site")),
                    "basis": association_basis or "direct call graph inventories an unresolved indirect call",
                }] if edge else []),
                "failure_reasons": sorted(set(failures)),
            }
            callsites.append(record)
            for target_id in sorted(target_ids):
                hypotheses.append({
                    "id": _stable_id("cpp-virtual-edge", callsite_id, target_id),
                    "kind": "virtual_dispatch_target",
                    "callsite_id": callsite_id,
                    "target_function_id": target_id,
                    "classification": classification,
                    "confidence": _confidence(classification),
                    "basis": "ABI slot target retained separately from the unchanged direct call graph",
                })

    function_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    class_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    vtable_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    callsite_index: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for special in all_specials:
        for function_id in special["function_ids"]:
            function_index[function_id]["special_member_ids"].add(special["id"])
            function_index[function_id]["class_ids"].update(special["class_ids"])
    for assignment in assignments:
        function_index[assignment["function_id"]]["vtable_assignment_ids"].add(assignment["id"])
        function_index[assignment["function_id"]]["class_ids"].update(assignment["class_ids"])
    for slot in all_slots:
        for function_id in slot["target_function_ids"]:
            function_index[function_id]["vtable_slot_ids"].add(slot["id"])
    for callsite in callsites:
        function_index[callsite["caller_function_id"]]["indirect_callsite_ids"].add(callsite["id"])
        for function_id in callsite["possible_target_function_ids"]:
            function_index[function_id]["possible_incoming_virtual_callsite_ids"].add(callsite["id"])
        callsite_index[callsite["id"]]["candidate_class_ids"].update(callsite["candidate_class_ids"])
        callsite_index[callsite["id"]]["candidate_vtable_slot_ids"].update(callsite["candidate_slot_ids"])
        callsite_index[callsite["id"]]["possible_target_function_ids"].update(callsite["possible_target_function_ids"])

    classes: list[dict[str, Any]] = []
    for class_id, seed in sorted(classes_seed.items()):
        for function_id in seed["function_ids"]:
            recovered_function = recovered_by_id.get(function_id) or {}
            seed["method_ids"].update(str(value) for value in recovered_function.get("method_ids") or [])
        seed["objc_class_names"].update(
            str(methods_by_id[method_id].get("class_name"))
            for method_id in seed["method_ids"]
            if method_id in methods_by_id and methods_by_id[method_id].get("class_name")
        )
        classification = "exact" if seed["rtti_ids"] or seed["vtable_ids"] else "unresolved"
        record = {
            "id": class_id,
            "architecture": seed["architecture"],
            "abi": "itanium-cxx-abi",
            "mangled_type_encoding": seed["mangled_type_encoding"],
            "display_name": _display_type_name(seed["mangled_type_encoding"]),
            "rtti_ids": sorted(seed["rtti_ids"]),
            "vtable_ids": sorted(seed["vtable_ids"]),
            "special_member_ids": sorted(seed["special_member_ids"]),
            "vtable_assignment_ids": sorted(seed["assignment_ids"]),
            "inheritance_relationship_ids": sorted(seed["inheritance_ids"]),
            "related_function_ids": sorted(seed["function_ids"]),
            "related_objc_method_ids": sorted(seed["method_ids"]),
            "related_objc_class_names": sorted(seed["objc_class_names"]),
            "classification": classification,
            "confidence": _confidence(classification),
            "provenance": ["itanium_name_mangling", "macho_symbol_table"],
            "evidence": [{"source": "executable", "address": None, "basis": "shared exact ABI type encoding across _ZTI/_ZTV/special-member symbols"}],
            "failure_reasons": sorted(seed["failure_reasons"]),
        }
        classes.append(record)
        class_index[class_id]["rtti_ids"].update(record["rtti_ids"])
        class_index[class_id]["vtable_ids"].update(record["vtable_ids"])
        class_index[class_id]["function_ids"].update(record["related_function_ids"])
        class_index[class_id]["method_ids"].update(record["related_objc_method_ids"])
    for vtable in all_vtables:
        vtable_index[vtable["id"]]["address_point_ids"].update(vtable["address_point_ids"])
        vtable_index[vtable["id"]]["slot_ids"].update(vtable["slot_ids"])
        vtable_index[vtable["id"]]["class_ids"].add(vtable["class_id"])

    for item in (classes + all_rtti + all_relationships + all_vtables + all_address_points + all_slots + all_specials + assignments + callsites):
        for reason in item.get("failure_reasons") or []:
            pass
    failure_counts = Counter(
        reason
        for collection in (classes, all_rtti, all_relationships, all_vtables, all_address_points, all_slots, all_specials, assignments, callsites)
        for item in collection
        for reason in item.get("failure_reasons") or []
    )
    all_classifications = Counter(
        item["classification"]
        for collection in (classes, all_rtti, all_relationships, all_vtables, all_address_points, all_slots, all_specials, assignments, callsites)
        for item in collection
    )
    input_artifacts = [{
        "artifact": name,
        "path": f"analysis/{name}.json",
        "sha256": sha256_file(workspace / "analysis" / f"{name}.json"),
    } for name in REQUIRED_REPORTS]
    input_artifacts.append({
        "artifact": "executable",
        "path": f"evidence/extracted/{archive_path}".replace("\\", "/"),
        "sha256": actual_hash,
    })
    abi_records = [{
        "id": "itanium-cxx-abi",
        "name": "Itanium C++ ABI",
        "version": "documented-layouts",
        "primary_source": ITANIUM_ABI_URL,
        "supported_structures": ["external-name-mangling", "virtual-tables", "class_type_info", "si_class_type_info", "vmi_class_type_info", "constructor-destructor-variants"],
        "architectures": [{
            "name": item.architecture_name,
            "bits": item.bits,
            "pointer_size": item.pointer_size,
            "endianness": "little" if item.endian == "<" else "big",
        } for item in sorted(macho.slices, key=lambda value: value.architecture_name)],
        "assumptions": [
            "Defined _ZTI and _ZTV symbols use the Itanium C++ ABI external-name grammar.",
            "RTTI runtime-vtable relocations select only the three documented layouts implemented by this stage.",
            "A virtual-table symbol extent ends at the next exact defined symbol in the same Mach-O section.",
            "ARM/Thumb code pointers are canonicalized only by clearing the architectural low state bit.",
            "Construction virtual tables, VTTs, covariant thunks, and compiler-specific extensions are not promoted without an implemented ABI layout.",
        ],
    }]
    facts = {
        "abi_records": abi_records,
        "input_artifacts": input_artifacts,
        "summary": {
            "class_count": len(classes),
            "rtti_record_count": len(all_rtti),
            "inheritance_relationship_count": len(all_relationships),
            "vtable_count": len(all_vtables),
            "address_point_count": len(all_address_points),
            "vtable_slot_count": len(all_slots),
            "special_member_function_count": len(all_specials),
            "vtable_assignment_count": len(assignments),
            "indirect_callsite_count": len(callsites),
            "virtual_callsite_count": sum(item["kind"] == "virtual" for item in callsites),
            "hypothesis_edge_count": len(hypotheses),
            "classification_counts": {name: all_classifications.get(name, 0) for name in CLASSIFICATIONS},
            "failure_reason_counts": {name: failure_counts[name] for name in sorted(failure_counts)},
        },
        "classes": sorted(classes, key=lambda item: (item["architecture"], item["mangled_type_encoding"], item["id"])),
        "rtti_records": sorted(all_rtti, key=lambda item: (item["architecture"], _address_key(item["address"]))),
        "inheritance_relationships": sorted(all_relationships, key=lambda item: (item["architecture"], item["derived_class_id"], item["id"])),
        "vtables": sorted(all_vtables, key=lambda item: (item["architecture"], _address_key(item["address"]))),
        "address_points": sorted(all_address_points, key=lambda item: (item["architecture"], _address_key(item["address"]))),
        "vtable_slots": sorted(all_slots, key=lambda item: (item["architecture"], _address_key(item["slot_address"]))),
        "special_member_functions": sorted(all_specials, key=lambda item: (item["architecture"], _address_key(item["address"]), item["symbol"])),
        "vtable_assignments": sorted(assignments, key=lambda item: (item["architecture"], item["function_id"], item["pseudocode_line"], item["id"])),
        "indirect_callsites": sorted(callsites, key=lambda item: (item["architecture"], _address_key(item["call_site"]), item["id"])),
        "pseudocode_artifacts": pseudocode_artifacts,
        "indexes": {
            "classes": _freeze_index(class_index, "class_id"),
            "vtables": _freeze_index(vtable_index, "vtable_id"),
            "functions": _freeze_index(function_index, "function_id"),
            "callsites": _freeze_index(callsite_index, "callsite_id"),
        },
        "evidence_boundary": {
            "abi_evidence_only": True,
            "names_strings_selectors_used_as_behavior_evidence": False,
            "gameplay_semantics_inferred": False,
            "direct_callgraph_preserved": True,
            "objc_dispatch_preserved": True,
            "objc_type_flow_preserved": True,
            "platform_api_map_preserved": True,
            "unsupported_abi_patterns_promoted": False,
        },
    }
    errors = [{
        "code": reason,
        "count": count,
        "message": "One or more C++ ABI records retain this uncertainty or unresolved reason",
    } for reason, count in sorted(failure_counts.items())]
    cpp_model = report_envelope("cpp-object-model", facts, hypotheses=hypotheses, errors=errors)
    cpp_model_path = workspace / "analysis" / "cpp-object-model.json"
    report_path = workspace / "reports" / "cpp-object-model-report.md"
    write_json_atomic(cpp_model_path, cpp_model)
    write_text_atomic(report_path, render_cpp_object_model_report(facts))
    after_hashes = {
        name: sha256_file(workspace / "analysis" / f"{name}.json")
        for name in PRESERVED_REPORTS
    }
    if after_hashes != preserved_hashes:
        raise CppModelError("A preserved upstream analysis artifact changed during C++ recovery")
    return CppModelResult(workspace, cpp_model, cpp_model_path, report_path)

