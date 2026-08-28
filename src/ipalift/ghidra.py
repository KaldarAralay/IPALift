"""Headless Ghidra orchestration and deterministic result normalization."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import IPALiftError
from .report import render_decompilation_report
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


class GhidraError(IPALiftError):
    """Ghidra is unavailable or its analysis did not complete correctly."""


GHIDRA_REPORT_NAMES = ("functions", "callgraph", "strings", "decompilation")
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-f]+$")
OBJ_C_DISPATCH_NAMES = (
    "objc_msgsend",
    "objc_msgsendsuper",
    "objc_msgsend_stret",
    "objc_msgsendsuper_stret",
)


@dataclass(frozen=True)
class GhidraInstallation:
    home: Path
    launcher: Path
    version: str


@dataclass(frozen=True)
class GhidraRunResult:
    workspace: Path
    reports: dict[str, dict[str, Any]]
    report_path: Path
    ghidra_version: str


def _read_properties(path: Path) -> dict[str, str]:
    properties: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise GhidraError(f"Cannot read Ghidra application properties: {exc}") from exc
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def validate_ghidra_home(path: Path) -> GhidraInstallation:
    try:
        home = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise GhidraError(f"Ghidra home does not exist: {path}") from exc
    if not home.is_dir():
        raise GhidraError(f"Ghidra home is not a directory: {home}")
    launcher_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    launcher = home / "support" / launcher_name
    properties_path = home / "Ghidra" / "application.properties"
    if not launcher.is_file() or not properties_path.is_file():
        raise GhidraError(
            f"Invalid Ghidra home {home}; expected support/{launcher_name} and Ghidra/application.properties"
        )
    properties = _read_properties(properties_path)
    version = properties.get("application.version")
    if not version:
        raise GhidraError(f"Ghidra version is missing from {properties_path}")
    return GhidraInstallation(home, launcher, version)


def discover_ghidra_home(explicit: Path | None = None, *, search_root: Path | None = None) -> GhidraInstallation:
    if explicit is not None:
        return validate_ghidra_home(explicit)
    configured = os.environ.get("GHIDRA_HOME")
    if configured:
        return validate_ghidra_home(Path(configured))
    root = (search_root or Path.cwd()).resolve()
    candidates = sorted(
        (root / "tools" / "ghidra").glob("ghidra_*_PUBLIC"),
        key=lambda item: item.name,
        reverse=True,
    ) if (root / "tools" / "ghidra").is_dir() else []
    for candidate in candidates:
        try:
            return validate_ghidra_home(candidate)
        except GhidraError:
            continue
    raise GhidraError(
        "Ghidra was not found. Pass --ghidra-home <directory>, set GHIDRA_HOME, "
        "or install an official release under tools/ghidra/."
    )


def _load_report(workspace: Path, name: str) -> dict[str, Any]:
    path = workspace / "analysis" / f"{name}.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GhidraError(f"Analysis workspace is missing {path.relative_to(workspace)}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise GhidraError(f"Cannot read {path}: {exc}") from exc
    if report.get("schema_version") != 1 or report.get("artifact") != name or not isinstance(report.get("facts"), dict):
        raise GhidraError(f"Invalid IPALift {name} report: {path}")
    return report


def _reject_encrypted_architectures(architectures: dict[str, Any]) -> None:
    encrypted: list[str] = []
    for architecture in architectures["facts"].get("architectures", []):
        encryption = architecture.get("encryption")
        if isinstance(encryption, dict) and encryption.get("is_encrypted") is True:
            name = str(architecture.get("architecture") or "unknown")
            crypt_id = encryption.get("crypt_id")
            encrypted.append(f"{name} (cryptid={crypt_id})")
    if encrypted:
        raise GhidraError(
            "Cannot decompile encrypted Mach-O code: "
            + ", ".join(encrypted)
            + ". Supply a legally obtained decrypted IPA whose LC_ENCRYPTION_INFO cryptid is 0."
        )


def _address(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        lowered = value.lower()
        if ADDRESS_PATTERN.match(lowered):
            return f"0x{int(lowered, 16):08x}"
        try:
            return f"0x{int(value, 0):08x}"
        except ValueError:
            return None
    try:
        return f"0x{int(value):08x}"
    except (TypeError, ValueError):
        return None


def _address_sort_key(value: str | None) -> tuple[int, str]:
    if value and ADDRESS_PATTERN.match(value):
        return (0, f"{int(value, 16):016x}")
    return (1, value or "")


def _safe_symbol_fragment(value: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9_$]", "_", value)
    rendered = re.sub(r"_+", "_", rendered).strip("_") or "anonymous"
    if rendered[0].isdigit():
        rendered = "n_" + rendered
    return rendered[:180]


def _canonical_implementation_address(address: str, architecture: str) -> tuple[str, bool]:
    """Clear the ARM/Thumb state bit while preserving it as explicit evidence."""
    lowered = architecture.lower()
    value = int(address, 16)
    is_thumb = lowered.startswith("arm") and "64" not in lowered and bool(value & 1)
    return (f"0x{value & ~1:08x}" if is_thumb else address, is_thumb)


def _method_records(classes_facts: dict[str, Any]) -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []
    for architecture in classes_facts.get("architectures", []):
        architecture_name = str(architecture.get("architecture") or "unknown")
        for objc_class in architecture.get("classes", []):
            class_name = str(objc_class["name"])
            for list_name, marker, kind in (
                ("instance_methods", "-", "instance"),
                ("class_methods", "+", "class"),
            ):
                for method in objc_class.get(list_name, []):
                    implementation_pointer = _address(method.get("implementation_address"))
                    if not implementation_pointer:
                        continue
                    address, thumb_entrypoint = _canonical_implementation_address(
                        implementation_pointer, architecture_name
                    )
                    selector = str(method["selector"])
                    methods.append({
                        "address": address,
                        "implementation_pointer": implementation_pointer,
                        "thumb_entrypoint": thumb_entrypoint,
                        "architecture": architecture_name,
                        "class_name": class_name,
                        "category_name": None,
                        "selector": selector,
                        "kind": kind,
                        "exact_name": f"{marker}[{class_name} {selector}]",
                        "type_encoding": method.get("type_encoding"),
                        "metadata_address": _address(method.get("metadata_address")),
                    })
        for category in architecture.get("categories", []):
            target = category.get("target_class") or {}
            class_name = str(target.get("name") or "UnknownClass")
            category_name = str(category["name"])
            display_class = f"{class_name}({category_name})"
            for list_name, marker, kind in (
                ("instance_methods", "-", "instance"),
                ("class_methods", "+", "class"),
            ):
                for method in category.get(list_name, []):
                    implementation_pointer = _address(method.get("implementation_address"))
                    if not implementation_pointer:
                        continue
                    address, thumb_entrypoint = _canonical_implementation_address(
                        implementation_pointer, architecture_name
                    )
                    selector = str(method["selector"])
                    methods.append({
                        "address": address,
                        "implementation_pointer": implementation_pointer,
                        "thumb_entrypoint": thumb_entrypoint,
                        "architecture": architecture_name,
                        "class_name": class_name,
                        "category_name": category_name,
                        "selector": selector,
                        "kind": kind,
                        "exact_name": f"{marker}[{display_class} {selector}]",
                        "type_encoding": method.get("type_encoding"),
                        "metadata_address": _address(method.get("metadata_address")),
                    })
    return sorted(methods, key=lambda item: (_address_sort_key(item["address"]), item["exact_name"]))


def prepare_ghidra_evidence(workspace: Path, destination: Path) -> dict[str, Any]:
    workspace = workspace.resolve(strict=True)
    application = _load_report(workspace, "application")
    architectures = _load_report(workspace, "architectures")
    frameworks = _load_report(workspace, "frameworks")
    classes = _load_report(workspace, "classes")
    assets = _load_report(workspace, "assets")
    _reject_encrypted_architectures(architectures)
    app_facts = application["facts"]
    extraction_root = Path(str(app_facts["archive"]["extraction_root"]))
    executable_archive_path = str(app_facts["executable"]["archive_path"])
    executable = workspace / extraction_root / Path(*executable_archive_path.split("/"))
    if not executable.is_file():
        raise GhidraError(f"Extracted executable is missing: {executable}")
    expected_hash = str(app_facts["executable"]["sha256"])
    actual_hash = sha256_file(executable)
    if actual_hash != expected_hash:
        raise GhidraError(
            f"Extracted executable hash mismatch: expected {expected_hash}, got {actual_hash}"
        )

    methods = _method_records(classes["facts"])
    grouped_methods: list[dict[str, Any]] = []
    methods_by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for method in methods:
        methods_by_address[method["address"]].append(method)
    for address in sorted(methods_by_address, key=_address_sort_key):
        records = methods_by_address[address]
        primary = records[0]
        marker = "i" if primary["kind"] == "instance" else "c"
        internal_name = (
            f"objc_{marker}_{_safe_symbol_fragment(primary['class_name'])}_"
            f"{_safe_symbol_fragment(primary['selector'])}_{address[2:]}"
        )
        grouped_methods.append({
            "address": address,
            "namespace": _safe_symbol_fragment(primary["class_name"]),
            "internal_name": internal_name,
            "exact_names": [record["exact_name"] for record in records],
            "records": records,
        })

    architecture_records = architectures["facts"].get("architectures", [])
    symbols = []
    sections = []
    imports = []
    for architecture in architecture_records:
        architecture_name = architecture.get("architecture")
        for symbol in architecture.get("exports", []):
            address = _address(symbol.get("address"))
            if address:
                symbols.append({
                    "address": address,
                    "name": symbol["name"],
                    "architecture": architecture_name,
                })
        for symbol in architecture.get("imports", []):
            imports.append({"name": symbol["name"], "architecture": architecture_name})
        for section in architecture.get("sections", []):
            sections.append({
                "address": _address(section.get("address")),
                "size": section.get("size"),
                "segment": section.get("segment"),
                "name": section.get("name"),
                "architecture": architecture_name,
            })

    evidence = {
        "schema_version": 1,
        "executable": {
            "path": str(executable),
            "sha256": actual_hash,
            "archive_path": executable_archive_path,
        },
        "methods": grouped_methods,
        "method_record_count": len(methods),
        "symbols": sorted(symbols, key=lambda item: (_address_sort_key(item["address"]), item["name"])),
        "imports": sorted(imports, key=lambda item: (item["name"], str(item["architecture"]))),
        "frameworks": frameworks["facts"].get("linked_libraries", []),
        "sections": sorted(sections, key=lambda item: (_address_sort_key(item["address"]), str(item["name"]))),
        "classes": [
            {
                "name": objc_class["name"],
                "address": _address(objc_class.get("address")),
                "metaclass_address": _address(objc_class.get("metaclass_address")),
            }
            for architecture in classes["facts"].get("architectures", [])
            for objc_class in architecture.get("classes", [])
        ],
        "selectors": sorted({
            selector
            for architecture in classes["facts"].get("architectures", [])
            for selector in architecture.get("selectors", [])
        }),
        "assets": [
            {
                "path": record["path"],
                "bundle_relative_path": record.get("bundle_relative_path"),
                "sha256": record["sha256"],
                "asset_category": record.get("asset_category"),
            }
            for record in assets["facts"].get("assets", [])
        ],
    }
    write_json_atomic(destination, evidence)
    evidence["_workspace"] = workspace
    evidence["_executable"] = executable
    return evidence


def build_headless_arguments(
    installation: GhidraInstallation,
    project_root: Path,
    executable: Path,
    evidence_path: Path,
    raw_output: Path,
    *,
    function_timeout: int,
    analysis_timeout: int,
) -> list[str]:
    script_path = Path(__file__).resolve().parent / "ghidra_scripts"
    configuration_script = script_path / "IPALiftConfigure.java"
    script = script_path / "IPALiftHeadless.java"
    for required_script in (configuration_script, script):
        if not required_script.is_file():
            raise GhidraError(f"Bundled Ghidra script is missing: {required_script}")
    return [
        str(installation.launcher),
        str(project_root),
        "IPALiftTransient",
        "-max-cpu",
        "1",
        "-import",
        str(executable),
        "-loader",
        "MachoLoader",
        "-loader-loadLibraries",
        "false",
        "-loader-applyLabels",
        "true",
        "-scriptPath",
        str(script_path),
        "-preScript",
        configuration_script.name,
        "-postScript",
        script.name,
        str(evidence_path),
        str(raw_output),
        str(function_timeout),
        "-analysisTimeoutPerFile",
        str(analysis_timeout),
        "-deleteProject",
    ]


def _run_process(arguments: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        if os.name == "nt" and arguments[0].lower().endswith((".bat", ".cmd")):
            command: str | list[str] = subprocess.list2cmdline(arguments)
            shell = True
        else:
            command = arguments
            shell = False
        return subprocess.run(
            command,
            shell=shell,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise GhidraError(f"Headless Ghidra exceeded the {timeout}-second process timeout") from exc
    except OSError as exc:
        raise GhidraError(f"Cannot launch headless Ghidra: {exc}") from exc


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GhidraError(f"Ghidra did not produce {label}: {path.name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise GhidraError(f"Cannot read Ghidra {label} {path}: {exc}") from exc


def _read_json_lines(path: Path, label: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                line = raw_line.strip()
                if not line:
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise GhidraError(f"Ghidra {label} line {line_number} is not an object")
                records.append(value)
    except FileNotFoundError as exc:
        raise GhidraError(f"Ghidra did not produce {label}: {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise GhidraError(f"Invalid Ghidra {label} JSON at line {line_number}: {exc}") from exc
    except OSError as exc:
        raise GhidraError(f"Cannot read Ghidra {label} {path}: {exc}") from exc
    return records


def _is_objc_dispatch(name: str | None) -> bool:
    if not name:
        return False
    lowered = re.sub(r"[^a-z0-9_]", "", name.lower())
    return any(candidate in lowered for candidate in OBJ_C_DISPATCH_NAMES)


def _copy_normalized_code(raw_code: Path, destination: Path, expected: dict[str, str]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    expected_names: set[str] = set()
    for address, raw_relative in sorted(expected.items(), key=lambda item: _address_sort_key(item[0])):
        source = raw_code / Path(raw_relative).name
        if not source.is_file():
            raise GhidraError(f"Successful decompilation is missing code for {address}: {source}")
        name = f"{address[2:]}.c"
        expected_names.add(name)
        try:
            code = source.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise GhidraError(f"Cannot read decompiled code {source}: {exc}") from exc
        code = code.replace("\r\n", "\n").replace("\r", "\n")
        if not code.endswith("\n"):
            code += "\n"
        write_text_atomic(destination / name, code)
    for existing in destination.glob("*.c"):
        if existing.name not in expected_names:
            existing.unlink()


def normalize_ghidra_results(
    workspace: Path,
    raw_output: Path,
    evidence: dict[str, Any],
) -> GhidraRunResult:
    workspace = workspace.resolve(strict=True)
    manifest = _read_json(raw_output / "manifest.json", "manifest")
    if manifest.get("completed") is not True:
        raise GhidraError("Ghidra manifest does not report a completed export")
    functions = _read_json_lines(raw_output / "functions.jsonl", "function records")
    calls = _read_json_lines(raw_output / "calls.jsonl", "call graph records")
    strings = _read_json_lines(raw_output / "strings.jsonl", "string records")
    decompilations = _read_json_lines(raw_output / "decompilation.jsonl", "decompilation records")

    methods_by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in evidence["methods"]:
        methods_by_address[group["address"]].extend(group["records"])
    exports_by_address: dict[str, list[str]] = defaultdict(list)
    for symbol in evidence["symbols"]:
        exports_by_address[symbol["address"]].append(symbol["name"])
    imports_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for symbol in evidence["imports"]:
        imports_by_name[str(symbol["name"])].append(symbol)
    classes_by_address = {
        item["address"]: item["name"] for item in evidence["classes"] if item.get("address")
    }
    selectors = set(evidence["selectors"])
    assets_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for asset in evidence["assets"]:
        relative = asset.get("bundle_relative_path")
        if relative:
            assets_by_name[Path(relative).name].append(asset)
            assets_by_name[str(relative)].append(asset)

    string_by_address: dict[str, dict[str, Any]] = {}
    for record in strings:
        address = _address(record.get("address"))
        if address:
            record["address"] = address
            string_by_address[address] = record
        value = str(record.get("value") or "")
        record["is_selector"] = value in selectors
        matched_assets = {
            asset["path"]: asset
            for key in (value, Path(value).name if value else "")
            for asset in assets_by_name.get(key, [])
        }
        record["asset_matches"] = [matched_assets[key] for key in sorted(matched_assets)]
        record["references"] = sorted(
            record.get("references", []),
            key=lambda item: (str(item.get("from_function_id") or ""), str(item.get("from_address") or "")),
        )
    strings.sort(key=lambda item: _address_sort_key(item.get("address")))

    function_by_id: dict[str, dict[str, Any]] = {}
    mapped_import_names: set[str] = set()
    mapped_export_addresses: set[str] = set()
    for function in functions:
        function_id = str(function["id"])
        address = _address(function.get("address"))
        function["address"] = address
        objc_methods = methods_by_address.get(address or "", [])
        exports = sorted(set(exports_by_address.get(address or "", [])))
        imported_symbols = (
            sorted(imports_by_name.get(str(function.get("name") or ""), []), key=lambda item: item["name"])
            if function.get("external")
            else []
        )
        provenance = ["ghidra"]
        confidence = "medium"
        confidence_basis = ["Ghidra discovered an executable function boundary"]
        if objc_methods:
            provenance.append("objective_c_metadata")
            confidence = "high"
            confidence_basis.append("Exact Objective-C implementation address matches recovered metadata")
        if exports:
            provenance.append("macho_symbol_table")
            confidence = "high"
            confidence_basis.append("Entry address matches a defined external Mach-O symbol")
            if address:
                mapped_export_addresses.add(address)
        if imported_symbols:
            provenance.append("macho_import_table")
            confidence = "high"
            confidence_basis.append("External function name exactly matches an undefined Mach-O symbol")
            mapped_import_names.update(item["name"] for item in imported_symbols)
        referenced_strings = sorted({
            reference["to_address"]
            for reference in function.get("cross_references", [])
            if reference.get("to_address") in string_by_address
        }, key=_address_sort_key)
        referenced_classes = sorted({
            classes_by_address[reference["to_address"]]
            for reference in function.get("cross_references", [])
            if reference.get("to_address") in classes_by_address
        })
        referenced_selectors = sorted({
            str(string_by_address[address_value].get("value"))
            for address_value in referenced_strings
            if string_by_address[address_value].get("is_selector")
        })
        referenced_assets = {
            asset["path"]: asset
            for address_value in referenced_strings
            for asset in string_by_address[address_value].get("asset_matches", [])
        }
        function.update({
            "objective_c_methods": objc_methods,
            "macho_exports": exports,
            "macho_imports": imported_symbols,
            "provenance": provenance,
            "confidence": confidence,
            "confidence_basis": confidence_basis,
            "referenced_string_addresses": referenced_strings,
            "referenced_selectors": referenced_selectors,
            "referenced_classes": referenced_classes,
            "referenced_assets": [referenced_assets[key] for key in sorted(referenced_assets)],
            "callers": [],
            "callees": [],
        })
        function_by_id[function_id] = function

    normalized_calls: list[dict[str, Any]] = []
    for edge in calls:
        caller_id = str(edge.get("caller_id") or "")
        target_id = edge.get("target_function_id")
        target_name = edge.get("target_name")
        thunk_target_name = edge.get("thunk_target_name")
        objc_dispatch = _is_objc_dispatch(str(target_name) if target_name else None) or _is_objc_dispatch(
            str(thunk_target_name) if thunk_target_name else None
        )
        target_resolved = bool(target_id and target_id in function_by_id)
        semantic_resolved = target_resolved and not objc_dispatch and not edge.get("indirect", False)
        unresolved_reason = None
        if objc_dispatch:
            unresolved_reason = "Dynamic Objective-C message dispatch target is not proven"
        elif edge.get("indirect", False) and not target_resolved:
            unresolved_reason = "Indirect call target is not statically proven"
        elif not target_resolved:
            unresolved_reason = "Call target does not map to a discovered function"
        normalized = {
            **edge,
            "objective_c_dispatch": objc_dispatch,
            "resolved_function_target": target_resolved,
            "semantic_target_resolved": semantic_resolved,
            "unresolved_reason": unresolved_reason,
        }
        normalized_calls.append(normalized)
        if caller_id in function_by_id and target_id:
            function_by_id[caller_id]["callees"].append(str(target_id))
        if target_id in function_by_id and caller_id:
            function_by_id[str(target_id)]["callers"].append(caller_id)
    normalized_calls.sort(
        key=lambda item: (
            str(item.get("caller_id") or ""),
            _address_sort_key(_address(item.get("call_site"))),
            str(item.get("target_function_id") or item.get("target_address") or ""),
            str(item.get("reference_type") or ""),
        )
    )
    for function in functions:
        function["callers"] = sorted(set(function["callers"]))
        function["callees"] = sorted(set(function["callees"]))
    functions.sort(key=lambda item: (bool(item.get("external")), _address_sort_key(item.get("address")), item["id"]))

    decomp_by_id = {str(item["function_id"]): item for item in decompilations}
    eligible = [item for item in functions if not item.get("external") and not item.get("thunk")]
    missing_attempts = [item["id"] for item in eligible if item["id"] not in decomp_by_id]
    if missing_attempts:
        raise GhidraError(
            f"Ghidra omitted decompilation status for {len(missing_attempts)} eligible functions; "
            f"first missing: {missing_attempts[0]}"
        )
    success_code: dict[str, str] = {}
    for item in decompilations:
        address = _address(item.get("address"))
        item["address"] = address
        if item.get("status") == "success" and address and item.get("raw_output_file"):
            success_code[address] = str(item["raw_output_file"])
            item["output_path"] = f"decompiled/functions/{address[2:]}.c"
        else:
            item["output_path"] = None
        item.pop("raw_output_file", None)
    decompilations.sort(key=lambda item: (_address_sort_key(item.get("address")), str(item["function_id"])))
    _copy_normalized_code(raw_output / "code", workspace / "decompiled" / "functions", success_code)

    statuses: dict[str, int] = defaultdict(int)
    for item in decompilations:
        statuses[str(item.get("status"))] += 1
    eligible_count = len(eligible)
    success_count = statuses.get("success", 0)
    coverage = round(success_count / eligible_count, 6) if eligible_count else 1.0

    discovered_internal_addresses = {
        item["address"] for item in functions if item.get("address") and not item.get("external")
    }
    missing_methods = []
    for address, records in sorted(methods_by_address.items(), key=lambda item: _address_sort_key(item[0])):
        if address not in discovered_internal_addresses:
            for method in records:
                missing_methods.append({
                    "address": address,
                    "exact_name": method["exact_name"],
                    "reason": "Ghidra did not contain a function at the recovered implementation address",
                })

    unmapped_imports = [
        {
            **item,
            "reason": "No Ghidra external function has this exact name; the import may represent data",
        }
        for item in evidence["imports"]
        if item["name"] not in mapped_import_names
    ]
    unmapped_exports = [
        {
            **item,
            "reason": "No discovered internal function starts at this exported address; the export may represent data",
        }
        for item in evidence["symbols"]
        if item["address"] not in mapped_export_addresses
    ]

    function_facts = {
        "ghidra": {
            "version": manifest.get("ghidra_version"),
            "language_id": manifest.get("language_id"),
            "compiler_spec_id": manifest.get("compiler_spec_id"),
            "executable_format": manifest.get("executable_format"),
            "image_base": manifest.get("image_base"),
            "memory_blocks": manifest.get("memory_blocks", []),
            "external_libraries": manifest.get("external_libraries", []),
            "applied_method_group_count": manifest.get("applied_method_group_count"),
            "applied_method_record_count": manifest.get("applied_method_record_count"),
            "applied_symbol_count": manifest.get("applied_symbol_count"),
            "applied_section_count": manifest.get("applied_section_count"),
            "applied_framework_count": manifest.get("applied_framework_count"),
            "objective_c_message_analyzer_enabled": manifest.get(
                "objective_c_message_analyzer_enabled"
            ),
            "max_cpu": manifest.get("max_cpu"),
        },
        "discovered_function_count": len(functions),
        "internal_function_count": sum(not item.get("external") for item in functions),
        "external_function_count": sum(bool(item.get("external")) for item in functions),
        "entrypoint_count": sum(bool(item.get("entrypoint")) for item in functions),
        "thunk_count": sum(bool(item.get("thunk")) for item in functions),
        "objective_c_method_record_count": evidence["method_record_count"],
        "objective_c_unique_implementation_count": len(methods_by_address),
        "objective_c_missing_function_count": len(missing_methods),
        "macho_import_count": len(evidence["imports"]),
        "macho_import_function_match_count": len(evidence["imports"]) - len(unmapped_imports),
        "macho_import_unmatched_count": len(unmapped_imports),
        "macho_imports_without_function_match": unmapped_imports,
        "macho_export_count": len(evidence["symbols"]),
        "macho_export_function_match_count": len(evidence["symbols"]) - len(unmapped_exports),
        "macho_export_unmatched_count": len(unmapped_exports),
        "macho_exports_without_function_match": unmapped_exports,
        "linked_library_count": len(evidence["frameworks"]),
        "section_count": len(evidence["sections"]),
        "selector_evidence_count": len(evidence["selectors"]),
        "asset_evidence_count": len(evidence["assets"]),
        "functions": functions,
    }
    call_facts = {
        "edge_count": len(normalized_calls),
        "resolved_function_edge_count": sum(bool(item["resolved_function_target"]) for item in normalized_calls),
        "semantic_resolved_edge_count": sum(bool(item["semantic_target_resolved"]) for item in normalized_calls),
        "unresolved_edge_count": sum(not item["semantic_target_resolved"] for item in normalized_calls),
        "objective_c_dispatch_edge_count": sum(bool(item["objective_c_dispatch"]) for item in normalized_calls),
        "edges": normalized_calls,
    }
    string_facts = {
        "string_count": len(strings),
        "selector_string_count": sum(bool(item.get("is_selector")) for item in strings),
        "asset_matched_string_count": sum(bool(item.get("asset_matches")) for item in strings),
        "strings": strings,
    }
    decompilation_facts = {
        "eligible_internal_non_thunk_count": eligible_count,
        "attempted_count": len(decompilations),
        "success_count": success_count,
        "failure_count": statuses.get("failure", 0),
        "timeout_count": statuses.get("timeout", 0),
        "skipped_count": statuses.get("skipped", 0),
        "success_coverage": coverage,
        "functions": decompilations,
    }

    reports = {
        "functions": report_envelope("functions", function_facts),
        "callgraph": report_envelope("callgraph", call_facts),
        "strings": report_envelope("strings", string_facts),
        "decompilation": report_envelope("decompilation", decompilation_facts),
    }
    analysis_root = workspace / "analysis"
    for name, report in reports.items():
        write_json_atomic(analysis_root / f"{name}.json", report)

    unresolved = _load_report(workspace, "unresolved")
    existing_items = [
        item for item in unresolved["facts"].get("items", [])
        if not str(item.get("code", "")).startswith("ghidra_")
    ]
    for missing in missing_methods:
        existing_items.append({
            "code": "ghidra_objc_method_unmapped",
            "severity": "error",
            "address": missing["address"],
            "method": missing["exact_name"],
            "message": missing["reason"],
        })
    unresolved_semantic = sum(not edge["semantic_target_resolved"] for edge in normalized_calls)
    if unresolved_semantic:
        existing_items.append({
            "code": "ghidra_unresolved_call_targets",
            "severity": "info",
            "count": unresolved_semantic,
            "message": "Call graph contains indirect or dynamic targets that cannot be proven statically",
        })
    failed = statuses.get("failure", 0) + statuses.get("timeout", 0)
    if failed:
        existing_items.append({
            "code": "ghidra_decompilation_failures",
            "severity": "warning",
            "count": failed,
            "message": "Some eligible functions failed or timed out during decompilation; see decompilation.json",
        })
    existing_items.sort(
        key=lambda item: (
            str(item.get("severity") or ""), str(item.get("code") or ""),
            _address_sort_key(_address(item.get("address"))), str(item.get("method") or ""),
        )
    )
    unresolved["facts"] = {"item_count": len(existing_items), "items": existing_items}
    write_json_atomic(analysis_root / "unresolved.json", unresolved)

    report_path = workspace / "reports" / "decompilation-report.md"
    write_text_atomic(
        report_path,
        render_decompilation_report(function_facts, call_facts, string_facts, decompilation_facts, existing_items),
    )
    return GhidraRunResult(workspace, reports, report_path, str(manifest.get("ghidra_version") or "unknown"))


def decompile_workspace(
    workspace: Path,
    *,
    ghidra_home: Path | None = None,
    function_timeout: int = 30,
    analysis_timeout: int = 3600,
) -> GhidraRunResult:
    if function_timeout < 1 or function_timeout > 600:
        raise GhidraError("--function-timeout must be between 1 and 600 seconds")
    if analysis_timeout < 60:
        raise GhidraError("--analysis-timeout must be at least 60 seconds")
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as exc:
        raise GhidraError(f"Analysis workspace does not exist: {workspace}") from exc
    if not workspace.is_dir():
        raise GhidraError(f"Analysis workspace is not a directory: {workspace}")
    with tempfile.TemporaryDirectory(prefix="ipalift-ghidra-") as temporary:
        temporary_root = Path(temporary)
        evidence_path = temporary_root / "evidence.json"
        raw_output = temporary_root / "raw"
        project_root = temporary_root / "project"
        raw_output.mkdir()
        project_root.mkdir()
        evidence = prepare_ghidra_evidence(workspace, evidence_path)
        executable = Path(evidence.pop("_executable"))
        evidence.pop("_workspace", None)
        installation = discover_ghidra_home(ghidra_home, search_root=Path.cwd())
        arguments = build_headless_arguments(
            installation,
            project_root,
            executable,
            evidence_path,
            raw_output,
            function_timeout=function_timeout,
            analysis_timeout=analysis_timeout,
        )
        completed = _run_process(arguments, timeout=analysis_timeout + 900)
        if completed.returncode != 0:
            diagnostic = "\n".join((completed.stdout + "\n" + completed.stderr).splitlines()[-80:])
            raise GhidraError(
                f"Headless Ghidra exited with code {completed.returncode}. Last output:\n{diagnostic}"
            )
        manifest_path = raw_output / "manifest.json"
        if not manifest_path.is_file():
            diagnostic = "\n".join((completed.stdout + "\n" + completed.stderr).splitlines()[-80:])
            raise GhidraError(f"Headless Ghidra produced no completion manifest. Last output:\n{diagnostic}")
        return normalize_ghidra_results(workspace, raw_output, evidence)
