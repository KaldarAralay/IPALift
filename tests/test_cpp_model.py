from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from ipalift.cli import build_parser
from ipalift.cpp_model import CppModelError, recover_cpp_model
from ipalift.macho import MachOAnalysis, MachOSlice, Section, Segment
from ipalift.util import report_envelope, sha256_file, write_json_atomic


def _symbol(name: str, value: int, section_index: int = 1) -> dict[str, object]:
    return {
        "name": name,
        "type": 0x0E,
        "type_kind": 0x0E,
        "section_index": section_index,
        "description": 0,
        "value": value,
        "external": False,
    }


def _put_words(data: bytearray, address: int, *values: int) -> None:
    struct.pack_into("<" + "I" * len(values), data, address - 0x1000, *values)


def _put_string(data: bytearray, address: int, value: str) -> None:
    encoded = value.encode("utf-8") + b"\0"
    data[address - 0x1000:address - 0x1000 + len(encoded)] = encoded


def synthetic_macho() -> MachOAnalysis:
    """Three unrelated ABI layouts: root, single inheritance, and VMI."""
    data = bytearray(0x3000)
    # Root class: two virtual slots.
    _put_words(data, 0x1100, 0, 0x1110, 0x2000, 0x2020)
    _put_words(data, 0x1110, 0, 0x1118)
    _put_string(data, 0x1118, "4Base")
    # Single-inheritance class with an override.
    _put_words(data, 0x1140, 0, 0x1150, 0x2040, 0x2060)
    _put_words(data, 0x1150, 0, 0x115C, 0x1110)
    _put_string(data, 0x115C, "7Derived")
    # Multiple-inheritance layout with two exact base descriptors.
    _put_words(data, 0x1180, 0, 0x1190, 0x20A0, 0x20C0)
    _put_words(data, 0x1190, 0, 0x11B0, 0, 2, 0x1110, 0x2, 0x1150, 0x402)
    _put_string(data, 0x11B0, "6Widget")
    # Ghidra pointer cell used by a mechanical vptr assignment.
    _put_words(data, 0x1600, 0x1140)

    symbols = [
        _symbol("__ZTV4Base", 0x1100),
        _symbol("__ZTI4Base", 0x1110),
        _symbol("__ZTS4Base", 0x1118),
        _symbol("__ZTV7Derived", 0x1140),
        _symbol("__ZTI7Derived", 0x1150),
        _symbol("__ZTS7Derived", 0x115C),
        _symbol("__ZTV6Widget", 0x1180),
        _symbol("__ZTI6Widget", 0x1190),
        _symbol("__ZTS6Widget", 0x11B0),
        _symbol("__ZN4BaseD1Ev", 0x2000, 2),
        _symbol("__ZN7DerivedD1Ev", 0x2040, 2),
        _symbol("__ZN7DerivedC1Ev", 0x2080, 2),
        _symbol("__ZN6WidgetD1Ev", 0x20A0, 2),
    ]
    macho_slice = MachOSlice(
        data=bytes(data),
        slice_offset=0,
        slice_size=len(data),
        endian="<",
        bits=32,
        magic_name="MH_MAGIC",
        cpu_type=12,
        cpu_subtype=6,
        file_type=2,
        command_count=0,
        commands_size=0,
        flags=0,
        reserved=None,
        segments=[Segment("__ALL", 0x1000, 0x3000, 0, 0x3000, 7, 5, 0)],
        sections=[
            Section("__const", "__DATA", 0x1100, 0x600, 0x100, 2, 0, 0, 0, 0, 0),
            Section("__text", "__TEXT", 0x2000, 0x1000, 0x1000, 2, 0, 0, 0, 0, 0),
        ],
        symbols_by_index=symbols,
        relocations_by_address={
            0x1110: "__ZTVN10__cxxabiv117__class_type_infoE",
            0x1150: "__ZTVN10__cxxabiv120__si_class_type_infoE",
            0x1190: "__ZTVN10__cxxabiv121__vmi_class_type_infoE",
        },
    )
    return MachOAnalysis("thin", [macho_slice])


def synthetic_fat_macho() -> MachOAnalysis:
    arm6 = synthetic_macho().slices[0]
    arm7 = synthetic_macho().slices[0]
    arm7.cpu_subtype = 9
    return MachOAnalysis("fat", [arm6, arm7])


def _function(address: int, name: str) -> dict[str, object]:
    rendered = f"0x{address:08x}"
    return {
        "id": rendered,
        "address": rendered,
        "name": name,
        "full_name": name,
        "external": False,
        "objective_c_methods": [],
    }


def make_workspace(root: Path) -> Path:
    workspace = root / "workspace"
    (workspace / "analysis").mkdir(parents=True)
    executable = workspace / "evidence" / "extracted" / "Payload" / "Fixture.app" / "Fixture"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"synthetic-mach-o-fixture")
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    application = {
        "archive": {},
        "bundle": {},
        "executable": {
            "archive_path": "Payload/Fixture.app/Fixture",
            "sha256": executable_hash,
            "size": executable.stat().st_size,
        },
        "plugins": {},
        "source": {},
        "tool": {},
    }
    architectures = {
        "container": "thin",
        "architecture_count": 1,
        "architectures": [{"architecture": "arm6", "bits": 32, "endianness": "little"}],
    }
    functions = [
        _function(0x2000, "Base destructor"),
        _function(0x2020, "Base virtual"),
        _function(0x2040, "Derived destructor"),
        _function(0x2060, "Derived virtual"),
        _function(0x2080, "Derived constructor"),
        _function(0x20A0, "Widget destructor"),
        _function(0x20C0, "Widget virtual"),
        _function(0x2100, "Ambiguous caller"),
        _function(0x2120, "Callback caller"),
    ]
    code = {
        "0x00002080": (
            "void Derived_constructor(void *this) {\n"
            "  *(undefined **)this = PTR_vtable_00001600 + 8;\n"
            "  (**(code **)(*(int *)this + 4))(this);\n"
            "}\n"
        ),
        "0x00002100": (
            "void ambiguous(void *value) {\n"
            "  (**(code **)(*(int *)value + 4))(value);\n"
            "}\n"
        ),
        "0x00002120": "void callback(code *fn) { (*fn)(); }\n",
    }
    recovered_functions = []
    for function in functions:
        function_id = str(function["id"])
        item = {
            "function_id": function_id,
            "method_ids": ["objc-method:bridge"] if function_id == "0x00002080" else [],
            "decompilation": {"status": "not_eligible", "output_path": None, "sha256": None},
        }
        if function_id in code:
            relative = f"decompiled/functions/{function_id[2:]}.c"
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(code[function_id], encoding="utf-8", newline="\n")
            item["decompilation"] = {
                "status": "success",
                "output_path": relative,
                "sha256": sha256_file(path),
            }
        recovered_functions.append(item)
    edges = [
        {
            "call_site": "0x00002090",
            "caller_id": "0x00002080",
            "indirect": True,
            "objective_c_dispatch": False,
            "reference_type": "COMPUTED_CALL",
            "resolved_function_target": False,
            "semantic_target_resolved": False,
            "unresolved_reason": "Indirect call target is not statically proven",
        },
        {
            "call_site": "0x00002108",
            "caller_id": "0x00002100",
            "indirect": True,
            "objective_c_dispatch": False,
            "reference_type": "COMPUTED_CALL",
            "resolved_function_target": False,
            "semantic_target_resolved": False,
            "unresolved_reason": "Indirect call target is not statically proven",
        },
        {
            "call_site": "0x00002128",
            "caller_id": "0x00002120",
            "indirect": True,
            "objective_c_dispatch": False,
            "reference_type": "COMPUTED_CALL",
            "resolved_function_target": False,
            "semantic_target_resolved": False,
            "unresolved_reason": "Indirect call target is not statically proven",
        },
    ]
    documents = {
        "application": application,
        "architectures": architectures,
        "functions": {
            "ghidra": {"language_id": "ARM:LE:32:v6"},
            "discovered_function_count": len(functions),
            "functions": functions,
        },
        "callgraph": {"edge_count": len(edges), "edges": edges},
        "recovered-code-index": {
            "function_count": len(functions),
            "functions": recovered_functions,
            "methods": [{"id": "objc-method:bridge", "class_name": "FixtureBridge"}],
        },
        "objc-dispatch": {},
        "objc-type-flow": {},
        "platform-api-map": {},
    }
    for name, facts in documents.items():
        write_json_atomic(workspace / "analysis" / f"{name}.json", report_envelope(name, facts))
    return workspace


class CppModelTests(unittest.TestCase):
    def test_fat_binary_attributes_ghidra_functions_to_the_analyzed_slice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = make_workspace(Path(temporary))
            path = workspace / "analysis" / "architectures.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["facts"].update({
                "container": "fat",
                "architecture_count": 2,
                "architectures": [
                    {"architecture": "arm6", "bits": 32, "endianness": "little"},
                    {"architecture": "arm7", "bits": 32, "endianness": "little"},
                ],
            })
            write_json_atomic(path, document)
            with patch("ipalift.cpp_model.parse_macho_file", return_value=synthetic_fat_macho()):
                result = recover_cpp_model(workspace)
            callsites = result.cpp_model["facts"]["indirect_callsites"]
            self.assertTrue(callsites)
            self.assertTrue(all(item["architecture"] == "arm6" for item in callsites))
            schema = json.loads(
                (Path(__file__).parents[1] / "schemas" / "cpp-object-model.schema.json")
                .read_text(encoding="utf-8")
            )
            Draft202012Validator(schema).validate(result.cpp_model)

    def test_fat_binary_rejects_ambiguous_ghidra_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = make_workspace(Path(temporary))
            architecture_path = workspace / "analysis" / "architectures.json"
            architecture_document = json.loads(architecture_path.read_text(encoding="utf-8"))
            architecture_document["facts"].update({
                "container": "fat",
                "architecture_count": 2,
                "architectures": [
                    {"architecture": "arm6", "bits": 32, "endianness": "little"},
                    {"architecture": "arm7", "bits": 32, "endianness": "little"},
                ],
            })
            write_json_atomic(architecture_path, architecture_document)
            function_path = workspace / "analysis" / "functions.json"
            function_document = json.loads(function_path.read_text(encoding="utf-8"))
            function_document["facts"]["ghidra"]["language_id"] = ""
            write_json_atomic(function_path, function_document)
            with patch("ipalift.cpp_model.parse_macho_file", return_value=synthetic_fat_macho()):
                with self.assertRaisesRegex(CppModelError, "invalid or missing language_id"):
                    recover_cpp_model(workspace)

    def test_generic_abi_recovery_is_complete_conservative_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = make_workspace(Path(temporary))
            preserved = {
                name: sha256_file(workspace / "analysis" / f"{name}.json")
                for name in ("callgraph", "objc-dispatch", "objc-type-flow", "platform-api-map")
            }
            with patch("ipalift.cpp_model.parse_macho_file", return_value=synthetic_macho()):
                first = recover_cpp_model(workspace)
                first_bytes = first.cpp_model_path.read_bytes()
                second = recover_cpp_model(workspace)
            self.assertEqual(first_bytes, second.cpp_model_path.read_bytes())
            facts = second.cpp_model["facts"]
            self.assertEqual(facts["summary"]["class_count"], 3)
            self.assertEqual(facts["summary"]["vtable_count"], 3)
            self.assertTrue(any(item["kind"] == "single_non_virtual" and item["classification"] == "exact" for item in facts["inheritance_relationships"]))
            self.assertEqual(sum(item["kind"] == "virtual_or_multiple" for item in facts["inheritance_relationships"]), 2)
            self.assertTrue(any(item["kind"] == "constructor" and item["abi_variant"] == "C1" and item["classification"] == "exact" for item in facts["special_member_functions"]))
            self.assertTrue(any(item["kind"] == "destructor" and item["classification"] == "exact" for item in facts["special_member_functions"]))
            self.assertTrue(any(item["classification"] == "exact" for item in facts["vtable_assignments"]))
            by_site = {item["call_site"]: item for item in facts["indirect_callsites"]}
            self.assertEqual(by_site["0x00002090"]["classification"], "exact")
            self.assertEqual(by_site["0x00002090"]["possible_target_function_ids"], ["0x00002060"])
            self.assertEqual(by_site["0x00002108"]["classification"], "candidate_set")
            self.assertGreater(len(by_site["0x00002108"]["possible_target_function_ids"]), 1)
            self.assertEqual(by_site["0x00002128"]["classification"], "unresolved")
            self.assertEqual(by_site["0x00002128"]["kind"], "other_indirect")
            derived = next(item for item in facts["classes"] if item["mangled_type_encoding"] == "7Derived")
            self.assertIn("objc-method:bridge", derived["related_objc_method_ids"])
            self.assertIn("FixtureBridge", derived["related_objc_class_names"])
            self.assertTrue(all(
                sha256_file(workspace / "analysis" / f"{name}.json") == digest
                for name, digest in preserved.items()
            ))
            schema = json.loads((Path(__file__).parents[1] / "schemas" / "cpp-object-model.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(second.cpp_model)

    def test_rejects_pseudocode_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = make_workspace(Path(temporary))
            path = workspace / "analysis" / "recovered-code-index.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            successful = next(item for item in document["facts"]["functions"] if item["decompilation"]["status"] == "success")
            successful["decompilation"]["output_path"] = "../outside.c"
            write_json_atomic(path, document)
            with patch("ipalift.cpp_model.parse_macho_file", return_value=synthetic_macho()):
                with self.assertRaisesRegex(CppModelError, "escapes"):
                    recover_cpp_model(workspace)

    def test_unsupported_rtti_layout_remains_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = make_workspace(Path(temporary))
            macho = synthetic_macho()
            macho.slices[0].relocations_by_address[0x1110] = "__ZTV_vendor_extension"
            with patch("ipalift.cpp_model.parse_macho_file", return_value=macho):
                result = recover_cpp_model(workspace)
            base = next(
                item
                for item in result.cpp_model["facts"]["rtti_records"]
                if item["mangled_type_encoding"] == "4Base"
            )
            self.assertEqual(base["classification"], "unresolved")
            self.assertIn("unsupported_rtti_runtime_layout", base["failure_reasons"])

    def test_rejects_missing_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            with self.assertRaisesRegex(CppModelError, "missing analysis/application.json"):
                recover_cpp_model(workspace)

    def test_cli_exposes_recover_cpp_model(self) -> None:
        args = build_parser().parse_args(["recover-cpp-model", "workspace"])
        self.assertEqual(args.command, "recover-cpp-model")


if __name__ == "__main__":
    unittest.main()
