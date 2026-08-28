from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from helpers import create_test_ipa, minimal_macho
from ipalift.ghidra import (
    GhidraError,
    _method_records,
    build_headless_arguments,
    decompile_workspace,
    normalize_ghidra_results,
    prepare_ghidra_evidence,
    validate_ghidra_home,
)
from ipalift.pipeline import analyze_ipa


GHIDRA_REPORTS = ("functions", "callgraph", "strings", "decompilation")


def write_json_line(path: Path, *records: dict) -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
        newline="\n",
    )


class GhidraTests(unittest.TestCase):
    def test_rejects_encrypted_code_before_ghidra_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ipa = create_test_ipa(root / "encrypted.ipa", executable=minimal_macho(crypt_id=1))
            workspace = analyze_ipa(ipa, root / "workspace").paths.output_root
            evidence_path = root / "evidence.json"
            error_pattern = r"encrypted Mach-O code: arm6 \(cryptid=1\).*cryptid is 0"

            with self.assertRaisesRegex(GhidraError, error_pattern):
                prepare_ghidra_evidence(workspace, evidence_path)
            self.assertFalse(evidence_path.exists())

            with patch("ipalift.ghidra.discover_ghidra_home") as discover:
                with self.assertRaisesRegex(GhidraError, error_pattern):
                    decompile_workspace(workspace)
                discover.assert_not_called()
            self.assertFalse((workspace / "decompiled").exists())

    def test_validates_installation_layout_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / "support").mkdir()
            (home / "Ghidra").mkdir()
            launcher = home / "support" / "analyzeHeadless.bat"
            launcher.write_text("@echo off\n", encoding="utf-8")
            (home / "Ghidra" / "application.properties").write_text(
                "application.version=12.1.3\n", encoding="utf-8"
            )
            installation = validate_ghidra_home(home)
            self.assertEqual("12.1.3", installation.version)
            self.assertEqual(launcher.resolve(), installation.launcher)
            arguments = build_headless_arguments(
                installation,
                home / "project",
                home / "fixture",
                home / "evidence.json",
                home / "raw",
                function_timeout=30,
                analysis_timeout=3600,
            )
            self.assertEqual("1", arguments[arguments.index("-max-cpu") + 1])
            self.assertEqual("IPALiftConfigure.java", arguments[arguments.index("-preScript") + 1])
            self.assertEqual("IPALiftHeadless.java", arguments[arguments.index("-postScript") + 1])

            launcher.unlink()
            with self.assertRaisesRegex(GhidraError, "Invalid Ghidra home"):
                validate_ghidra_home(home)

    def test_arm_thumb_method_pointer_is_preserved_and_canonicalized(self) -> None:
        facts = {
            "architectures": [{
                "architecture": "arm6",
                "classes": [{
                    "name": "Fixture",
                    "instance_methods": [{
                        "selector": "run:",
                        "implementation_address": 0x1001,
                        "metadata_address": 0x2000,
                        "type_encoding": "v@:@",
                    }],
                    "class_methods": [],
                }],
                "categories": [],
            }]
        }
        record = _method_records(facts)[0]
        self.assertEqual("0x00001000", record["address"])
        self.assertEqual("0x00001001", record["implementation_pointer"])
        self.assertTrue(record["thumb_entrypoint"])

    def test_normalization_is_deterministic_and_evidence_linked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = analyze_ipa(create_test_ipa(root / "fixture.ipa"), root / "workspace").paths.output_root
            prepared = prepare_ghidra_evidence(workspace, root / "prepared.json")
            self.assertEqual(0, prepared["method_record_count"])
            self.assertEqual(1, len(prepared["frameworks"]))

            raw = root / "raw"
            code = raw / "code"
            code.mkdir(parents=True)
            (code / "00001000.c").write_text(
                "void fixture(void) {\n    return;\n}\n", encoding="utf-8", newline="\n"
            )
            manifest = {
                "completed": True,
                "ghidra_version": "12.1.3",
                "language_id": "ARM:LE:32:v6",
                "compiler_spec_id": "default",
                "executable_format": "Mac OS X Mach-O",
                "image_base": "0x00001000",
                "memory_blocks": [],
                "external_libraries": ["UIKit"],
                "applied_method_group_count": 1,
                "applied_method_record_count": 1,
                "applied_symbol_count": 1,
                "applied_section_count": 1,
                "applied_framework_count": 1,
            }
            (raw / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            caller = {
                "id": "0x00001000",
                "address": "0x00001000",
                "address_space": "ram",
                "name": "fixture",
                "full_name": "Fixture::fixture",
                "namespace": "Fixture",
                "signature": "void fixture(void)",
                "source_type": "USER_DEFINED",
                "external": False,
                "thunk": False,
                "thunk_target_id": None,
                "entrypoint": True,
                "body_start": "0x00001000",
                "body_end": "0x00001003",
                "size": 4,
                "basic_blocks": [{
                    "start": "0x00001000",
                    "end": "0x00001003",
                    "size": 4,
                    "instruction_count": 1,
                    "destinations": [],
                }],
                "cross_references": [
                    {"from_address": "0x00001000", "to_address": "0x00002000"},
                    {"from_address": "0x00001000", "to_address": "0x00003000"},
                    {"from_address": "0x00001000", "to_address": "0x00003010"},
                ],
            }
            objc_id = "external:<EXTERNAL>::_objc_msgSend@EXTERNAL:00000001"
            puts_id = "external:<EXTERNAL>::_puts@EXTERNAL:00000002"
            external_base = {
                "address": None,
                "address_space": "EXTERNAL",
                "namespace": "<EXTERNAL>",
                "signature": "undefined external(void)",
                "source_type": "IMPORTED",
                "external": True,
                "thunk": False,
                "thunk_target_id": None,
                "entrypoint": False,
                "body_start": None,
                "body_end": None,
                "size": 0,
                "basic_blocks": [],
                "cross_references": [],
            }
            write_json_line(
                raw / "functions.jsonl",
                caller,
                {**external_base, "id": objc_id, "name": "_objc_msgSend", "full_name": "<EXTERNAL>::_objc_msgSend"},
                {**external_base, "id": puts_id, "name": "_puts", "full_name": "<EXTERNAL>::_puts"},
            )
            write_json_line(
                raw / "calls.jsonl",
                {
                    "caller_id": caller["id"],
                    "call_site": "0x00001000",
                    "target_address": None,
                    "target_function_id": objc_id,
                    "target_name": "objc_msgSend_stub",
                    "thunk_target_name": "_objc_msgSend",
                    "reference_type": "UNCONDITIONAL_CALL",
                    "indirect": False,
                },
            )
            write_json_line(
                raw / "strings.jsonl",
                {
                    "address": "0x00003000",
                    "value": "image.png",
                    "length": 10,
                    "data_type": "string",
                    "references": [{
                        "from_address": "0x00001000",
                        "from_function_id": caller["id"],
                        "reference_type": "DATA",
                    }],
                },
                {
                    "address": "0x00003010",
                    "value": "run:",
                    "length": 5,
                    "data_type": "string",
                    "references": [],
                },
            )
            write_json_line(
                raw / "decompilation.jsonl",
                {
                    "function_id": caller["id"],
                    "address": caller["address"],
                    "status": "success",
                    "message": None,
                    "raw_output_file": "00001000.c",
                },
            )
            method = {
                "address": "0x00001000",
                "implementation_pointer": "0x00001001",
                "thumb_entrypoint": True,
                "architecture": "arm6",
                "class_name": "Fixture",
                "category_name": None,
                "selector": "run:",
                "kind": "instance",
                "exact_name": "-[Fixture run:]",
                "type_encoding": "v@:@",
                "metadata_address": "0x00004000",
            }
            evidence = {
                "methods": [{
                    "address": method["address"],
                    "namespace": "Fixture",
                    "internal_name": "objc_i_Fixture_run_00001000",
                    "exact_names": [method["exact_name"]],
                    "records": [method],
                }],
                "method_record_count": 1,
                "symbols": [{"address": "0x00001000", "name": "_fixture", "architecture": "arm6"}],
                "imports": [
                    {"name": "_objc_msgSend", "architecture": "arm6"},
                    {"name": "_puts", "architecture": "arm6"},
                    {"name": "_global_data", "architecture": "arm6"},
                ],
                "frameworks": [{"name": "UIKit"}],
                "sections": [{"address": "0x00001000", "size": 4, "segment": "__TEXT", "name": "__text"}],
                "classes": [{"name": "Fixture", "address": "0x00002000", "metaclass_address": None}],
                "selectors": ["run:"],
                "assets": [{
                    "path": "Payload/Fixture.app/image.png",
                    "bundle_relative_path": "image.png",
                    "sha256": "fixture",
                    "asset_category": "image",
                }],
            }

            first = normalize_ghidra_results(workspace, raw, evidence)
            first_bytes = {
                name: (workspace / "analysis" / f"{name}.json").read_bytes()
                for name in GHIDRA_REPORTS
            }
            second = normalize_ghidra_results(workspace, raw, evidence)
            for name in GHIDRA_REPORTS:
                self.assertEqual(first_bytes[name], (workspace / "analysis" / f"{name}.json").read_bytes())

            functions = second.reports["functions"]["facts"]
            internal = next(item for item in functions["functions"] if item["id"] == caller["id"])
            imported = next(item for item in functions["functions"] if item["id"] == puts_id)
            self.assertEqual("-[Fixture run:]", internal["objective_c_methods"][0]["exact_name"])
            self.assertEqual(["_fixture"], internal["macho_exports"])
            self.assertEqual(["Fixture"], internal["referenced_classes"])
            self.assertEqual(["run:"], internal["referenced_selectors"])
            self.assertEqual("Payload/Fixture.app/image.png", internal["referenced_assets"][0]["path"])
            self.assertEqual("_puts", imported["macho_imports"][0]["name"])
            self.assertEqual(1, functions["macho_import_unmatched_count"])
            edge = second.reports["callgraph"]["facts"]["edges"][0]
            self.assertTrue(edge["objective_c_dispatch"])
            self.assertFalse(edge["semantic_target_resolved"])
            self.assertIn("Objective-C", edge["unresolved_reason"])
            self.assertTrue((workspace / "decompiled" / "functions" / "00001000.c").is_file())
            self.assertTrue(first.report_path.is_file())

            schema_root = Path(__file__).parents[1] / "schemas"
            registry = Registry()
            for schema_path in schema_root.glob("*.schema.json"):
                contents = json.loads(schema_path.read_text(encoding="utf-8"))
                registry = registry.with_resource(contents["$id"], Resource.from_contents(contents))
            for name in GHIDRA_REPORTS:
                schema = json.loads((schema_root / f"{name}.schema.json").read_text(encoding="utf-8"))
                Draft202012Validator(schema, registry=registry).validate(second.reports[name])


if __name__ == "__main__":
    unittest.main()
