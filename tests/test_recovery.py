from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ipalift.recovery import RecoveryError, recover_objc_workspace
from ipalift.util import report_envelope, write_json_atomic


def objc_method(
    address: str,
    exact_name: str,
    selector: str,
    *,
    kind: str = "instance",
    class_name: str = "Widget",
    category_name: str | None = None,
    pointer: str | None = None,
) -> dict:
    return {
        "address": address,
        "implementation_pointer": pointer or address,
        "thumb_entrypoint": bool(pointer and int(pointer, 16) & 1),
        "architecture": "arm6",
        "class_name": class_name,
        "category_name": category_name,
        "selector": selector,
        "kind": kind,
        "exact_name": exact_name,
        "type_encoding": "v12@0:4@8" if ":" in selector else "v8@0:4",
        "metadata_address": "0x00004000",
    }


def function(
    function_id: str,
    *,
    methods: list[dict] | None = None,
    external: bool = False,
    thunk: bool = False,
    callers: list[str] | None = None,
    callees: list[str] | None = None,
) -> dict:
    address = None if external else function_id
    name = "external" if external else f"FUN_{function_id[2:]}"
    return {
        "id": function_id,
        "address": address,
        "name": name,
        "full_name": name,
        "namespace": "<EXTERNAL>" if external else "Global",
        "signature": f"void {name}(void)",
        "external": external,
        "thunk": thunk,
        "entrypoint": False,
        "objective_c_methods": methods or [],
        "callers": callers or [],
        "callees": callees or [],
        "referenced_string_addresses": ["0x00003000"] if methods else [],
        "referenced_selectors": ["render:"] if methods else [],
        "referenced_classes": ["Widget"] if methods else [],
        "referenced_assets": ([{
            "path": "Payload/Fixture.app/image.png",
            "bundle_relative_path": "image.png",
            "sha256": "asset-sha",
            "asset_category": "image",
        }] if methods else []),
        "macho_imports": [],
        "macho_exports": ["_native"] if function_id == "0x00001300" else [],
        "provenance": ["ghidra", *( ["objective_c_metadata"] if methods else [])],
        "confidence": "high" if methods else "medium",
        "confidence_basis": ["fixture evidence"],
    }


def build_workspace(root: Path) -> Path:
    workspace = root / "workspace"
    analysis = workspace / "analysis"
    code = workspace / "decompiled" / "functions"
    analysis.mkdir(parents=True)
    code.mkdir(parents=True)

    instance = objc_method(
        "0x00001000", "-[Widget render:]", "render:", pointer="0x00001001"
    )
    class_method = objc_method(
        "0x00001100", "+[Widget sharedWidget]", "sharedWidget", kind="class"
    )
    category_method = objc_method(
        "0x00001200",
        "-[Widget(Extras) extraAction]",
        "extraAction",
        class_name="Widget",
        category_name="Extras",
    )
    functions = [
        function("0x00001000", methods=[instance], callees=["0x00001300"]),
        function("0x00001100", methods=[class_method]),
        function("0x00001200", methods=[category_method]),
        function("0x00001300", callers=["0x00001000"]),
        function("0x00001400", thunk=True),
        function("external:<EXTERNAL>::_puts@EXTERNAL:00000001", external=True),
    ]
    write_json_atomic(
        analysis / "functions.json",
        report_envelope("functions", {"discovered_function_count": len(functions), "functions": functions}),
    )

    class_record = {
        "name": "Widget",
        "address": 0x2000,
        "metaclass_address": 0x2100,
        "superclass": {"name": "NSObject", "address": None, "source": "external_relocation"},
        "protocols": [{"name": "Renderable"}],
        "ivars": [{
            "name": "image", "offset": 4, "size": 4, "type_encoding": '@"UIImage"',
            "alignment_log2": 2, "metadata_address": 0x2200,
        }],
        "properties": [{"name": "image", "attributes": 'T@"UIImage",&,Vimage', "metadata_address": 0x2210}],
        "flags": 0,
        "instance_start": 4,
        "instance_size": 8,
        "instance_methods": [
            {
                "implementation_address": 0x1001,
                "metadata_address": 0x4000,
                "selector": "render:",
                "kind": "instance",
                "type_encoding": "v12@0:4@8",
            },
            {
                "implementation_address": 0x1500,
                "metadata_address": 0x4010,
                "selector": "missingMethod",
                "kind": "instance",
                "type_encoding": "v8@0:4",
            },
        ],
        "class_methods": [{
            "implementation_address": 0x1100,
            "metadata_address": 0x4020,
            "selector": "sharedWidget",
            "kind": "class",
            "type_encoding": "v8@0:4",
        }],
    }
    collision_class = lambda name, address: {
        "name": name,
        "address": address,
        "metaclass_address": address + 4,
        "superclass": None,
        "protocols": [],
        "ivars": [],
        "properties": [],
        "flags": 0,
        "instance_start": 0,
        "instance_size": 0,
        "instance_methods": [],
        "class_methods": [],
    }
    category = {
        "name": "Extras",
        "address": 0x2300,
        "target_class": {"name": "Widget", "address": 0x2000, "source": "class_pointer"},
        "protocols": [],
        "properties": [],
        "instance_methods": [{
            "implementation_address": 0x1200,
            "metadata_address": 0x4030,
            "selector": "extraAction",
            "kind": "instance",
            "type_encoding": "v8@0:4",
        }],
        "class_methods": [],
    }
    protocol = lambda address: {
        "name": "Renderable",
        "address": address,
        "inherited_protocols": ["NSObject"],
        "inherited_protocol_addresses": [],
        "properties": [{"name": "ready", "attributes": "TB,R"}],
        "methods": [{
            "kind": "instance",
            "required": True,
            "selector": "render:",
            "type_encoding": "v12@0:4@8",
        }],
    }
    classes_facts = {
        "architectures": [{
            "architecture": "arm6",
            "classes": [class_record, collision_class("A/B", 0x2400), collision_class("A:B", 0x2500)],
            "categories": [category],
            "protocols": [protocol(0x2600), protocol(0x2700)],
        }]
    }
    write_json_atomic(analysis / "classes.json", report_envelope("classes", classes_facts))
    write_json_atomic(
        analysis / "strings.json",
        report_envelope("strings", {
            "strings": [{
                "address": "0x00003000",
                "value": "image.png",
                "data_type": "string",
                "is_selector": False,
                "asset_matches": [{
                    "path": "Payload/Fixture.app/image.png",
                    "bundle_relative_path": "image.png",
                    "sha256": "asset-sha",
                    "asset_category": "image",
                }],
            }]
        }),
    )
    write_json_atomic(
        analysis / "decompilation.json",
        report_envelope("decompilation", {"functions": [
            {
                "function_id": "0x00001000", "address": "0x00001000", "status": "success",
                "output_path": "decompiled/functions/00001000.c",
            },
            {
                "function_id": "0x00001100", "address": "0x00001100", "status": "failure",
                "message": "fixture decompiler failure", "output_path": None,
            },
            {
                "function_id": "0x00001200", "address": "0x00001200", "status": "success",
                "output_path": "decompiled/functions/00001200.c",
            },
            {
                "function_id": "0x00001300", "address": "0x00001300", "status": "timeout",
                "message": "fixture timeout", "output_path": None,
            },
        ]}),
    )
    (code / "00001000.c").write_text("void recovered_widget(void) { return; }\n", encoding="utf-8", newline="\n")
    (code / "00001200.c").write_text("void recovered_category(void) { return; }\n", encoding="utf-8", newline="\n")
    return workspace


class RecoveryTests(unittest.TestCase):
    def test_recovery_is_complete_collision_safe_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_workspace(Path(temporary))
            first = recover_objc_workspace(workspace)
            facts = first.index["facts"]
            self.assertEqual(6, facts["function_count"])
            self.assertEqual({
                "objective_c_method": 3,
                "native_internal_function": 1,
                "thunk": 1,
                "external_function": 1,
            }, facts["classification_counts"])
            self.assertEqual(4, facts["objective_c_method_count"])
            self.assertEqual(3, facts["mapped_objective_c_method_count"])
            self.assertEqual(1, facts["unresolved_objective_c_method_count"])
            self.assertEqual({"failure": 1, "success": 2, "unresolved": 1}, facts["method_decompilation_status_counts"])
            self.assertEqual(3, facts["class_count"])
            self.assertEqual(1, facts["category_count"])
            self.assertEqual(1, facts["protocol_count"])
            self.assertEqual(2, facts["protocol_metadata_record_count"])
            self.assertEqual(11, facts["generated_file_count"])
            self.assertEqual(11, len(first.generated_files))
            self.assertTrue(all((workspace / path).is_file() for path in first.generated_files))

            methods = facts["methods"]
            self.assertEqual(4, len({item["id"] for item in methods}))
            thumb = next(item for item in methods if item["selector"] == "render:")
            self.assertEqual("0x00001001", thumb["implementation_pointer"])
            self.assertEqual("0x00001000", thumb["canonical_address"])
            self.assertTrue(thumb["thumb_entrypoint"])
            self.assertEqual(["0x00001300"], thumb["callees"])
            self.assertEqual("image.png", thumb["referenced_strings"][0]["value"])
            self.assertEqual("Payload/Fixture.app/image.png", thumb["referenced_assets"][0]["path"])
            missing = next(item for item in methods if item["selector"] == "missingMethod")
            self.assertEqual("unresolved", missing["mapping_status"])
            self.assertIsNone(missing["function_id"])

            class_paths = [item["header_path"] for item in facts["classes"]]
            self.assertEqual(len(class_paths), len({path.casefold() for path in class_paths}))
            collision_paths = [path for path in class_paths if Path(path).stem.startswith("A_B")]
            self.assertEqual(2, len(collision_paths))
            self.assertNotEqual(collision_paths[0].casefold(), collision_paths[1].casefold())

            widget = next(item for item in facts["classes"] if item["name"] == "Widget")
            widget_header = (workspace / widget["header_path"]).read_text(encoding="utf-8")
            widget_source = (workspace / widget["source_path"]).read_text(encoding="utf-8")
            self.assertIn("@interface Widget : NSObject <Renderable>", widget_header)
            self.assertIn("NOT ORIGINAL SOURCE", widget_header)
            self.assertIn("Original implementation pointer: 0x00001001", widget_source)
            self.assertIn("fixture decompiler failure", widget_source)
            self.assertIn("No pseudocode body is available", widget_source)
            category = facts["categories"][0]
            self.assertIn(
                "-[Widget(Extras) extraAction]",
                (workspace / category["source_path"]).read_text(encoding="utf-8"),
            )
            protocol = facts["protocols"][0]
            self.assertEqual(2, protocol["metadata_record_count"])
            self.assertEqual(2, protocol["declarations"][0]["occurrence_count"])
            self.assertIn(
                "metadata occurrences: 2",
                (workspace / protocol["source_path"]).read_text(encoding="utf-8"),
            )
            native = (workspace / "recovered" / "native-functions.md").read_text(encoding="utf-8")
            self.assertIn("0x00001300", native)
            self.assertNotIn("0x00001400", native)

            all_sources = "\n".join(
                (workspace / entity["source_path"]).read_text(encoding="utf-8")
                for entity in [*facts["classes"], *facts["categories"]]
            )
            for method in methods:
                self.assertEqual(1, all_sources.count(f"IPALIFT METHOD {method['id']}"))

            tracked = [
                "analysis/recovered-code-index.json",
                "reports/objc-recovery-report.md",
                *first.generated_files,
            ]
            first_bytes = {path: (workspace / path).read_bytes() for path in tracked}
            second = recover_objc_workspace(workspace)
            self.assertEqual(first.generated_files, second.generated_files)
            for path, content in first_bytes.items():
                self.assertEqual(content, (workspace / path).read_bytes(), path)

            schema_root = Path(__file__).parents[1] / "schemas"
            registry = Registry()
            for schema_path in schema_root.glob("*.schema.json"):
                contents = json.loads(schema_path.read_text(encoding="utf-8"))
                registry = registry.with_resource(contents["$id"], Resource.from_contents(contents))
            schema = json.loads(
                (schema_root / "recovered-code-index.schema.json").read_text(encoding="utf-8")
            )
            Draft202012Validator(schema, registry=registry).validate(second.index)

            prior = json.loads((workspace / "analysis/recovered-code-index.json").read_text(encoding="utf-8"))
            stale = "recovered/objc/classes/obsolete.h"
            prior["facts"]["generated_files"].append(stale)
            write_json_atomic(workspace / "analysis/recovered-code-index.json", prior)
            (workspace / stale).write_text("obsolete", encoding="utf-8")
            recover_objc_workspace(workspace)
            self.assertFalse((workspace / stale).exists())

    def test_rejects_missing_workspace_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RecoveryError, "missing analysis/classes.json"):
                recover_objc_workspace(Path(temporary))

    def test_rejects_decompilation_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_workspace(Path(temporary))
            path = workspace / "analysis" / "decompilation.json"
            report = json.loads(path.read_text(encoding="utf-8"))
            report["facts"]["functions"][0]["output_path"] = "../outside.c"
            write_json_atomic(path, report)
            with self.assertRaisesRegex(RecoveryError, "escapes the analysis workspace"):
                recover_objc_workspace(workspace)


if __name__ == "__main__":
    unittest.main()
