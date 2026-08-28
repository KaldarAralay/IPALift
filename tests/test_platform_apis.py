from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ipalift.cli import build_parser
from ipalift.dispatch import resolve_objc_dispatch
from ipalift.platform_apis import PlatformAPIMapError, map_platform_apis
from ipalift.typeflow import infer_objc_types
from ipalift.util import report_envelope, write_json_atomic
from tests.test_dispatch import direct_edge, method, raw_function, recovered_function, selector_reference
from tests.test_typeflow import build_typeflow_workspace


def build_platform_workspace(root: Path) -> Path:
    workspace = build_typeflow_workspace(root)
    analysis = workspace / "analysis"

    load_commands = [
        {"index": 1, "command": "LC_LOAD_DYLIB", "kind": "framework", "name": "UIKit", "path": "/System/Library/Frameworks/UIKit.framework/UIKit"},
        {"index": 2, "command": "LC_LOAD_DYLIB", "kind": "framework", "name": "Foundation", "path": "/System/Library/Frameworks/Foundation.framework/Foundation"},
        {"index": 3, "command": "LC_LOAD_DYLIB", "kind": "dylib", "name": "libSystem.B", "path": "/usr/lib/libSystem.B.dylib"},
    ]
    imports = [
        {"name": "_UIApplicationMain", "library_ordinal": 1, "weak_reference": False},
        {"name": "_OBJC_CLASS_$_UIView", "library_ordinal": 1, "weak_reference": False},
        {"name": "_OBJC_CLASS_$_NSObject", "library_ordinal": 2, "weak_reference": False},
        {"name": "_mystery", "library_ordinal": 0, "weak_reference": False},
    ]
    write_json_atomic(
        analysis / "architectures.json",
        report_envelope(
            "architectures",
            {
                "architecture_count": 1,
                "architectures": [{
                    "architecture": "arm6",
                    "load_commands": load_commands,
                    "imports": imports,
                }],
            },
        ),
    )
    linked_libraries = [
        {
            "architectures": ["arm6"],
            "command": item["command"],
            "compatibility_version": "1.0.0",
            "current_version": "1.0.0",
            "kind": item["kind"],
            "name": item["name"],
            "path": item["path"],
            "timestamp": 2,
        }
        for item in load_commands
    ]
    write_json_atomic(
        analysis / "frameworks.json",
        report_envelope(
            "frameworks",
            {
                "linked_library_count": len(linked_libraries),
                "linked_libraries": linked_libraries,
            },
        ),
    )

    functions_path = analysis / "functions.json"
    functions = json.loads(functions_path.read_text(encoding="utf-8"))
    raw_functions = functions["facts"]["functions"]
    function_by_id = {item["id"]: item for item in raw_functions}
    function_by_id["0x00001000"]["cross_references"].append({
        "from_address": "0x00001040",
        "to_address": "0x00008000",
        "reference_type": "PARAM",
        "target_symbol": "_OBJC_CLASS_$_UIView",
    })
    external_main = raw_function("0x00009000")
    external_main.update({
        "external": True,
        "name": "_UIApplicationMain",
        "full_name": "<EXTERNAL>::_UIApplicationMain",
        "macho_imports": [{"architecture": "arm6", "name": "_UIApplicationMain"}],
    })
    external_mystery = raw_function("0x00009004")
    external_mystery.update({
        "external": True,
        "name": "_mystery",
        "full_name": "<EXTERNAL>::_mystery",
        "macho_imports": [{"architecture": "arm6", "name": "_mystery"}],
    })
    class_message_function = raw_function(
        "0x00001600",
        references=[selector_reference("0x0000160c", "0x0000300c")],
    )
    draw_method = method("method:draw", "0x00001700", "Widget", "drawRect:")
    launch_method = method(
        "method:launch",
        "0x00001800",
        "Widget",
        "applicationDidFinishLaunching:",
    )
    for index, item in enumerate((draw_method, launch_method), start=20):
        item.update({
            "metadata_address": f"0x{0x5000 + index * 4:08x}",
            "entity_id": "class:Widget",
            "type_encoding": "v8@0:4",
            "confidence": "high",
            "provenance": ["ghidra", "objective_c_metadata"],
        })
    raw_functions.extend([
        class_message_function,
        raw_function("0x00001700", methods=[draw_method]),
        raw_function("0x00001800", methods=[launch_method]),
        external_main,
        external_mystery,
    ])
    functions["facts"]["discovered_function_count"] = len(raw_functions)
    write_json_atomic(functions_path, functions)

    callgraph_path = analysis / "callgraph.json"
    callgraph = json.loads(callgraph_path.read_text(encoding="utf-8"))
    edges = callgraph["facts"]["edges"]
    edges.append(direct_edge("0x00001600", "0x00001610"))
    for call_site, symbol, target_id in (
        ("0x00001050", "_UIApplicationMain", "0x00009000"),
        ("0x00001054", "_mystery", "0x00009004"),
    ):
        edges.append({
            "caller_id": "0x00001000",
            "call_site": call_site,
            "target_address": target_id,
            "target_function_id": target_id,
            "target_name": symbol,
            "thunk_target_name": f"<EXTERNAL>::{symbol}",
            "reference_type": "UNCONDITIONAL_CALL",
            "indirect": False,
            "objective_c_dispatch": False,
            "resolved_function_target": True,
            "semantic_target_resolved": True,
            "unresolved_reason": None,
        })
    callgraph["facts"]["edge_count"] = len(edges)
    write_json_atomic(callgraph_path, callgraph)

    recovered_path = analysis / "recovered-code-index.json"
    recovered = json.loads(recovered_path.read_text(encoding="utf-8"))
    recovered["facts"]["methods"].extend([draw_method, launch_method])
    recovered["facts"]["objective_c_method_count"] = len(recovered["facts"]["methods"])
    widget = next(item for item in recovered["facts"]["classes"] if item["name"] == "Widget")
    widget["superclass"] = {"name": "UIView", "source": "external_relocation"}
    widget["protocols"] = ["UIApplicationDelegate"]
    widget.setdefault("method_ids", []).extend([draw_method["id"], launch_method["id"]])
    recovered["facts"]["functions"].extend([
        recovered_function("0x00001600", [], "decompiled/functions/00001600.c"),
        recovered_function("0x00001700", [draw_method["id"]], None),
        recovered_function("0x00001800", [launch_method["id"]], None),
        recovered_function("0x00009000", [], None),
        recovered_function("0x00009004", [], None),
    ])
    recovered["facts"]["function_count"] = len(recovered["facts"]["functions"])
    write_json_atomic(recovered_path, recovered)

    code = workspace / "decompiled" / "functions"
    (code / "00001600.c").write_text(
        'void classMessage(void) { _objc_msgSend(&objc::class_t::UIView,"render"); }\n',
        encoding="utf-8",
        newline="\n",
    )

    resolve_objc_dispatch(workspace)
    infer_objc_types(workspace)

    dispatch = json.loads((analysis / "objc-dispatch.json").read_text(encoding="utf-8"))
    callsite_by_address = {
        item["call_site"]: item for item in dispatch["facts"]["callsites"]
    }
    typeflow_path = analysis / "objc-type-flow.json"
    typeflow = json.loads(typeflow_path.read_text(encoding="utf-8"))
    refinements = typeflow["facts"]["dispatch_refinements"]
    refinements_by_id = {item["callsite_id"]: item for item in refinements}
    for address, candidates in (
        ("0x00001210", ["NSObject", "UIView"]),
        ("0x00001310", ["UIView"]),
    ):
        callsite = callsite_by_address[address]
        refinements_by_id[callsite["id"]] = {
            "callsite_id": callsite["id"],
            "call_site": address,
            "caller_function_id": callsite["caller"]["function_id"],
            "receiver_value_id": f"type-value:fixture-{address[2:]}",
            "baseline_receiver_status": callsite["receiver"]["status"],
            "baseline_receiver_kind": callsite["receiver"]["receiver_kind"],
            "baseline_class_candidates": callsite["receiver"]["class_candidates"],
            "receiver_kind": "typed_instance",
            "classification": "candidate_set",
            "class_candidates": candidates,
            "confidence": "medium",
            "evidence_ids": [],
            "propagation_step_ids": [],
            "failure_reasons": ["type_flow_does_not_prove_one_exact_runtime_class"],
            "changed": True,
        }
    typeflow["facts"]["dispatch_refinements"] = sorted(
        refinements_by_id.values(), key=lambda item: (item["call_site"], item["callsite_id"])
    )
    typeflow["facts"]["dispatch_refinement_count"] = len(
        typeflow["facts"]["dispatch_refinements"]
    )
    write_json_atomic(typeflow_path, typeflow)
    return workspace


class PlatformAPITests(unittest.TestCase):
    def test_complete_conservative_deterministic_map(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_platform_workspace(Path(temporary))
            preserved_paths = [
                workspace / "analysis" / name
                for name in ("callgraph.json", "objc-dispatch.json", "objc-type-flow.json")
            ]
            preserved = {path: path.read_bytes() for path in preserved_paths}

            first = map_platform_apis(workspace)
            facts = first.platform_map["facts"]
            self.assertEqual(
                facts["summary"]["dependency_count"],
                sum(facts["summary"]["classification_counts"].values()),
            )

            imported = {item["name"]: item for item in facts["imported_symbols"]}
            self.assertEqual("exact", imported["_UIApplicationMain"]["classification"])
            self.assertEqual(["0x00001050"], imported["_UIApplicationMain"]["direct_call_sites"])
            self.assertEqual("unresolved", imported["_mystery"]["classification"])
            self.assertIn(
                "macho_library_ordinal_does_not_name_a_loaded_library",
                imported["_mystery"]["failure_reasons"],
            )

            class_reference = next(
                item for item in facts["external_class_references"]
                if item["class_names"] == ["UIView"]
            )
            self.assertEqual("exact", class_reference["classification"])
            self.assertEqual(["0x00001040"], class_reference["source_addresses"])

            messages = {item["call_site"]: item for item in facts["message_callsites"]}
            self.assertEqual("external_exact", messages["0x00001610"]["platform_status"])
            self.assertEqual(["UIView"], messages["0x00001610"]["external_class_candidates"])
            self.assertEqual("external_exact", messages["0x00001110"]["platform_status"])
            self.assertEqual("super", messages["0x00001110"]["receiver_kind"])
            self.assertEqual("UIView", messages["0x00001110"]["super_lookup_start"])
            self.assertEqual("external_candidate", messages["0x00001310"]["platform_status"])
            self.assertIn(
                "instance_receiver_allows_dynamic_subclasses",
                messages["0x00001310"]["failure_reasons"],
            )
            self.assertEqual("external_candidate", messages["0x00001210"]["platform_status"])
            self.assertEqual(
                ["NSObject", "UIView"],
                messages["0x00001210"]["external_class_candidates"],
            )
            self.assertEqual(
                {"Foundation", "UIKit"},
                set(messages["0x00001210"]["frameworks"]),
            )

            callbacks = facts["callback_dependencies"]
            self.assertTrue(any(
                item["kind"] == "superclass_override"
                and item["selector"] == "drawRect:"
                and item["class_names"] == ["UIView"]
                for item in callbacks
            ))
            self.assertTrue(any(
                item["kind"] == "protocol_callback"
                and item["protocol_name"] == "UIApplicationDelegate"
                and item["selector"] == "applicationDidFinishLaunching:"
                for item in callbacks
            ))
            self.assertFalse(facts["evidence_boundary"]["gameplay_semantics_inferred"])
            self.assertTrue(facts["indexes"]["frameworks"])
            self.assertTrue(facts["indexes"]["categories"])

            first_bytes = first.platform_map_path.read_bytes()
            second = map_platform_apis(workspace)
            self.assertEqual(first_bytes, second.platform_map_path.read_bytes())
            self.assertEqual(first.platform_map, second.platform_map)
            for path, contents in preserved.items():
                self.assertEqual(contents, path.read_bytes(), path)

            schema_root = Path(__file__).parents[1] / "schemas"
            registry = Registry()
            for schema_path in schema_root.glob("*.schema.json"):
                contents = json.loads(schema_path.read_text(encoding="utf-8"))
                resource = Resource.from_contents(contents)
                registry = registry.with_resource(contents["$id"], resource)
                registry = registry.with_resource(schema_path.name, resource)
            schema = json.loads(
                (schema_root / "platform-api-map.schema.json").read_text(encoding="utf-8")
            )
            Draft202012Validator(schema, registry=registry).validate(second.platform_map)

    def test_cli_exposes_map_platform_apis(self) -> None:
        args = build_parser().parse_args(["map-platform-apis", "workspace"])
        self.assertEqual("map-platform-apis", args.command)
        self.assertEqual(Path("workspace"), args.workspace)

    def test_rejects_pseudocode_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_platform_workspace(Path(temporary))
            path = workspace / "analysis" / "recovered-code-index.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["facts"]["functions"][0]["decompilation"]["output_path"] = "../outside.c"
            write_json_atomic(path, document)
            with self.assertRaisesRegex(
                PlatformAPIMapError, "escapes the analysis workspace"
            ):
                map_platform_apis(workspace)

    def test_rejects_missing_workspace_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                PlatformAPIMapError,
                "missing analysis/architectures.json",
            ):
                map_platform_apis(Path(temporary))


if __name__ == "__main__":
    unittest.main()
