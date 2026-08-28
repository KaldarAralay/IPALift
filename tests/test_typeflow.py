from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ipalift.cli import build_parser
from ipalift.dispatch import resolve_objc_dispatch
from ipalift.typeflow import TypeFlowError, _local_declarations, infer_objc_types
from ipalift.util import write_json_atomic
from tests.test_dispatch import build_dispatch_workspace, direct_edge, selector_reference


def build_typeflow_workspace(root: Path) -> Path:
    workspace = build_dispatch_workspace(root)
    analysis = workspace / "analysis"

    recovered_path = analysis / "recovered-code-index.json"
    recovered = json.loads(recovered_path.read_text(encoding="utf-8"))
    methods = recovered["facts"]["methods"]
    for index, item in enumerate(methods):
        item["metadata_address"] = f"0x{0x5000 + index * 4:08x}"
        item["entity_id"] = f"entity:{item['class_name']}"
        item["type_encoding"] = "v8@0:4"
    method_by_id = {item["id"]: item for item in methods}
    method_by_id["method:factory"].update({
        "selector": "alloc",
        "exact_name": "+[Widget alloc]",
        "type_encoding": '@"Widget"8@0:4',
    })
    method_by_id["method:widget-render"]["type_encoding"] = "v12@0:4i8"
    method_by_id["method:other-render"]["type_encoding"] = "v12@0:4i8"
    for class_index, objc_class in enumerate(recovered["facts"]["classes"]):
        objc_class["id"] = f"class:{objc_class['name']}"
        objc_class["protocols"] = []
        objc_class["ivars"] = []
        objc_class["properties"] = []
        if objc_class["name"] == "Widget":
            objc_class["ivars"] = [{
                "name": "mOther",
                "type_encoding": '@"Other"',
                "metadata_address": "0x00006000",
                "offset": 8,
            }]
            objc_class["properties"] = [{
                "name": "other",
                "attributes": 'T@"Other",&,N,V_mOther',
                "metadata_address": "0x00006004",
            }]
    recovered["facts"]["categories"] = []
    write_json_atomic(recovered_path, recovered)

    functions_path = analysis / "functions.json"
    functions = json.loads(functions_path.read_text(encoding="utf-8"))
    function_by_id = {
        item["id"]: item for item in functions["facts"]["functions"]
    }
    function_by_id["0x00001000"]["cross_references"].append(
        selector_reference("0x0000101c", "0x00003014")
    )
    function_by_id["0x00001000"]["cross_references"].append(
        selector_reference("0x0000102c", "0x00003018")
    )
    function_by_id["0x00001300"]["cross_references"] = [
        {
            "from_address": "0x00001308",
            "to_address": "0x00006000",
            "reference_type": "DATA",
            "target_symbol": "Widget::mOther",
        },
        selector_reference("0x0000130c", "0x0000300c"),
    ]
    write_json_atomic(functions_path, functions)

    strings_path = analysis / "strings.json"
    strings = json.loads(strings_path.read_text(encoding="utf-8"))
    for item in strings["facts"]["strings"]:
        if item["address"] == "0x00003000":
            item["value"] = "alloc"
        elif item["address"] == "0x0000300c":
            item["value"] = "render"
    strings["facts"]["strings"].append({
        "address": "0x00003014",
        "value": "init",
        "is_selector": True,
    })
    strings["facts"]["strings"].append({
        "address": "0x00003018",
        "value": "new",
        "is_selector": True,
    })
    write_json_atomic(strings_path, strings)

    callgraph_path = analysis / "callgraph.json"
    callgraph = json.loads(callgraph_path.read_text(encoding="utf-8"))
    callgraph["facts"]["edges"].append(
        direct_edge("0x00001000", "0x00001020")
    )
    callgraph["facts"]["edges"].append(
        direct_edge("0x00001000", "0x00001030")
    )
    callgraph["facts"]["edge_count"] = len(callgraph["facts"]["edges"])
    write_json_atomic(callgraph_path, callgraph)

    code = workspace / "decompiled" / "functions"
    (code / "00001000.c").write_text(
        "/* Ghidra decompiler output, not original source. */\n"
        "Widget * allocate(void) {\n"
        "  ID local_8;\n"
        "  ID local_c;\n"
        "  ID local_10;\n"
        "  local_8 = _objc_msgSend(&objc::class_t::Widget,\"alloc\");\n"
        "  local_c = _objc_msgSend(local_8,\"init\");\n"
        "  local_10 = _objc_msgSend(&objc::class_t::Widget,\"new\");\n"
        "  return local_c;\n"
        "}\n",
        encoding="utf-8",
        newline="\n",
    )
    (code / "00001200.c").write_text(
        "void ambiguous(ID receiver) {\n"
        "  Widget * widget;\n"
        "  Other * other;\n"
        "  ID mixed;\n"
        "  undefined4 cycle_a;\n"
        "  undefined4 cycle_b;\n"
        "  mixed = widget;\n"
        "  mixed = other;\n"
        "  cycle_a = cycle_b;\n"
        "  cycle_b = cycle_a;\n"
        "  _objc_msgSend(receiver,\"render\");\n"
        "}\n",
        encoding="utf-8",
        newline="\n",
    )
    (code / "00001300.c").write_text(
        "void ivarDispatch(ID param_1) {\n"
        "  _objc_msgSend(*(ID *)(param_1 + 8),\"render\");\n"
        "}\n",
        encoding="utf-8",
        newline="\n",
    )
    (code / "00001400.c").write_text(
        "/* wrapped Ghidra namespace */\n"
        "ID Widget::\n"
        "  wrappedMethod(ID param_1, SEL param_2) {\n"
        "  _objc_msgSend(param_1,\"render\");\n"
        "  return param_1;\n"
        "}\n",
        encoding="utf-8",
        newline="\n",
    )
    resolve_objc_dispatch(workspace)
    return workspace


class TypeFlowTests(unittest.TestCase):
    def test_local_declarations_accept_attached_pointer_declarators(self) -> None:
        code = (
            "void inspect(void) {\n"
            "  int *first;\n"
            "  undefined4 after_pointer;\n"
            "  Widget ** objects;\n"
            "  Other* compact;\n"
            "  after_pointer = 0;\n"
            "}\n"
        )
        self.assertEqual(
            [
                ("first", "int *"),
                ("after_pointer", "undefined4"),
                ("objects", "Widget **"),
                ("compact", "Other*"),
            ],
            _local_declarations(code),
        )

    def test_evidence_flow_fixed_point_refinement_and_determinism(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_typeflow_workspace(Path(temporary))
            callgraph_path = workspace / "analysis" / "callgraph.json"
            direct_before = callgraph_path.read_bytes()

            first = infer_objc_types(workspace)
            facts = first.type_flow["facts"]
            self.assertTrue(facts["fixed_point"]["converged"])
            self.assertGreaterEqual(facts["fixed_point"]["cyclic_component_count"], 1)
            self.assertEqual(
                facts["value_count"],
                sum(facts["classification_counts"].values()),
            )
            values = facts["values"]

            ivar = next(
                item for item in values
                if item["kind"] == "ivar" and item["name"] == "mOther"
            )
            self.assertEqual("candidate_set", ivar["classification"])
            self.assertEqual(["Other"], [
                item["class_name"] for item in ivar["type_candidates"]
            ])
            ivar_access = next(
                item for item in values
                if item["kind"] == "ivar_access" and item["name"] == "mOther"
            )
            self.assertIn(
                "ivar_metadata_to_machine_access",
                {
                    step["kind"] for step in facts["propagation_steps"]
                    if step["id"] in ivar_access["propagation_step_ids"]
                },
            )

            scalar_parameter = next(
                item for item in values
                if item["kind"] == "method_parameter"
                and item["method_id"] == "method:widget-render"
                and item["index"] == 2
            )
            self.assertEqual("exact", scalar_parameter["classification"])
            self.assertEqual(["int"], [
                item["name"] for item in scalar_parameter["type_candidates"]
            ])
            wrapped_return = next(
                item for item in values
                if item["kind"] == "function_return"
                and item["function_id"] == "0x00001400"
            )
            self.assertEqual("id", wrapped_return["declared_type"])
            self.assertNotIn(
                "ID Widget::",
                [item["name"] for item in wrapped_return["type_candidates"]],
            )

            evidence_by_id = {
                record["id"]: record for record in facts["evidence"]
            }
            allocation_results = [
                item for item in values
                if item["kind"] == "message_result"
                and item["source_address"] == "0x00001010"
                and any(
                    evidence_by_id[evidence_id]["kind"]
                    == "explicit_class_alloc_result"
                    for evidence_id in item["evidence_ids"]
                )
            ]
            self.assertEqual(1, len(allocation_results))
            self.assertEqual("exact", allocation_results[0]["classification"])
            self.assertEqual(
                ["Widget"],
                [item["class_name"] for item in allocation_results[0]["type_candidates"]],
            )
            init_steps = [
                item for item in facts["propagation_steps"]
                if item["kind"] == "objective_c_init_convention"
            ]
            self.assertEqual(1, len(init_steps))
            self.assertTrue(init_steps[0]["hypothesis"])
            factory_result = next(
                item for item in values
                if item["kind"] == "message_result"
                and item["source_address"] == "0x00001030"
            )
            self.assertEqual("candidate_set", factory_result["classification"])
            self.assertEqual(
                ["Widget"],
                [item["class_name"] for item in factory_result["type_candidates"]],
            )
            self.assertTrue(factory_result["type_candidates"][0]["hypothesis"])
            self.assertTrue(any(
                evidence_by_id[evidence_id]["kind"]
                == "objective_c_class_factory_convention"
                for evidence_id in factory_result["evidence_ids"]
            ))

            superclass_receiver = next(
                item for item in values
                if item["kind"] == "message_receiver"
                and item["source_address"] == "0x00001110"
            )
            self.assertEqual("exact", superclass_receiver["classification"])
            self.assertEqual(
                ["Base"],
                [item["class_name"] for item in superclass_receiver["type_candidates"]],
            )

            mixed = next(
                item for item in values
                if item["kind"] == "local" and item["name"] == "mixed"
            )
            self.assertEqual("candidate_set", mixed["classification"])
            self.assertGreaterEqual(len(mixed["type_candidates"]), 3)
            cycle_a = next(
                item for item in values
                if item["kind"] == "local" and item["name"] == "cycle_a"
            )
            self.assertEqual("unresolved", cycle_a["classification"])
            self.assertIn(
                "no_supported_type_evidence_reaches_value",
                cycle_a["failure_reasons"],
            )

            refinement = next(
                item for item in facts["dispatch_refinements"]
                if item["call_site"] == "0x00001310"
            )
            self.assertEqual("candidate_set", refinement["classification"])
            self.assertEqual("typed_instance", refinement["receiver_kind"])
            self.assertEqual(["Other"], refinement["class_candidates"])
            self.assertTrue(refinement["changed"])
            self.assertIn(
                "type_flow_does_not_prove_one_exact_runtime_class",
                refinement["failure_reasons"],
            )

            first_bytes = first.type_flow_path.read_bytes()
            second = infer_objc_types(workspace)
            self.assertEqual(first_bytes, second.type_flow_path.read_bytes())
            self.assertEqual(first.type_flow, second.type_flow)

            refined_dispatch = resolve_objc_dispatch(workspace)
            self.assertTrue(
                refined_dispatch.dispatch["facts"]["type_flow_refinement_available"]
            )
            refined_callsite = next(
                item for item in refined_dispatch.dispatch["facts"]["callsites"]
                if item["call_site"] == "0x00001310"
            )
            self.assertEqual("candidate_set", refined_callsite["classification"])
            self.assertEqual(2, len(refined_callsite["possible_targets"]))
            self.assertEqual("candidate_set", refined_callsite["refined_classification"])
            self.assertEqual(1, len(refined_callsite["refined_possible_targets"]))
            self.assertEqual(
                "Other",
                refined_callsite["refined_possible_targets"][0]["class_name"],
            )
            self.assertTrue(refined_callsite["refinement_changed"])
            refined_super = next(
                item for item in refined_dispatch.dispatch["facts"]["callsites"]
                if item["call_site"] == "0x00001110"
            )
            self.assertEqual("super", refined_super["receiver"]["receiver_kind"])
            self.assertIsNone(refined_super["type_flow_refinement"])
            self.assertIsNone(refined_super["refined_classification"])
            self.assertEqual(direct_before, callgraph_path.read_bytes())

            stable = infer_objc_types(workspace)
            self.assertEqual(first_bytes, stable.type_flow_path.read_bytes())

            schema_root = Path(__file__).parents[1] / "schemas"
            registry = Registry()
            for schema_path in schema_root.glob("*.schema.json"):
                contents = json.loads(schema_path.read_text(encoding="utf-8"))
                resource = Resource.from_contents(contents)
                registry = registry.with_resource(contents["$id"], resource)
                registry = registry.with_resource(schema_path.name, resource)
            type_schema = json.loads(
                (schema_root / "objc-type-flow.schema.json").read_text(encoding="utf-8")
            )
            dispatch_schema = json.loads(
                (schema_root / "objc-dispatch.schema.json").read_text(encoding="utf-8")
            )
            Draft202012Validator(type_schema, registry=registry).validate(
                stable.type_flow
            )
            Draft202012Validator(dispatch_schema, registry=registry).validate(
                refined_dispatch.dispatch
            )

    def test_cli_exposes_infer_objc_types(self) -> None:
        args = build_parser().parse_args(["infer-objc-types", "workspace"])
        self.assertEqual("infer-objc-types", args.command)
        self.assertEqual(Path("workspace"), args.workspace)

    def test_rejects_pseudocode_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_typeflow_workspace(Path(temporary))
            path = workspace / "analysis" / "recovered-code-index.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["facts"]["functions"][0]["decompilation"]["output_path"] = "../outside.c"
            write_json_atomic(path, document)
            with self.assertRaisesRegex(TypeFlowError, "escapes the analysis workspace"):
                infer_objc_types(workspace)

    def test_rejects_missing_workspace_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                TypeFlowError,
                "missing analysis/callgraph.json",
            ):
                infer_objc_types(Path(temporary))


if __name__ == "__main__":
    unittest.main()
