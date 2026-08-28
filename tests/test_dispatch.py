from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ipalift.dispatch import DispatchError, resolve_objc_dispatch
from ipalift.util import report_envelope, write_json_atomic


def method(
    method_id: str,
    function_id: str,
    class_name: str,
    selector: str,
    *,
    kind: str = "instance",
) -> dict:
    marker = "+" if kind == "class" else "-"
    return {
        "id": method_id,
        "function_id": function_id,
        "mapping_status": "mapped",
        "exact_name": f"{marker}[{class_name} {selector}]",
        "class_name": class_name,
        "category_name": None,
        "kind": kind,
        "selector": selector,
        "architecture": "arm6",
        "canonical_address": function_id,
        "implementation_pointer": function_id,
    }


def raw_function(
    function_id: str,
    *,
    methods: list[dict] | None = None,
    references: list[dict] | None = None,
) -> dict:
    return {
        "id": function_id,
        "address": function_id,
        "name": f"FUN_{function_id[2:]}",
        "full_name": f"FUN_{function_id[2:]}",
        "objective_c_methods": methods or [],
        "cross_references": references or [],
    }


def selector_reference(from_address: str, to_address: str) -> dict:
    return {
        "from_address": from_address,
        "to_address": to_address,
        "reference_type": "PARAM",
        "target_symbol": None,
    }


def direct_edge(caller_id: str, call_site: str, target_name: str = "_objc_msgSend") -> dict:
    return {
        "caller_id": caller_id,
        "call_site": call_site,
        "target_address": "0x00009000",
        "target_function_id": None,
        "target_name": target_name,
        "thunk_target_name": f"<EXTERNAL>::{target_name}",
        "reference_type": "UNCONDITIONAL_CALL",
        "indirect": False,
        "objective_c_dispatch": True,
        "resolved_function_target": False,
        "semantic_target_resolved": False,
        "unresolved_reason": "Dynamic Objective-C message dispatch target is not proven",
    }


def recovered_function(function_id: str, method_ids: list[str], output_path: str | None) -> dict:
    return {
        "function_id": function_id,
        "method_ids": method_ids,
        "decompilation": {
            "status": "success" if output_path else "failure",
            "output_path": output_path,
            "sha256": None,
            "message": None if output_path else "fixture failure",
        },
    }


def build_dispatch_workspace(root: Path) -> Path:
    workspace = root / "workspace"
    analysis = workspace / "analysis"
    code = workspace / "decompiled" / "functions"
    analysis.mkdir(parents=True)
    code.mkdir(parents=True)

    methods = [
        method("method:factory", "0x00002000", "Widget", "factory", kind="class"),
        method("method:cleanup", "0x00002100", "Base", "cleanup"),
        method("method:widget-render", "0x00002200", "Widget", "render"),
        method("method:other-render", "0x00002300", "Other", "render"),
        method("method:super-caller", "0x00001100", "Widget", "invokeSuper"),
        method("method:self-caller", "0x00001400", "Widget", "invokeSelf"),
    ]
    method_by_id = {item["id"]: item for item in methods}
    raw_functions = [
        raw_function(
            "0x00001000",
            references=[selector_reference("0x0000100c", "0x00003000")],
        ),
        raw_function(
            "0x00001100",
            methods=[method_by_id["method:super-caller"]],
            references=[selector_reference("0x0000110c", "0x00003004")],
        ),
        raw_function(
            "0x00001200",
            references=[selector_reference("0x0000120c", "0x00003008")],
        ),
        raw_function(
            "0x00001300",
            references=[selector_reference("0x0000130c", "0x0000300c")],
        ),
        raw_function(
            "0x00001400",
            methods=[method_by_id["method:self-caller"]],
            references=[selector_reference("0x0000140c", "0x00003008")],
        ),
        raw_function(
            "0x00001500",
            references=[selector_reference("0x0000150c", "0x00003010")],
        ),
        *[
            raw_function(item["function_id"], methods=[item])
            for item in methods
            if item["id"] not in {"method:super-caller", "method:self-caller"}
        ],
    ]
    write_json_atomic(
        analysis / "functions.json",
        report_envelope(
            "functions",
            {"discovered_function_count": len(raw_functions), "functions": raw_functions},
        ),
    )

    edges = [
        direct_edge("0x00001000", "0x00001010"),
        direct_edge("0x00001100", "0x00001110", "_objc_msgSendSuper2"),
        direct_edge("0x00001200", "0x00001210"),
        direct_edge("0x00001300", "0x00001310"),
        direct_edge("0x00001400", "0x00001410"),
        direct_edge("0x00001500", "0x00001510", "_objc_msgSend_fpret"),
    ]
    write_json_atomic(
        analysis / "callgraph.json",
        report_envelope("callgraph", {"edge_count": len(edges), "edges": edges}),
    )
    strings = [
        {"address": "0x00003000", "value": "factory", "is_selector": True},
        {"address": "0x00003004", "value": "cleanup", "is_selector": True},
        {"address": "0x00003008", "value": "render", "is_selector": True},
        {"address": "0x0000300c", "value": "setNeedsDisplay", "is_selector": True},
        {"address": "0x00003010", "value": "externalOnly", "is_selector": True},
    ]
    write_json_atomic(
        analysis / "strings.json",
        report_envelope("strings", {"strings": strings}),
    )

    classes = [
        {
            "name": "Base",
            "architecture": "arm6",
            "address": "0x00004000",
            "metaclass_address": "0x00004004",
            "superclass": {"name": "NSObject"},
        },
        {
            "name": "Widget",
            "architecture": "arm6",
            "address": "0x00004100",
            "metaclass_address": "0x00004104",
            "superclass": {"name": "Base"},
        },
        {
            "name": "Other",
            "architecture": "arm6",
            "address": "0x00004200",
            "metaclass_address": "0x00004204",
            "superclass": {"name": "NSObject"},
        },
    ]
    source_paths = {
        function_id: f"decompiled/functions/{function_id[2:]}.c"
        for function_id in ("0x00001000", "0x00001100", "0x00001200", "0x00001300", "0x00001400", "0x00001500")
    }
    recovered_functions = [
        recovered_function(
            item["id"],
            [method_record["id"] for method_record in item.get("objective_c_methods", [])],
            source_paths.get(item["id"]),
        )
        for item in raw_functions
    ]
    write_json_atomic(
        analysis / "recovered-code-index.json",
        report_envelope(
            "recovered-code-index",
            {
                "function_count": len(recovered_functions),
                "objective_c_method_count": len(methods),
                "functions": recovered_functions,
                "methods": methods,
                "classes": classes,
            },
        ),
    )

    pseudocode = {
        "0x00001000": 'void exact(void) { _objc_msgSend(&objc::class_t::Widget,"factory"); }\n',
        "0x00001100": 'void superCall(ID param_1,SEL param_2) { _objc_msgSendSuper2(&local_14,"cleanup"); }\n',
        "0x00001200": 'void ambiguous(ID receiver) { _objc_msgSend(receiver,"render"); }\n',
        "0x00001300": 'void unresolved(ID receiver) { _objc_msgSend(receiver,"setNeedsDisplay"); }\n',
        "0x00001400": 'void selfCall(ID param_1,SEL param_2) { _objc_msgSend(param_1,"render"); }\n',
        "0x00001500": 'void related(ID receiver) { _objc_msgSend_fpret(receiver,"externalOnly"); }\n',
    }
    for function_id, contents in pseudocode.items():
        (code / f"{function_id[2:]}.c").write_text(contents, encoding="utf-8", newline="\n")
    return workspace


class DispatchTests(unittest.TestCase):
    def test_dispatch_analysis_is_complete_conservative_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_dispatch_workspace(Path(temporary))
            callgraph_path = workspace / "analysis" / "callgraph.json"
            direct_before = callgraph_path.read_bytes()
            first = resolve_objc_dispatch(workspace)
            facts = first.dispatch["facts"]
            self.assertEqual(6, facts["dispatch_callsite_count"])
            self.assertEqual(
                {"resolved": 2, "candidate_set": 2, "unresolved": 2},
                facts["classification_counts"],
            )
            self.assertEqual(6, sum(facts["selector_status_counts"].values()))
            self.assertEqual({"objc_msgSend": 4, "objc_msgSendSuper2": 1, "objc_msgSend_fpret": 1}, facts["runtime_variant_counts"])
            self.assertEqual(direct_before, callgraph_path.read_bytes())

            callsites = {item["call_site"]: item for item in facts["callsites"]}
            exact = callsites["0x00001010"]
            self.assertEqual("resolved", exact["classification"])
            self.assertEqual("class_object", exact["receiver"]["receiver_kind"])
            self.assertEqual("+[Widget factory]", exact["possible_targets"][0]["exact_name"])
            self.assertEqual([], exact["failure_reasons"])

            superclass = callsites["0x00001110"]
            self.assertEqual("resolved", superclass["classification"])
            self.assertEqual("super", superclass["receiver"]["receiver_kind"])
            self.assertEqual("-[Base cleanup]", superclass["possible_targets"][0]["exact_name"])
            self.assertEqual(["Base"], superclass["lookup_paths"])

            ambiguous = callsites["0x00001210"]
            self.assertEqual("candidate_set", ambiguous["classification"])
            self.assertEqual(
                {"-[Other render]", "-[Widget render]"},
                {item["exact_name"] for item in ambiguous["possible_targets"]},
            )
            self.assertIn("multiple_recovered_target_methods_remain_possible", ambiguous["failure_reasons"])

            self_call = callsites["0x00001410"]
            self.assertEqual("candidate_set", self_call["classification"])
            self.assertEqual("self", self_call["receiver"]["receiver_kind"])
            self.assertTrue(self_call["receiver"]["dynamic_subclasses_possible"])
            self.assertIn(
                "single_local_candidate_is_not_an_exact_dynamic_receiver_proof",
                self_call["failure_reasons"],
            )

            unresolved = callsites["0x00001310"]
            self.assertEqual("unresolved", unresolved["classification"])
            self.assertEqual([], unresolved["possible_targets"])
            self.assertIn(
                "no_recovered_method_implements_the_supported_selector_context",
                unresolved["failure_reasons"],
            )
            self.assertEqual("objc_msgSend_fpret", callsites["0x00001510"]["direct_runtime_edge"]["runtime_variant"])

            self.assertEqual(facts["inferred_edge_count"], len(first.dispatch["hypotheses"]))
            self.assertTrue(all(item["edge_kind"] == "objective_c_dynamic_dispatch_inference" for item in first.dispatch["hypotheses"]))
            self.assertNotIn("inferred_edges", facts)

            tracked = [first.dispatch_path, first.report_path]
            first_bytes = {path: path.read_bytes() for path in tracked}
            second = resolve_objc_dispatch(workspace)
            self.assertEqual(direct_before, callgraph_path.read_bytes())
            for path, contents in first_bytes.items():
                self.assertEqual(contents, path.read_bytes(), path)
            self.assertEqual(first.dispatch, second.dispatch)

            schema_root = Path(__file__).parents[1] / "schemas"
            registry = Registry()
            for schema_path in schema_root.glob("*.schema.json"):
                contents = json.loads(schema_path.read_text(encoding="utf-8"))
                resource = Resource.from_contents(contents)
                registry = registry.with_resource(contents["$id"], resource)
                registry = registry.with_resource(schema_path.name, resource)
            schema = json.loads((schema_root / "objc-dispatch.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator(schema, registry=registry).validate(second.dispatch)

    def test_rejects_pseudocode_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_dispatch_workspace(Path(temporary))
            path = workspace / "analysis" / "recovered-code-index.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["facts"]["functions"][0]["decompilation"]["output_path"] = "../outside.c"
            write_json_atomic(path, document)
            with self.assertRaisesRegex(DispatchError, "escapes the analysis workspace"):
                resolve_objc_dispatch(workspace)

    def test_rejects_missing_workspace_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(DispatchError, "missing analysis/callgraph.json"):
                resolve_objc_dispatch(Path(temporary))


if __name__ == "__main__":
    unittest.main()
