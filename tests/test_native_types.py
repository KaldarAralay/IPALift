from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from ipalift.cli import build_parser
from ipalift.cpp_model import recover_cpp_model
from ipalift.native_types import (
    NativeTypeFlowError,
    _field_accesses,
    _virtual_forms,
    infer_native_types,
)
from ipalift.util import sha256_file, write_json_atomic
from tests.test_cpp_model import make_workspace, synthetic_macho


PRESERVED_REPORTS = (
    "functions",
    "callgraph",
    "objc-dispatch",
    "objc-type-flow",
    "platform-api-map",
    "cpp-object-model",
)


def _document(workspace: Path, name: str) -> dict[str, object]:
    path = workspace / "analysis" / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _write_document(workspace: Path, name: str, document: dict[str, object]) -> None:
    write_json_atomic(workspace / "analysis" / f"{name}.json", document)


def _replace_code(workspace: Path, function_id: str, code: str) -> None:
    recovered = _document(workspace, "recovered-code-index")
    record = next(
        item
        for item in recovered["facts"]["functions"]
        if item["function_id"] == function_id
    )
    relative = record["decompilation"]["output_path"]
    path = workspace / relative
    path.write_text(code, encoding="utf-8", newline="\n")
    record["decompilation"]["sha256"] = sha256_file(path)
    _write_document(workspace, "recovered-code-index", recovered)


def _add_function(
    workspace: Path,
    function_id: str,
    address: str,
    name: str,
    code: str,
) -> None:
    functions = _document(workspace, "functions")
    functions["facts"]["functions"].append({
        "id": function_id,
        "address": address,
        "name": name,
        "full_name": name,
        "external": False,
        "objective_c_methods": [],
    })
    functions["facts"]["discovered_function_count"] += 1
    _write_document(workspace, "functions", functions)

    relative = f"decompiled/functions/{function_id[2:]}.c"
    path = workspace / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8", newline="\n")
    recovered = _document(workspace, "recovered-code-index")
    recovered["facts"]["functions"].append({
        "function_id": function_id,
        "method_ids": [],
        "decompilation": {
            "status": "success",
            "output_path": relative,
            "sha256": sha256_file(path),
        },
    })
    recovered["facts"]["function_count"] += 1
    _write_document(workspace, "recovered-code-index", recovered)


def _native_workspace(root: Path) -> tuple[Path, str]:
    workspace = make_workspace(root)
    _replace_code(
        workspace,
        "0x00002080",
        (
            "void Derived_constructor(void *this) {\n"
            "  undefined4 field_value;\n"
            "  unknown cycle_a;\n"
            "  unknown cycle_b;\n"
            "  cycle_a = cycle_b;\n"
            "  cycle_b = cycle_a;\n"
            "  *(undefined **)this = PTR_vtable_00001600 + 8;\n"
            "  field_value = *(undefined4 *)(this + 0xc);\n"
            "  *(undefined4 *)(this + 0x10) = field_value;\n"
            "  *(undefined4 *)DAT_00001700 = field_value;\n"
            "  (**(code **)(*(int *)this + 4))(this);\n"
            "}\n"
        ),
    )
    _replace_code(
        workspace,
        "0x00002100",
        (
            "void ambiguous(void *value) {\n"
            "  void * cast_value;\n"
            "  cast_value = (Derived *)value;\n"
            "  cast_value = (Base *)value;\n"
            "  (**(code **)(*(int *)value + 4))(value);\n"
            "}\n"
        ),
    )
    _add_function(
        workspace,
        "0x00002140",
        "0x00002140",
        "Fixture builder",
        (
            "void build_fixture(void *storage) {\n"
            "  Derived_constructor(storage);\n"
            "}\n"
        ),
    )
    callgraph = _document(workspace, "callgraph")
    callgraph["facts"]["edges"].append({
        "call_site": "0x00002148",
        "caller_id": "0x00002140",
        "target_function_id": "0x00002080",
        "target_name": "Derived_constructor",
        "indirect": False,
        "objective_c_dispatch": False,
        "reference_type": "UNCONDITIONAL_CALL",
        "resolved_function_target": True,
        "semantic_target_resolved": True,
        "unresolved_reason": None,
    })
    callgraph["facts"]["edge_count"] += 1
    _write_document(workspace, "callgraph", callgraph)

    with patch("ipalift.cpp_model.parse_macho_file", return_value=synthetic_macho()):
        recover_cpp_model(workspace)

    cpp = _document(workspace, "cpp-object-model")
    derived = next(
        item
        for item in cpp["facts"]["classes"]
        if item["mangled_type_encoding"] == "7Derived"
    )
    exact_constructor = next(
        item
        for item in cpp["facts"]["special_member_functions"]
        if item["kind"] == "constructor" and derived["id"] in item["class_ids"]
    )
    candidate_special = copy.deepcopy(exact_constructor)
    candidate_special.update({
        "id": "cpp-special-member:synthetic-candidate-receiver",
        "address": "0x00002100",
        "function_ids": ["0x00002100"],
        "classification": "candidate_set",
        "confidence": "medium",
        "failure_reasons": ["synthetic_ambiguous_special_member_evidence"],
    })
    cpp["facts"]["special_member_functions"].append(candidate_special)
    cpp["facts"]["special_member_functions"].sort(key=lambda item: item["id"])
    cpp["facts"]["summary"]["special_member_function_count"] += 1
    _write_document(workspace, "cpp-object-model", cpp)
    return workspace, derived["id"]


def _schema() -> dict[str, object]:
    path = Path(__file__).parents[1] / "schemas" / "native-type-flow.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


class NativeTypeFlowTests(unittest.TestCase):
    def test_generic_native_flow_is_complete_conservative_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace, derived_id = _native_workspace(Path(temporary))
            preserved = {
                name: sha256_file(workspace / "analysis" / f"{name}.json")
                for name in PRESERVED_REPORTS
            }
            with patch("ipalift.native_types.parse_macho_file", return_value=synthetic_macho()):
                first = infer_native_types(workspace)
                first_json = first.native_type_flow_path.read_bytes()
                first_report = first.report_path.read_bytes()
                second = infer_native_types(workspace)

            self.assertEqual(first_json, second.native_type_flow_path.read_bytes())
            self.assertEqual(first_report, second.report_path.read_bytes())
            self.assertTrue(all(
                sha256_file(workspace / "analysis" / f"{name}.json") == digest
                for name, digest in preserved.items()
            ))

            facts = second.native_type_flow["facts"]
            self.assertEqual(facts["summary"]["value_count"], len(facts["values"]))
            self.assertEqual(facts["summary"]["layout_count"], len(facts["layouts"]))
            self.assertEqual(facts["summary"]["virtual_refinement_count"], 3)
            self.assertEqual(facts["summary"]["unsupported_cpp_class_count"], 0)
            self.assertTrue(facts["fixed_point"]["converged"])
            self.assertGreaterEqual(facts["fixed_point"]["cyclic_component_count"], 1)
            self.assertEqual(facts["architecture_records"][0]["pointer_size"], 4)
            self.assertEqual(facts["architecture_records"][0]["cpp_abi"], "itanium-cxx-abi")

            values = facts["values"]
            constructor_this = next(
                item for item in values
                if item.get("function_id") == "0x00002080" and item.get("name") == "this"
            )
            self.assertEqual(constructor_this["classification"], "exact")
            self.assertEqual(
                [item["cpp_class_id"] for item in constructor_this["type_candidates"]],
                [derived_id],
            )
            self.assertIn("objc-method:bridge", constructor_this["related_objc_method_ids"])
            self.assertIn("FixtureBridge", constructor_this["related_objc_class_names"])

            constructed_storage = next(
                item for item in values
                if item.get("function_id") == "0x00002140" and item.get("name") == "storage"
            )
            self.assertEqual(constructed_storage["classification"], "exact")
            self.assertEqual(constructed_storage["type_candidates"][0]["kind"], "cpp_dynamic_object")
            self.assertEqual(constructed_storage["type_candidates"][0]["cpp_class_id"], derived_id)

            cycles = [
                item for item in values
                if item.get("function_id") == "0x00002080"
                and item.get("name") in {"cycle_a", "cycle_b"}
            ]
            self.assertEqual(len(cycles), 2)
            self.assertEqual({item["classification"] for item in cycles}, {"unresolved"})
            self.assertEqual(len({item["cycle_id"] for item in cycles}), 1)
            self.assertIsNotNone(cycles[0]["cycle_id"])
            self.assertTrue(all(
                "cyclic_flow_has_no_supported_incoming_evidence" in item["failure_reasons"]
                for item in cycles
            ))

            cast_value = next(
                item for item in values
                if item.get("function_id") == "0x00002100" and item.get("name") == "cast_value"
            )
            self.assertEqual(cast_value["classification"], "candidate_set")
            self.assertIn("Derived *", {item["name"] for item in cast_value["type_candidates"]})
            self.assertIn("Base *", {item["name"] for item in cast_value["type_candidates"]})

            callback = next(
                item for item in values
                if item.get("function_id") == "0x00002120" and item.get("name") == "fn"
            )
            self.assertEqual(callback["classification"], "candidate_set")
            self.assertEqual(callback["type_candidates"][0]["kind"], "function_pointer")

            accesses = {(item["offset"], item["access_kind"]): item for item in facts["field_accesses"]}
            self.assertEqual(accesses[(12, "read")]["width"], 4)
            self.assertEqual(accesses[(16, "write")]["width"], 4)
            derived_layout = next(item for item in facts["layouts"] if item["class_ids"] == [derived_id])
            self.assertEqual(derived_layout["classification"], "exact")
            self.assertEqual(
                {item["offset"] for item in facts["fields"] if item["layout_id"] == derived_layout["id"]},
                {12, 16},
            )

            globals_by_address = {item["address"]: item for item in facts["globals"]}
            self.assertEqual(globals_by_address["0x00001700"]["classification"], "candidate_set")
            self.assertEqual(globals_by_address["0x00001600"]["classification"], "exact")
            self.assertEqual(globals_by_address["0x00001600"]["type_candidates"][0]["kind"], "vtable_pointer")

            cpp = _document(workspace, "cpp-object-model")["facts"]
            callsites = {item["call_site"]: item["id"] for item in cpp["indirect_callsites"]}
            refinements = {item["cpp_callsite_id"]: item for item in facts["virtual_dispatch_refinements"]}
            exact = refinements[callsites["0x00002090"]]
            candidate = refinements[callsites["0x00002108"]]
            unresolved = refinements[callsites["0x00002128"]]
            self.assertEqual(exact["classification"], "exact")
            self.assertEqual(exact["refined_target_function_ids"], ["0x00002060"])
            self.assertEqual(candidate["classification"], "candidate_set")
            self.assertEqual(candidate["refined_target_function_ids"], ["0x00002060", "0x000020c0"])
            self.assertTrue(candidate["changed"])
            self.assertIn("multiple_refined_virtual_targets", candidate["failure_reasons"])
            self.assertEqual(unresolved["classification"], "unresolved")
            self.assertEqual(unresolved["refined_target_function_ids"], [])

            class_index = next(item for item in facts["indexes"]["classes"] if item["class_id"] == derived_id)
            self.assertIn("objc-method:bridge", class_index["method_ids"])
            self.assertIn("FixtureBridge", class_index["objc_class_names"])
            self.assertTrue(facts["indexes"]["functions"])
            self.assertTrue(facts["indexes"]["globals"])
            self.assertTrue(facts["indexes"]["layouts"])
            self.assertEqual(len(facts["indexes"]["callsites"]), 3)
            self.assertTrue(any(
                item["kind"] == "native_virtual_dispatch_target"
                and item["refinement_id"] == candidate["id"]
                for item in second.native_type_flow["hypotheses"]
            ))
            self.assertFalse(facts["evidence_boundary"]["unsupported_cpp_abi_promoted"])

            schema = _schema()
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(second.native_type_flow)

    def test_unsupported_cpp_abi_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace, derived_id = _native_workspace(Path(temporary))
            cpp = _document(workspace, "cpp-object-model")
            derived = next(item for item in cpp["facts"]["classes"] if item["id"] == derived_id)
            derived["abi"] = "vendor-cxx-abi"
            _write_document(workspace, "cpp-object-model", cpp)
            preserved_cpp = sha256_file(workspace / "analysis" / "cpp-object-model.json")
            with patch("ipalift.native_types.parse_macho_file", return_value=synthetic_macho()):
                result = infer_native_types(workspace)
            facts = result.native_type_flow["facts"]
            self.assertEqual(facts["summary"]["unsupported_cpp_class_count"], 1)
            self.assertEqual(facts["unsupported_cpp_classes"], [{
                "class_id": derived_id,
                "architecture": "arm6",
                "abi": "vendor-cxx-abi",
                "failure_reason": "unsupported_cpp_abi",
            }])
            self.assertFalse(any(
                candidate.get("cpp_class_id") == derived_id
                for value in facts["values"]
                for candidate in value["type_candidates"]
            ))
            self.assertTrue(any(item["code"] == "unsupported_cpp_abi" for item in result.native_type_flow["errors"]))
            self.assertEqual(sha256_file(workspace / "analysis" / "cpp-object-model.json"), preserved_cpp)
            Draft202012Validator(_schema()).validate(result.native_type_flow)

    def test_rejects_pseudocode_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _derived_id = _native_workspace(Path(temporary))
            recovered = _document(workspace, "recovered-code-index")
            successful = next(
                item for item in recovered["facts"]["functions"]
                if item["decompilation"]["status"] == "success"
            )
            successful["decompilation"]["output_path"] = "../outside.c"
            _write_document(workspace, "recovered-code-index", recovered)
            with patch("ipalift.native_types.parse_macho_file", return_value=synthetic_macho()):
                with self.assertRaisesRegex(NativeTypeFlowError, "escapes"):
                    infer_native_types(workspace)

    def test_rejects_duplicate_cpp_class_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _derived_id = _native_workspace(Path(temporary))
            cpp = _document(workspace, "cpp-object-model")
            cpp["facts"]["classes"].append(copy.deepcopy(cpp["facts"]["classes"][0]))
            _write_document(workspace, "cpp-object-model", cpp)
            with patch("ipalift.native_types.parse_macho_file", return_value=synthetic_macho()):
                with self.assertRaisesRegex(NativeTypeFlowError, "duplicate class IDs"):
                    infer_native_types(workspace)

    def test_rejects_missing_and_malformed_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            empty = Path(temporary)
            with self.assertRaisesRegex(NativeTypeFlowError, "missing analysis/application.json"):
                infer_native_types(empty)
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _derived_id = _native_workspace(Path(temporary))
            path = workspace / "analysis" / "cpp-object-model.json"
            path.write_text("{malformed", encoding="utf-8")
            with self.assertRaisesRegex(NativeTypeFlowError, "Cannot read"):
                infer_native_types(workspace)

    def test_pointer_sized_forms_are_architecture_aware(self) -> None:
        field_code = "value = object->field0_0x0[3];\n"
        self.assertEqual(_field_accesses(field_code, 4)[0]["offset"], 12)
        self.assertEqual(_field_accesses(field_code, 8)[0]["offset"], 24)
        virtual_code = "(**(code **)object->field0_0x0[2])(object);\n"
        self.assertEqual(_virtual_forms(virtual_code, 4)[0]["slot_offset"], 8)
        self.assertEqual(_virtual_forms(virtual_code, 8)[0]["slot_offset"], 16)

    def test_cli_exposes_infer_native_types(self) -> None:
        args = build_parser().parse_args(["infer-native-types", "workspace"])
        self.assertEqual(args.command, "infer-native-types")


if __name__ == "__main__":
    unittest.main()
