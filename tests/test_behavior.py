from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ipalift.behavior import BehaviorLiftError, lift_behavior
from ipalift.cli import main
from ipalift.interactions import recover_interactions
from ipalift.util import sha256_file, write_json_atomic
from tests.test_interactions import build_interaction_workspace


REPORT_ORDER = (
    "functions",
    "callgraph",
    "recovered-code-index",
    "objc-dispatch",
    "objc-type-flow",
    "platform-api-map",
    "native-type-flow",
    "ui-model",
    "interaction-model",
)


def _refresh_input_hashes(workspace: Path) -> None:
    analysis = workspace / "analysis"
    for consumer in REPORT_ORDER:
        path = analysis / f"{consumer}.json"
        if not path.exists():
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        references = document.get("facts", {}).get("input_artifacts", [])
        changed = False
        if isinstance(references, dict):
            iterator = references.items()
        else:
            iterator = (
                (str(reference.get("artifact") or ""), reference)
                for reference in references
            )
        for artifact, reference in iterator:
            source = analysis / f"{artifact}.json"
            if source.exists() and artifact != consumer:
                digest = sha256_file(source)
                if reference.get("sha256") != digest:
                    reference["sha256"] = digest
                    changed = True
        if changed:
            write_json_atomic(path, document)


def build_behavior_workspace(root: Path) -> Path:
    workspace = build_interaction_workspace(root)
    analysis = workspace / "analysis"
    code_path = workspace / "decompiled" / "functions" / "00001100.c"
    code_path.write_text(
        """int helper(id self, int delta) {
  int oldCount = self->_count;
  self->_count = oldCount + 1;
  if (oldCount < 10) {
    self->_count = oldCount + delta;
  }
  DAT_00002000 = 1;
  _objc_msgSend(defaults, \"objectForKey:\", \"savedKey\");
  _objc_msgSend(defaults, \"setObject:forKey:\", \"value\", \"savedKey\");
  _objc_msgSend(session, \"dataTaskWithURL:completionHandler:\", \"https://example.invalid/api\", block);
  _objc_msgSend(center, \"postNotificationName:object:\", \"SavedNotification\", self);
  _objc_msgSend(self, \"presentViewController:animated:completion:\", detail, 1, 0);
  _objc_msgSend(application, \"openURL:\", url);
  FUN_00001600();
  return self->_count;
}
""",
        encoding="utf-8",
        newline="\n",
    )

    recovered_path = analysis / "recovered-code-index.json"
    recovered = json.loads(recovered_path.read_text(encoding="utf-8"))
    function = next(
        item for item in recovered["facts"]["functions"]
        if item["function_id"] == "0x00001100"
    )
    function["decompilation"]["sha256"] = sha256_file(code_path)
    write_json_atomic(recovered_path, recovered)

    objc_path = analysis / "objc-type-flow.json"
    objc = json.loads(objc_path.read_text(encoding="utf-8"))
    values = objc["facts"].setdefault("values", [])
    if isinstance(values, dict):
        values["type-value:delta"] = {
            "id": "type-value:delta",
            "kind": "function_parameter",
            "function_id": "0x00001100",
            "position": 1,
            "name": "delta",
            "declared_type": "int",
            "classification": "exact",
            "type_candidates": [{"type_name": "int32_t"}],
            "failure_reasons": [],
        }
    else:
        values.append({
            "id": "type-value:delta",
            "kind": "function_parameter",
            "function_id": "0x00001100",
            "position": 1,
            "name": "delta",
            "declared_type": "int",
            "classification": "exact",
            "type_candidates": [{"type_name": "int32_t"}],
            "failure_reasons": [],
        })
    write_json_atomic(objc_path, objc)

    native_path = analysis / "native-type-flow.json"
    native = json.loads(native_path.read_text(encoding="utf-8"))
    native["facts"]["values"] = [{
        "id": "native-value:count",
        "kind": "field_storage",
        "function_id": "0x00001100",
        "name": "count",
        "declared_type": "int32_t",
        "classification": "exact",
        "type_candidates": [{"type_name": "int32_t"}],
        "failure_reasons": [],
    }]
    global_record = native["facts"]["globals"][0]
    reference = next(
        item for item in global_record["references"]
        if item["function_id"] == "0x00001100"
    )
    reference["pseudocode_line"] = 7
    write_json_atomic(native_path, native)

    _refresh_input_hashes(workspace)
    recover_interactions(workspace)
    return workspace


def _schema_registry() -> Registry:
    root = Path(__file__).parents[1] / "schemas"
    registry = Registry()
    for path in root.glob("*.schema.json"):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents)
        registry = registry.with_resource(contents["$id"], resource)
        registry = registry.with_resource(path.name, resource)
    return registry


class BehaviorLiftTests(unittest.TestCase):
    def test_lifts_complete_bounded_deterministic_behavior_and_state_models(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_behavior_workspace(Path(temporary))
            preserved = {
                path: path.read_bytes()
                for path in (workspace / "analysis").glob("*.json")
            }

            first = lift_behavior(workspace)
            first_behavior = first.behavior_ir_path.read_bytes()
            first_state = first.state_model_path.read_bytes()
            first_report = first.report_path.read_bytes()
            second = lift_behavior(workspace)

            self.assertEqual(first_behavior, second.behavior_ir_path.read_bytes())
            self.assertEqual(first_state, second.state_model_path.read_bytes())
            self.assertEqual(first_report, second.report_path.read_bytes())
            for path, contents in preserved.items():
                self.assertEqual(contents, path.read_bytes(), path)

            behavior = second.behavior_ir["facts"]
            contract = next(
                item for item in behavior["function_contracts"]
                if item["function_id"] == "0x00001100"
            )
            self.assertEqual("helper", contract["signature"]["name"])
            self.assertEqual("int", contract["signature"]["declared_return_type"])
            delta = next(item for item in contract["parameters"] if item["name"] == "delta")
            self.assertIn("int32_t", delta["type_candidates"])
            self.assertEqual("explicit_values", contract["return_behavior"]["mode"])
            self.assertIn("self->_count", contract["return_behavior"]["expressions"])
            guards = [
                item for item in behavior["branch_guards"]
                if item["id"] in contract["branch_guard_ids"]
            ]
            self.assertEqual(["oldCount < 10"], [item["expression"] for item in guards])
            self.assertTrue(contract["state_read_ids"])
            self.assertTrue(contract["state_write_ids"])
            self.assertTrue(contract["constant_ids"])
            self.assertTrue(contract["outgoing_call_ids"])
            self.assertEqual(
                {"callback", "notification", "timer"},
                {item["kind"] for item in behavior["async_callbacks"]},
            )
            self.assertTrue(all(item["evidence"] for item in behavior["function_contracts"]))
            self.assertFalse(behavior["evidence_boundary"]["static_paths_claim_runtime_execution"])
            self.assertFalse(behavior["evidence_boundary"]["candidate_sets_promoted"])
            for collection_name in (
                "function_contracts", "return_sites", "branch_guards",
                "state_accesses", "constants", "calls", "async_callbacks",
            ):
                for record in behavior[collection_name]:
                    self.assertTrue(record["evidence"], (collection_name, record["id"]))
                    for link in record["evidence"]:
                        source_path = workspace / Path(*link["path"].split("/"))
                        self.assertTrue(source_path.is_file(), link)
                        self.assertEqual(sha256_file(source_path), link["sha256"], link)

            state = second.state_model["facts"]
            count_state = next(
                item for item in state["state_variables"]
                if item["id"] == "native-value:count"
            )
            self.assertTrue(count_state["read_access_ids"])
            self.assertTrue(count_state["write_access_ids"])
            self.assertIn("int32_t", count_state["type_candidates"])
            self.assertTrue(state["transitions"])
            action_transition = next(
                item for item in state["transitions"]
                if item["event"] == "touchUpInside"
            )
            self.assertTrue(action_transition["branch_guard_ids"])
            self.assertTrue(action_transition["state_write_access_ids"])
            self.assertEqual("candidate_set", action_transition["classification"])
            self.assertIn(
                "static_interaction_does_not_prove_runtime_transition",
                action_transition["failure_reasons"],
            )
            self.assertTrue(state["state_machines"])
            self.assertFalse(state["evidence_boundary"]["transitions_claim_runtime_execution"])
            self.assertFalse(state["evidence_boundary"]["guard_to_effect_paths_claimed_exact"])
            for collection_name in (
                "state_variables", "states", "transitions", "state_machines",
                "async_callbacks",
            ):
                for record in state[collection_name]:
                    self.assertTrue(record["evidence"], (collection_name, record["id"]))
                    for link in record["evidence"]:
                        source_path = workspace / Path(*link["path"].split("/"))
                        self.assertTrue(source_path.is_file(), link)
                        self.assertEqual(sha256_file(source_path), link["sha256"], link)

            registry = _schema_registry()
            schemas = Path(__file__).parents[1] / "schemas"
            Draft202012Validator(
                json.loads((schemas / "behavior-ir.schema.json").read_text(encoding="utf-8")),
                registry=registry,
            ).validate(second.behavior_ir)
            Draft202012Validator(
                json.loads((schemas / "state-model.schema.json").read_text(encoding="utf-8")),
                registry=registry,
            ).validate(second.state_model)

            report = second.report_path.read_text(encoding="utf-8")
            self.assertIn("Static, evidence-linked implementation guidance", report)
            self.assertIn("## State model", report)

    def test_rejects_pseudocode_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_behavior_workspace(Path(temporary))
            path = workspace / "analysis" / "recovered-code-index.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            function = next(
                item for item in document["facts"]["functions"]
                if item["function_id"] == "0x00001100"
            )
            function["decompilation"]["output_path"] = "../outside.c"
            write_json_atomic(path, document)
            _refresh_input_hashes(workspace)
            with self.assertRaisesRegex(BehaviorLiftError, "escapes the analysis workspace"):
                lift_behavior(workspace)

    def test_rejects_missing_or_mismatched_pseudocode_hash(self) -> None:
        for digest, message in ((None, "hash is missing"), ("0" * 64, "hash mismatch")):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                workspace = build_behavior_workspace(Path(temporary))
                path = workspace / "analysis" / "recovered-code-index.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                function = next(
                    item for item in document["facts"]["functions"]
                    if item["function_id"] == "0x00001100"
                )
                function["decompilation"]["sha256"] = digest
                write_json_atomic(path, document)
                _refresh_input_hashes(workspace)
                with self.assertRaisesRegex(BehaviorLiftError, message):
                    lift_behavior(workspace)

    def test_rejects_missing_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(BehaviorLiftError, "missing analysis/functions.json"):
                lift_behavior(Path(temporary))

    def test_rejects_function_parameter_count_over_policy_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_behavior_workspace(Path(temporary))
            parameters = ", ".join(f"int value{index}" for index in range(129))
            code_path = workspace / "decompiled" / "functions" / "00001100.c"
            code_path.write_text(
                f"int helper({parameters}) {{ return 0; }}\n",
                encoding="utf-8",
                newline="\n",
            )
            recovered_path = workspace / "analysis" / "recovered-code-index.json"
            recovered = json.loads(recovered_path.read_text(encoding="utf-8"))
            function = next(
                item for item in recovered["facts"]["functions"]
                if item["function_id"] == "0x00001100"
            )
            function["decompilation"]["sha256"] = sha256_file(code_path)
            write_json_atomic(recovered_path, recovered)
            _refresh_input_hashes(workspace)
            with self.assertRaisesRegex(
                BehaviorLiftError, "Function parameter count 129 exceeds limit 128"
            ):
                lift_behavior(workspace)

    def test_empty_transition_model_retains_exact_artifact_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_behavior_workspace(Path(temporary))
            interaction_path = workspace / "analysis" / "interaction-model.json"
            interaction = json.loads(interaction_path.read_text(encoding="utf-8"))
            interaction["facts"]["interactions"] = []
            interaction["facts"]["triggers"] = []
            interaction["facts"]["call_slices"] = []
            write_json_atomic(interaction_path, interaction)
            _refresh_input_hashes(workspace)

            result = lift_behavior(workspace)
            state = result.state_model["facts"]
            self.assertEqual([], state["transitions"])
            application = next(
                item for item in state["state_machines"]
                if item["scope"] == "application"
            )
            self.assertEqual("unresolved", application["classification"])
            self.assertEqual("behavior-ir", application["evidence"][0]["artifact"])
            self.assertEqual(
                sha256_file(result.behavior_ir_path),
                application["evidence"][0]["sha256"],
            )
            schema_root = Path(__file__).parents[1] / "schemas"
            Draft202012Validator(
                json.loads((schema_root / "state-model.schema.json").read_text(encoding="utf-8")),
                registry=_schema_registry(),
            ).validate(result.state_model)

    def test_cli_lifts_behavior_and_reports_both_artifacts(self) -> None:
        workspace = Path("workspace")
        result = SimpleNamespace(
            workspace=workspace,
            behavior_ir={"facts": {"summary": {
                "function_contract_count": 8,
                "branch_guard_count": 4,
                "state_access_count": 12,
                "async_callback_count": 3,
                "classification_counts": {"exact": 4, "candidate_set": 20, "unresolved": 1},
            }}},
            behavior_ir_path=workspace / "analysis" / "behavior-ir.json",
            state_model={"facts": {"summary": {
                "state_variable_count": 4,
                "transition_count": 6,
                "state_machine_count": 3,
            }}},
            state_model_path=workspace / "analysis" / "state-model.json",
            report_path=workspace / "reports" / "behavior-lifting-report.md",
        )
        stdout = io.StringIO()
        with patch("ipalift.cli.lift_behavior", return_value=result) as lift:
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["lift-behavior", str(workspace)])
        self.assertEqual(0, exit_code)
        lift.assert_called_once_with(workspace)
        output = stdout.getvalue()
        self.assertIn("Functions: 8; guards: 4; state accesses: 12", output)
        self.assertIn("State variables: 4; transitions: 6; machines: 3", output)
        self.assertIn(str(result.behavior_ir_path), output)
        self.assertIn(str(result.state_model_path), output)


if __name__ == "__main__":
    unittest.main()
