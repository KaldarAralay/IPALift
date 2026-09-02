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

from ipalift.behavior import lift_behavior
from ipalift.cli import main
from ipalift.handoff import HandoffError, build_handoff
from ipalift.interactions import recover_interactions
from ipalift.ui_recovery import recover_ui
from ipalift.util import sha256_file, write_json_atomic
from tests.test_interactions import build_interaction_workspace


REQUIRED_INPUTS = (
    "application",
    "assets",
    "recovered-code-index",
    "objc-type-flow",
    "native-type-flow",
    "platform-api-map",
    "ui-model",
    "interaction-model",
    "behavior-ir",
    "state-model",
)


def build_handoff_workspace(root: Path) -> Path:
    workspace = build_interaction_workspace(root)
    analysis = workspace / "analysis"

    objc_path = analysis / "objc-type-flow.json"
    objc = json.loads(objc_path.read_text(encoding="utf-8"))
    objc["facts"]["values"] = [
        {
            "id": "type-value:handler-receiver",
            "kind": "function_parameter",
            "function_id": "0x00001100",
            "name": "receiver",
            "declared_type": "id",
            "classification": "candidate_set",
            "type_candidates": [
                {"class_name": "ExampleController"},
                {"class_name": "UIViewController"},
            ],
            "failure_reasons": ["runtime_receiver_class_not_proven"],
        },
        {
            "id": "type-value:unassigned",
            "kind": "property",
            "function_id": None,
            "name": "model",
            "declared_type": "id",
            "classification": "unresolved",
            "type_candidates": [],
            "failure_reasons": ["property_type_not_recovered"],
        },
    ]
    write_json_atomic(objc_path, objc)

    native_path = analysis / "native-type-flow.json"
    native = json.loads(native_path.read_text(encoding="utf-8"))
    native["facts"]["values"] = [{
        "id": "native-value:count",
        "kind": "field_storage",
        "function_id": "0x00001100",
        "name": None,
        "declared_type": "int32_t",
        "classification": "exact",
        "type_candidates": [{"type_name": "int32_t"}],
        "failure_reasons": [],
    }]
    native["facts"]["layouts"] = [{
        "id": "native-layout:example",
        "class_ids": ["cpp-class:example"],
        "field_ids": ["native-field:count"],
        "value_ids": ["native-value:count"],
        "size": 16,
        "alignment": 8,
        "classification": "candidate_set",
        "failure_reasons": ["layout_owner_candidate"],
    }]
    write_json_atomic(native_path, native)

    recover_ui(workspace)
    recover_interactions(workspace)
    refresh_shared_input_hashes(workspace)
    lift_behavior(workspace)
    return workspace


def refresh_shared_input_hashes(workspace: Path) -> None:
    order = (
        "application",
        "assets",
        "functions",
        "callgraph",
        "recovered-code-index",
        "objc-dispatch",
        "objc-type-flow",
        "platform-api-map",
        "native-type-flow",
        "ui-model",
        "interaction-model",
        "behavior-ir",
        "state-model",
    )
    analysis = workspace / "analysis"
    for consumer in order:
        path = analysis / f"{consumer}.json"
        if not path.exists():
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        changed = False
        references = document.get("facts", {}).get("input_artifacts", [])
        if isinstance(references, dict):
            iterator = references.items()
        else:
            iterator = (
                (str(reference.get("artifact") or ""), reference)
                for reference in references
            )
        for artifact, reference in iterator:
            source = analysis / f"{artifact}.json"
            if source.exists():
                reference["sha256"] = sha256_file(source)
                changed = True
        if changed:
            write_json_atomic(path, document)


def schema_registry() -> Registry:
    root = Path(__file__).parents[1] / "schemas"
    registry = Registry()
    for path in root.glob("*.schema.json"):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents)
        registry = registry.with_resource(contents["$id"], resource)
        registry = registry.with_resource(path.name, resource)
    return registry


class HandoffTests(unittest.TestCase):
    def test_builds_complete_bounded_deterministic_handoff_without_mutating_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_handoff_workspace(Path(temporary))
            analysis = workspace / "analysis"
            upstream = {
                name: (analysis / f"{name}.json").read_bytes()
                for name in REQUIRED_INPUTS
            }
            stale = workspace / "handoff" / "work-packets" / "stale.json"
            stale.parent.mkdir(parents=True, exist_ok=True)
            stale.write_text("stale", encoding="utf-8")

            first = build_handoff(workspace)
            first_manifest = first.manifest_path.read_bytes()
            first_report = first.report_path.read_bytes()
            first_packets = {
                path.name: path.read_bytes()
                for path in first.packets_root.glob("*.json")
            }
            second = build_handoff(workspace)

            self.assertEqual(first_manifest, second.manifest_path.read_bytes())
            self.assertEqual(first_report, second.report_path.read_bytes())
            self.assertEqual(
                first_packets,
                {path.name: path.read_bytes() for path in second.packets_root.glob("*.json")},
            )
            self.assertFalse(stale.exists())
            for name, before in upstream.items():
                self.assertEqual(before, (analysis / f"{name}.json").read_bytes(), name)

            facts = second.manifest["facts"]
            summary = facts["summary"]
            self.assertEqual(len(facts["screen_plans"]), summary["screen_plan_count"])
            self.assertEqual(len(facts["packet_index"]), summary["packet_count"])
            self.assertEqual(len(facts["implementation_order"]), summary["work_item_count"])
            self.assertGreater(summary["candidate_alternative_count"], 0)
            self.assertGreater(summary["unresolved_question_count"], 0)
            self.assertGreater(facts["application_plan"]["work_item_count"], 0)
            self.assertTrue(any(len(item["packet_ids"]) > 1 for item in facts["screen_plans"]))

            packet_documents = [
                json.loads((workspace / packet["path"]).read_text(encoding="utf-8"))
                for packet in facts["packet_index"]
            ]
            all_items = [item for packet in packet_documents for item in packet["work_items"]]
            all_subjects = {item["subject_id"] for item in all_items}
            all_kinds = {item["kind"] for item in all_items}
            self.assertTrue({
                "screen", "component", "asset", "navigation", "interaction", "state",
                "persistence", "networking", "platform_dependency", "code_unit", "type_context",
                "behavior_contract", "state_machine",
            }.issubset(all_kinds))
            for artifact, collection, key in (
                ("ui-model", "elements", "id"),
                ("ui-model", "resource_references", "id"),
                ("ui-model", "navigation_edges", "id"),
                ("interaction-model", "interactions", "id"),
                ("interaction-model", "effects", "id"),
                ("recovered-code-index", "functions", "function_id"),
                ("platform-api-map", "dependencies", "id"),
                ("behavior-ir", "function_contracts", "id"),
                ("state-model", "state_variables", "id"),
                ("state-model", "transitions", "id"),
                ("state-model", "state_machines", "id"),
            ):
                source = json.loads((analysis / f"{artifact}.json").read_text(encoding="utf-8"))
                expected = {str(item[key]) for item in source["facts"].get(collection, []) if item.get(key)}
                self.assertTrue(expected.issubset(all_subjects), (artifact, collection))

            archive_assets = json.loads(
                (analysis / "assets.json").read_text(encoding="utf-8")
            )["facts"].get("assets", [])
            expected_archive_asset_ids = {
                "archive-asset:" + hashlib.sha256(
                    str(
                        asset.get("bundle_relative_path")
                        or asset.get("path")
                        or f"sha256:{asset.get('sha256') or index}"
                    ).encode("utf-8")
                ).hexdigest()[:20]
                for index, asset in enumerate(archive_assets)
            }
            linked_archive_asset_ids = {
                link["record_id"]
                for item in all_items
                for link in item["evidence_links"]
                if link["artifact"] == "assets"
            }
            self.assertTrue(expected_archive_asset_ids.issubset(linked_archive_asset_ids))

            bounds = facts["policy"]["bounds"]
            input_hashes = {item["artifact"]: item["sha256"] for item in facts["input_artifacts"]}
            for packet_ref, packet in zip(facts["packet_index"], packet_documents):
                path = workspace / packet_ref["path"]
                self.assertLessEqual(path.stat().st_size, bounds["max_packet_bytes"])
                self.assertLessEqual(len(packet["work_items"]), bounds["max_work_items_per_packet"])
                self.assertEqual(packet_ref["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                for item in packet["work_items"]:
                    self.assertTrue(item["evidence_links"])
                    for link in item["evidence_links"]:
                        if link["artifact"] in input_hashes:
                            self.assertEqual(input_hashes[link["artifact"]], link["sha256"])
                            self.assertTrue(link["json_pointer"].startswith("/"))

            order = facts["implementation_order"]
            self.assertEqual(list(range(1, len(order) + 1)), [item["rank"] for item in order])
            phase_positions = {value: index for index, value in enumerate(facts["policy"]["phase_order"])}
            self.assertEqual(
                sorted(phase_positions[item["phase"]] for item in order),
                [phase_positions[item["phase"]] for item in order],
            )
            self.assertFalse(facts["evidence_boundary"]["new_behavioral_inference_introduced"])
            self.assertFalse(facts["evidence_boundary"]["candidate_sets_promoted"])
            self.assertTrue(facts["evidence_boundary"]["packets_bounded"])

            schemas = Path(__file__).parents[1] / "schemas"
            registry = schema_registry()
            manifest_schema = json.loads(
                (schemas / "reconstruction-handoff.schema.json").read_text(encoding="utf-8")
            )
            packet_schema = json.loads(
                (schemas / "reconstruction-work-packet.schema.json").read_text(encoding="utf-8")
            )
            Draft202012Validator(manifest_schema, registry=registry).validate(second.manifest)
            validator = Draft202012Validator(packet_schema, registry=registry)
            for packet in packet_documents:
                validator.validate(packet)

    def test_bounds_large_inline_component_data_and_keeps_source_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_handoff_workspace(Path(temporary))
            ui_path = workspace / "analysis" / "ui-model.json"
            ui = json.loads(ui_path.read_text(encoding="utf-8"))
            element = ui["facts"]["elements"][0]
            element["properties"]["veryLongValue"] = "x" * 10000
            element_id = element["id"]
            write_json_atomic(ui_path, ui)
            recover_interactions(workspace)
            refresh_shared_input_hashes(workspace)
            lift_behavior(workspace)

            result = build_handoff(workspace)
            items = [
                item
                for packet in result.manifest["facts"]["packet_index"]
                for item in json.loads((workspace / packet["path"]).read_text(encoding="utf-8"))["work_items"]
                if item["subject_id"] == element_id
            ]
            self.assertEqual(1, len(items))
            marker = items[0]["details"]["properties"]["veryLongValue"]
            self.assertEqual("text", marker["$truncated"])
            self.assertEqual(10000, marker["original_char_count"])
            self.assertTrue(items[0]["evidence_links"])

    def test_rejects_stale_shared_input_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_handoff_workspace(Path(temporary))
            ui_path = workspace / "analysis" / "ui-model.json"
            ui = json.loads(ui_path.read_text(encoding="utf-8"))
            ui["facts"]["screens"][0]["name"] = "Changed after interaction recovery"
            write_json_atomic(ui_path, ui)
            with self.assertRaisesRegex(HandoffError, "built from a different ui-model"):
                build_handoff(workspace)

    def test_accepts_mapping_shaped_typeflow_provenance_from_real_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_handoff_workspace(Path(temporary))
            path = workspace / "analysis" / "objc-type-flow.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["facts"]["input_artifacts"] = {
                "recovered-code-index": {
                    "path": "analysis/recovered-code-index.json",
                    "sha256": sha256_file(
                        workspace / "analysis" / "recovered-code-index.json"
                    ),
                }
            }
            write_json_atomic(path, document)
            refresh_shared_input_hashes(workspace)
            lift_behavior(workspace)

            result = build_handoff(workspace)
            self.assertTrue(result.manifest_path.is_file())

    def test_rejects_pseudocode_path_traversal_and_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_handoff_workspace(Path(temporary))
            recovered_path = workspace / "analysis" / "recovered-code-index.json"
            recovered = json.loads(recovered_path.read_text(encoding="utf-8"))
            function = next(
                item for item in recovered["facts"]["functions"]
                if item["function_id"] == "0x00001000"
            )
            original = dict(function["decompilation"])
            function["decompilation"]["output_path"] = "../outside.c"
            write_json_atomic(recovered_path, recovered)
            refresh_shared_input_hashes(workspace)
            with self.assertRaisesRegex(HandoffError, "escapes the analysis workspace"):
                build_handoff(workspace)

            recovered = json.loads(recovered_path.read_text(encoding="utf-8"))
            function = next(
                item for item in recovered["facts"]["functions"]
                if item["function_id"] == "0x00001000"
            )
            function["decompilation"] = original
            function["decompilation"]["sha256"] = "0" * 64
            write_json_atomic(recovered_path, recovered)
            refresh_shared_input_hashes(workspace)
            with self.assertRaisesRegex(HandoffError, "hash mismatch"):
                build_handoff(workspace)

    def test_rejects_missing_or_dangling_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(HandoffError, "missing analysis/application.json"):
                build_handoff(Path(temporary))

        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_handoff_workspace(Path(temporary))
            path = workspace / "analysis" / "interaction-model.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["facts"]["interactions"][0]["trigger_id"] = "interaction-trigger:missing"
            write_json_atomic(path, document)
            refresh_shared_input_hashes(workspace)
            with self.assertRaisesRegex(HandoffError, "unknown trigger"):
                build_handoff(workspace)


    def test_cli_builds_handoff_and_reports_all_artifacts(self) -> None:
        workspace = Path("workspace")
        result = SimpleNamespace(
            workspace=workspace,
            manifest={"facts": {"summary": {
                "screen_plan_count": 3,
                "packet_count": 5,
                "work_item_count": 42,
                "classification_counts": {"exact": 30, "candidate_set": 9, "unresolved": 3},
            }}},
            manifest_path=workspace / "analysis" / "reconstruction-handoff.json",
            packets_root=workspace / "handoff" / "work-packets",
            report_path=workspace / "reports" / "reconstruction-handoff-report.md",
        )
        stdout = io.StringIO()
        with patch("ipalift.cli.build_handoff", return_value=result) as build:
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["build-handoff", str(workspace)])
        self.assertEqual(0, exit_code)
        build.assert_called_once_with(workspace)
        output = stdout.getvalue()
        self.assertIn("Screens: 3; packets: 5; work items: 42", output)
        self.assertIn(str(result.manifest_path), output)
        self.assertIn(str(result.packets_root), output)
        self.assertIn(str(result.report_path), output)
if __name__ == "__main__":
    unittest.main()
