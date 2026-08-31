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

from ipalift.cli import main
from ipalift.interactions import InteractionRecoveryError, recover_interactions
from ipalift.ui_recovery import recover_ui
from ipalift.util import report_envelope, write_json_atomic
from tests.test_ui_recovery import build_ui_workspace


def _method(method_id: str, function_id: str, selector: str) -> dict:
    return {
        "id": method_id,
        "function_id": function_id,
        "mapping_status": "mapped",
        "class_name": "ExampleController",
        "selector": selector,
        "kind": "instance",
    }


def _function(function_id: str, method_ids: list[str], output_path: str | None) -> dict:
    return {
        "function_id": function_id,
        "method_ids": method_ids,
        "callers": [],
        "callees": [],
        "referenced_strings": [],
        "referenced_assets": [],
        "decompilation": {
            "status": "success" if output_path else "failure",
            "output_path": output_path,
            "sha256": None,
            "message": None if output_path else "synthetic function has no pseudocode",
        },
    }


def _direct_edge(caller: str, target: str, call_site: str) -> dict:
    return {
        "caller_id": caller,
        "call_site": call_site,
        "target_address": target,
        "target_function_id": target,
        "target_name": f"FUN_{target[2:]}",
        "thunk_target_name": None,
        "reference_type": "UNCONDITIONAL_CALL",
        "indirect": False,
        "objective_c_dispatch": False,
        "resolved_function_target": True,
        "semantic_target_resolved": True,
        "unresolved_reason": None,
    }


def _platform_call(
    identity: str,
    function_id: str,
    call_site: str,
    selector: str,
    categories: list[str],
    *,
    frameworks: list[str] | None = None,
) -> dict:
    return {
        "id": f"platform-message:{identity}",
        "caller_function_id": function_id,
        "call_site": call_site,
        "selector": selector,
        "classification": "exact",
        "platform_status": "external_exact",
        "frameworks": frameworks or ["Foundation"],
        "categories": categories,
        "external_class_candidates": [],
        "affected_method_ids": [],
        "affected_class_names": ["ExampleController"],
        "failure_reasons": [],
    }


def build_interaction_workspace(root: Path) -> Path:
    workspace = build_ui_workspace(root)
    analysis = workspace / "analysis"
    code_root = workspace / "decompiled" / "functions"
    code_root.mkdir(parents=True, exist_ok=True)

    code_by_function = {
        "0x00001000": """void didTap(id self) {
  _objc_msgSend(self, \"setText:\", \"Working\");
  FUN_00001100(self);
}
""",
        "0x00001100": """void helper(id self) {
  int oldCount = self->_count;
  self->_count = oldCount + 1;
  DAT_00002000 = 1;
  _objc_msgSend(defaults, \"objectForKey:\", \"savedKey\");
  _objc_msgSend(defaults, \"setObject:forKey:\", \"value\", \"savedKey\");
  _objc_msgSend(session, \"dataTaskWithURL:completionHandler:\", \"https://example.invalid/api\", block);
  _objc_msgSend(center, \"postNotificationName:object:\", \"SavedNotification\", self);
  _objc_msgSend(self, \"presentViewController:animated:completion:\", detail, 1, 0);
  _objc_msgSend(application, \"openURL:\", url);
  FUN_00001600();
}
""",
        "0x00001200": """void viewDidLoad(id self) {
  _objc_msgSend(center, \"addObserver:selector:name:object:\", self, \"handleRefresh:\", \"RefreshNotification\", 0);
  _objc_msgSend(timerClass, \"scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:\", 1.5, self, \"tick:\", 0, 1);
}
""",
        "0x00001300": "void didSelect(id self) { self->_selected = 1; }\n",
        "0x00001400": "void handleRefresh(id self) { self->_needsRefresh = 1; }\n",
        "0x00001500": "void tick(id self) { int value = self->_count; }\n",
        "0x00001600": "void completion(void) { DAT_00002000 = 2; }\n",
        "0x00001700": "void dynamicTarget(id self) { self->_dynamic = 1; }\n",
    }
    for function_id, code in code_by_function.items():
        path = code_root / f"{function_id[2:]}.c"
        path.write_text(code, encoding="utf-8", newline="\n")

    recovered_path = analysis / "recovered-code-index.json"
    recovered = json.loads(recovered_path.read_text(encoding="utf-8"))
    facts = recovered["facts"]
    methods = facts["methods"]
    additional_methods = [
        _method("method:view-did-load", "0x00001200", "viewDidLoad"),
        _method("method:did-select", "0x00001300", "tableView:didSelectRowAtIndexPath:"),
        _method("method:handle-refresh", "0x00001400", "handleRefresh:"),
        _method("method:tick", "0x00001500", "tick:"),
    ]
    methods.extend(additional_methods)
    function_records = {str(item.get("function_id")): item for item in facts["functions"]}
    function_records["0x00001000"]["decompilation"] = {
        "status": "success",
        "output_path": "decompiled/functions/00001000.c",
        "sha256": None,
        "message": None,
    }
    function_records["0x00001000"]["callees"] = ["0x00001100"]
    function_records["0x00001000"]["referenced_strings"] = [{"value": "Working"}]
    for function_id, method_ids in (
        ("0x00001100", []),
        ("0x00001200", ["method:view-did-load"]),
        ("0x00001300", ["method:did-select"]),
        ("0x00001400", ["method:handle-refresh"]),
        ("0x00001500", ["method:tick"]),
        ("0x00001600", []),
        ("0x00001700", []),
    ):
        relative = f"decompiled/functions/{function_id[2:]}.c"
        function_records[function_id] = _function(function_id, method_ids, relative)
    function_records["0x00001100"]["callers"] = ["0x00001000"]
    function_records["0x00001100"]["callees"] = ["0x00001600"]
    function_records["0x00001100"]["referenced_strings"] = [
        {"value": "savedKey"},
        {"value": "https://example.invalid/api"},
    ]
    for record in function_records.values():
        decompilation = record.get("decompilation") or {}
        relative = decompilation.get("output_path")
        if decompilation.get("status") == "success" and relative:
            decompilation["sha256"] = hashlib.sha256((workspace / relative).read_bytes()).hexdigest()
    facts["functions"] = sorted(function_records.values(), key=lambda item: str(item.get("function_id")))
    facts["function_count"] = len(facts["functions"])
    facts["objective_c_method_count"] = len(methods)
    controller = next(item for item in facts["classes"] if item.get("name") == "ExampleController")
    controller.setdefault("protocols", []).append("UITableViewDelegate")
    controller["properties"].append({"name": "count"})
    controller.setdefault("ivars", []).extend([
        {"name": "_count"},
        {"name": "_selected"},
        {"name": "_needsRefresh"},
        {"name": "_dynamic"},
    ])
    write_json_atomic(recovered_path, recovered)

    raw_functions = [
        {"id": function_id, "external": False}
        for function_id in sorted(code_by_function)
    ]
    write_json_atomic(
        analysis / "functions.json",
        report_envelope("functions", {"discovered_function_count": len(raw_functions), "functions": raw_functions}),
    )
    edges = [
        _direct_edge("0x00001000", "0x00001100", "0x00001030"),
        _direct_edge("0x00001100", "0x00001600", "0x00001170"),
    ]
    write_json_atomic(
        analysis / "callgraph.json",
        report_envelope("callgraph", {"edge_count": len(edges), "edges": edges}),
    )
    dispatch = json.loads((analysis / "objc-dispatch.json").read_text(encoding="utf-8"))
    dispatch["hypotheses"] = [{
        "id": "objc-dispatch-edge:synthetic",
        "edge_kind": "objective_c_dynamic_dispatch_inference",
        "caller_function_id": "0x00001100",
        "call_site": "0x00001174",
        "target_method_id": "method:dynamic",
        "target_function_id": "0x00001700",
        "selector": "dynamicOperation",
        "resolution": "resolved",
    }]
    write_json_atomic(analysis / "objc-dispatch.json", dispatch)

    platform_path = analysis / "platform-api-map.json"
    platform = json.loads(platform_path.read_text(encoding="utf-8"))
    calls = platform["facts"]["message_callsites"]
    calls.extend([
        _platform_call("defaults-read", "0x00001100", "0x00001110", "objectForKey:", ["persistence"]),
        _platform_call("defaults-write", "0x00001100", "0x00001118", "setObject:forKey:", ["persistence"]),
        _platform_call("network", "0x00001100", "0x00001120", "dataTaskWithURL:completionHandler:", ["networking"]),
        _platform_call("notification-post", "0x00001100", "0x00001130", "postNotificationName:object:", ["system_services"]),
        _platform_call("present", "0x00001100", "0x00001140", "presentViewController:animated:completion:", ["ui"], frameworks=["UIKit"]),
        _platform_call("generic-platform", "0x00001100", "0x00001150", "openURL:", ["system_services"], frameworks=["UIKit"]),
        _platform_call("notification-register", "0x00001200", "0x00001210", "addObserver:selector:name:object:", ["system_services"]),
        _platform_call("timer-register", "0x00001200", "0x00001220", "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:", ["system_services"]),
    ])
    platform["facts"]["callback_dependencies"] = [{
        "id": "platform-dependency-table-delegate",
        "kind": "protocol_callback",
        "classification": "exact",
        "selector": "tableView:didSelectRowAtIndexPath:",
        "protocol_name": "UITableViewDelegate",
        "callback_contract": "UITableViewDelegate::tableView:didSelectRowAtIndexPath:",
        "affected_method_ids": ["method:did-select"],
        "affected_function_ids": ["0x00001300"],
        "affected_class_names": ["ExampleController"],
        "failure_reasons": [],
    }]
    platform["facts"]["dependencies"] = [{
        "id": "platform-dependency-sqlite",
        "kind": "imported_function",
        "classification": "exact",
        "symbol": "_sqlite3_step",
        "categories": ["persistence"],
        "frameworks": ["SQLite"],
        "affected_function_ids": ["0x00001100"],
        "call_sites": ["0x00001160"],
        "failure_reasons": [],
    }]
    write_json_atomic(platform_path, platform)

    native = report_envelope(
        "native-type-flow",
        {
            "field_accesses": [
                {
                    "id": "native-field-access:read-count",
                    "function_id": "0x00001100",
                    "field_value_id": "native-value:count",
                    "access_kind": "read",
                    "offset": 8,
                    "width": 4,
                    "expression": "self->_count",
                    "pseudocode_line": 2,
                    "classification": "exact",
                    "failure_reasons": [],
                },
                {
                    "id": "native-field-access:write-count",
                    "function_id": "0x00001100",
                    "field_value_id": "native-value:count",
                    "access_kind": "write",
                    "offset": 8,
                    "width": 4,
                    "expression": "self->_count = oldCount + 1",
                    "pseudocode_line": 3,
                    "classification": "exact",
                    "failure_reasons": [],
                },
            ],
            "globals": [{
                "id": "native-global:flag",
                "address": "0x00002000",
                "exact_symbols": ["DAT_00002000"],
                "references": [{
                    "function_id": "0x00001100",
                    "path": "decompiled/functions/00001100.c",
                    "pseudocode_line": 4,
                    "label": "DAT_00002000",
                }, {
                    "function_id": "0x00001600",
                    "path": "decompiled/functions/00001600.c",
                    "pseudocode_line": 1,
                    "label": "DAT_00002000",
                }],
                "classification": "exact",
                "failure_reasons": [],
            }],
        },
    )
    write_json_atomic(analysis / "native-type-flow.json", native)
    recover_ui(workspace)
    return workspace


class InteractionRecoveryTests(unittest.TestCase):
    def test_recovers_all_trigger_and_effect_families_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_interaction_workspace(Path(temporary))
            preserved = {
                path: path.read_bytes()
                for path in (workspace / "analysis").glob("*.json")
            }
            first = recover_interactions(workspace)
            model_bytes = first.interaction_model_path.read_bytes()
            report_bytes = first.report_path.read_bytes()
            second = recover_interactions(workspace)

            self.assertEqual(model_bytes, second.interaction_model_path.read_bytes())
            self.assertEqual(report_bytes, second.report_path.read_bytes())
            for path, contents in preserved.items():
                self.assertEqual(contents, path.read_bytes(), path)

            facts = second.interaction_model["facts"]
            trigger_kinds = {item["kind"] for item in facts["triggers"]}
            self.assertEqual(
                {"ui_action", "lifecycle", "delegate", "notification", "timer", "callback"},
                trigger_kinds,
            )
            effect_kinds = {item["kind"] for item in facts["effects"]}
            self.assertTrue({
                "state_read", "state_write", "navigation", "ui_update",
                "persistence_read", "persistence_write", "persistence_access",
                "network_request", "notification_post", "timer_schedule", "platform_api",
            }.issubset(effect_kinds))

            action = next(item for item in facts["triggers"] if item["selector"] == "didTap:")
            self.assertEqual("exact", action["classification"])
            action_slice = next(item for item in facts["call_slices"] if item["trigger_id"] == action["id"])
            self.assertIn("0x00001100", {item["function_id"] for item in action_slice["nodes"]})
            dynamic = next(item for item in action_slice["edges"] if item["kind"] == "objective_c_dynamic")
            self.assertEqual("candidate_set", dynamic["classification"])
            action_chain = next(item for item in facts["interactions"] if item["trigger_id"] == action["id"])
            action_effects = [item for item in facts["effects"] if item["id"] in action_chain["effect_ids"]]
            self.assertTrue(any(item["kind"] == "network_request" for item in action_effects))
            self.assertTrue(any(item["kind"] == "state_write" for item in action_effects))
            persistence = next(item for item in action_effects if item["selector"] == "setObject:forKey:")
            self.assertEqual(["value", "savedKey"], persistence["details"]["literal_arguments"])
            self.assertTrue(all(
                item["classification"] == "candidate_set"
                for item in persistence["details"]["resource_candidates"]
            ))

            notification = next(item for item in facts["triggers"] if item["kind"] == "notification")
            self.assertEqual("handleRefresh:", notification["selector"])
            self.assertEqual("RefreshNotification", notification["notification_name"])
            timer = next(item for item in facts["triggers"] if item["kind"] == "timer")
            self.assertEqual("tick:", timer["selector"])
            self.assertEqual("1.5", timer["timer_interval"])
            callback = next(item for item in facts["triggers"] if item["kind"] == "callback")
            self.assertEqual("candidate_set", callback["classification"])
            callback_effects = [
                item for item in facts["effects"] if item["trigger_id"] == callback["id"]
            ]
            self.assertTrue(callback_effects)
            self.assertTrue(all(
                item["classification"] == "candidate_set" for item in callback_effects
            ))
            self.assertFalse(facts["evidence_boundary"]["application_specific_rules_used"])
            self.assertFalse(facts["evidence_boundary"]["ui_model_reparsed_or_duplicated"])
            report = second.report_path.read_text(encoding="utf-8")
            self.assertIn("trigger → handler → effect", report)
            self.assertIn("### MainScreen", report)

            schema_root = Path(__file__).parents[1] / "schemas"
            registry = Registry()
            for schema_path in schema_root.glob("*.schema.json"):
                contents = json.loads(schema_path.read_text(encoding="utf-8"))
                resource = Resource.from_contents(contents)
                registry = registry.with_resource(contents["$id"], resource)
                registry = registry.with_resource(schema_path.name, resource)
            schema = json.loads((schema_root / "interaction-model.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator(schema, registry=registry).validate(second.interaction_model)

    def test_rejects_pseudocode_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_interaction_workspace(Path(temporary))
            path = workspace / "analysis" / "recovered-code-index.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            function = next(item for item in document["facts"]["functions"] if item["function_id"] == "0x00001000")
            function["decompilation"]["output_path"] = "../outside.c"
            write_json_atomic(path, document)
            with self.assertRaisesRegex(InteractionRecoveryError, "escapes the analysis workspace"):
                recover_interactions(workspace)

    def test_rejects_pseudocode_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = build_interaction_workspace(Path(temporary))
            path = workspace / "analysis" / "recovered-code-index.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            function = next(item for item in document["facts"]["functions"] if item["function_id"] == "0x00001000")
            function["decompilation"]["sha256"] = "0" * 64
            write_json_atomic(path, document)
            with self.assertRaisesRegex(InteractionRecoveryError, "hash mismatch"):
                recover_interactions(workspace)

    def test_rejects_missing_ui_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(InteractionRecoveryError, "missing analysis/functions.json"):
                recover_interactions(Path(temporary))


    def test_cli_recovers_interactions_and_reports_artifacts(self) -> None:
        workspace = Path("workspace")
        result = SimpleNamespace(
            workspace=workspace,
            interaction_model={"facts": {"summary": {
                "trigger_count": 6,
                "interaction_count": 6,
                "effect_count": 12,
                "classification_counts": {"exact": 10, "candidate_set": 8, "unresolved": 6},
            }}},
            interaction_model_path=workspace / "analysis" / "interaction-model.json",
            report_path=workspace / "reports" / "interaction-reconstruction-report.md",
        )
        stdout = io.StringIO()
        with patch("ipalift.cli.recover_interactions", return_value=result) as recover:
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["recover-interactions", str(workspace)])
        self.assertEqual(0, exit_code)
        recover.assert_called_once_with(workspace)
        output = stdout.getvalue()
        self.assertIn("Triggers: 6; interactions: 6; effects: 12", output)
        self.assertIn(str(result.interaction_model_path), output)
        self.assertIn(str(result.report_path), output)
if __name__ == "__main__":
    unittest.main()
