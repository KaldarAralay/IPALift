from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ipalift.full_run import FULL_RUN_STAGES, run_full_pipeline


class FullRunTests(unittest.TestCase):
    def test_runs_every_stage_in_dependency_order_and_forwards_ghidra_options(self) -> None:
        ipa = Path("fixture.ipa")
        requested_output = Path("requested-output")
        workspace = Path("resolved-workspace")
        ghidra_home = Path("ghidra-home")
        report = workspace / "reports" / "reconstruction-handoff-report.md"
        calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        progress: list[tuple[int, int, str]] = []

        def stage(name: str, result: object = SimpleNamespace()) -> object:
            def invoke(*args: object, **kwargs: object) -> object:
                calls.append((name, args, kwargs))
                return result

            return invoke

        analysis_result = SimpleNamespace(paths=SimpleNamespace(output_root=workspace))
        final_result = SimpleNamespace(report_path=report)
        with (
            patch("ipalift.full_run.analyze_ipa", side_effect=stage("analyze", analysis_result)),
            patch("ipalift.full_run.decompile_workspace", side_effect=stage("decompile")),
            patch("ipalift.full_run.recover_objc_workspace", side_effect=stage("recover-objc")),
            patch("ipalift.full_run.resolve_objc_dispatch", side_effect=stage("resolve-objc-dispatch")),
            patch("ipalift.full_run.infer_objc_types", side_effect=stage("infer-objc-types")),
            patch("ipalift.full_run.map_platform_apis", side_effect=stage("map-platform-apis")),
            patch("ipalift.full_run.recover_cpp_model", side_effect=stage("recover-cpp-model")),
            patch("ipalift.full_run.infer_native_types", side_effect=stage("infer-native-types")),
            patch("ipalift.full_run.recover_ui", side_effect=stage("recover-ui")),
            patch("ipalift.full_run.recover_interactions", side_effect=stage("recover-interactions")),
            patch("ipalift.full_run.build_handoff", side_effect=stage("build-handoff", final_result)),
        ):
            result = run_full_pipeline(
                ipa,
                requested_output,
                ghidra_home=ghidra_home,
                function_timeout=45,
                analysis_timeout=7200,
                on_stage=lambda index, total, name: progress.append((index, total, name)),
            )

        self.assertEqual(
            [
                "analyze",
                "decompile",
                "recover-objc",
                "resolve-objc-dispatch",
                "infer-objc-types",
                "resolve-objc-dispatch",
                "infer-objc-types",
                "map-platform-apis",
                "recover-cpp-model",
                "infer-native-types",
                "recover-ui",
                "recover-interactions",
                "build-handoff",
            ],
            [call[0] for call in calls],
        )
        self.assertEqual((ipa, requested_output), calls[0][1])
        self.assertEqual((workspace,), calls[1][1])
        self.assertEqual(
            {
                "ghidra_home": ghidra_home,
                "function_timeout": 45,
                "analysis_timeout": 7200,
            },
            calls[1][2],
        )
        self.assertTrue(all(call[1] == (workspace,) for call in calls[2:]))
        self.assertEqual(
            [(index, len(FULL_RUN_STAGES), name) for index, name in enumerate(FULL_RUN_STAGES, 1)],
            progress,
        )
        self.assertEqual(workspace, result.workspace)
        self.assertEqual(FULL_RUN_STAGES, result.completed_stages)
        self.assertEqual(report, result.final_report_path)


if __name__ == "__main__":
    unittest.main()
