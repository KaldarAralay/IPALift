"""Ordered orchestration for a complete IPALift analysis run."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cpp_model import recover_cpp_model
from .dispatch import resolve_objc_dispatch
from .ghidra import decompile_workspace
from .native_types import infer_native_types
from .pipeline import analyze_ipa
from .platform_apis import map_platform_apis
from .recovery import recover_objc_workspace
from .typeflow import infer_objc_types


FULL_RUN_STAGES = (
    "analyze",
    "decompile",
    "recover-objc",
    "resolve-objc-dispatch (pass 1)",
    "infer-objc-types (pass 1)",
    "resolve-objc-dispatch (pass 2)",
    "infer-objc-types (pass 2)",
    "map-platform-apis",
    "recover-cpp-model",
    "infer-native-types",
)

StageCallback = Callable[[int, int, str], None]


@dataclass(frozen=True)
class FullRunResult:
    workspace: Path
    completed_stages: tuple[str, ...]
    final_report_path: Path


def run_full_pipeline(
    ipa_path: Path,
    output_path: Path,
    *,
    ghidra_home: Path | None = None,
    function_timeout: int = 30,
    analysis_timeout: int = 3600,
    on_stage: StageCallback | None = None,
) -> FullRunResult:
    """Run every IPALift stage in dependency order and stop on the first error."""
    completed: list[str] = []

    def execute(index: int, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        stage = FULL_RUN_STAGES[index - 1]
        if on_stage is not None:
            on_stage(index, len(FULL_RUN_STAGES), stage)
        result = function(*args, **kwargs)
        completed.append(stage)
        return result

    analysis = execute(1, analyze_ipa, ipa_path, output_path)
    workspace = analysis.paths.output_root
    execute(
        2,
        decompile_workspace,
        workspace,
        ghidra_home=ghidra_home,
        function_timeout=function_timeout,
        analysis_timeout=analysis_timeout,
    )
    execute(3, recover_objc_workspace, workspace)
    execute(4, resolve_objc_dispatch, workspace)
    execute(5, infer_objc_types, workspace)
    execute(6, resolve_objc_dispatch, workspace)
    execute(7, infer_objc_types, workspace)
    execute(8, map_platform_apis, workspace)
    execute(9, recover_cpp_model, workspace)
    final = execute(10, infer_native_types, workspace)
    return FullRunResult(workspace, tuple(completed), final.report_path)
