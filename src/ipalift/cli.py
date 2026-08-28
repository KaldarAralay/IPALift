"""Command-line interface for IPALift."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .cpp_model import recover_cpp_model
from .dispatch import resolve_objc_dispatch
from .errors import IPALiftError
from .ghidra import decompile_workspace
from .native_types import infer_native_types
from .pipeline import analyze_ipa
from .platform_apis import map_platform_apis
from .recovery import recover_objc_workspace
from .typeflow import infer_objc_types


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipalift",
        description="Analyze a decrypted iOS IPA into deterministic, evidence-linked reports.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    analyze = subcommands.add_parser("analyze", help="validate, extract, and analyze an IPA")
    analyze.add_argument("ipa", type=Path, help="path to a legally obtained decrypted IPA")
    analyze.add_argument("--output", "-o", type=Path, required=True, help="analysis output directory")
    decompile = subcommands.add_parser(
        "decompile", help="run deterministic headless Ghidra analysis on an IPALift workspace"
    )
    decompile.add_argument("workspace", type=Path, help="existing output directory from ipalift analyze")
    decompile.add_argument(
        "--ghidra-home", type=Path, help="Ghidra installation directory (otherwise use GHIDRA_HOME or tools/ghidra)"
    )
    decompile.add_argument(
        "--function-timeout", type=int, default=30, help="decompiler timeout per function in seconds (default: 30)"
    )
    decompile.add_argument(
        "--analysis-timeout", type=int, default=3600, help="Ghidra auto-analysis timeout in seconds (default: 3600)"
    )
    recover = subcommands.add_parser(
        "recover-objc", help="organize existing decompilation evidence into Objective-C views"
    )
    recover.add_argument(
        "workspace", type=Path, help="existing IPALift workspace containing Ghidra analysis reports"
    )
    dispatch = subcommands.add_parser(
        "resolve-objc-dispatch",
        help="infer evidence-bounded Objective-C message targets without changing the direct call graph",
    )
    dispatch.add_argument(
        "workspace", type=Path, help="existing IPALift workspace containing recovered Objective-C reports"
    )
    type_flow = subcommands.add_parser(
        "infer-objc-types",
        help="propagate evidence-bounded Objective-C and native types to a deterministic fixed point",
    )
    type_flow.add_argument(
        "workspace", type=Path, help="existing IPALift workspace containing Objective-C dispatch reports"
    )
    platform_apis = subcommands.add_parser(
        "map-platform-apis",
        help="map evidence-linked iOS and third-party platform dependencies for compatibility planning",
    )
    platform_apis.add_argument(
        "workspace",
        type=Path,
        help="existing IPALift workspace containing Objective-C type-flow reports",
    )
    cpp_model = subcommands.add_parser(
        "recover-cpp-model",
        help="recover evidence-bounded C++ ABI object models and virtual dispatch",
    )
    cpp_model.add_argument(
        "workspace",
        type=Path,
        help="existing IPALift workspace containing normalized analysis reports",
    )
    native_types = subcommands.add_parser(
        "infer-native-types",
        help="propagate evidence-bounded native/C++ types and numeric data layouts",
    )
    native_types.add_argument(
        "workspace",
        type=Path,
        help="existing IPALift workspace containing the C++ object-model report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "analyze":
            result = analyze_ipa(args.ipa, args.output)
            application = result.reports["application"]["facts"]
            classes = result.reports["classes"]["facts"]
            print(f"Analyzed {application['bundle']['display_name'] or application['bundle']['bundle_name']}")
            print(f"Output: {result.paths.output_root}")
            print(f"Architectures: {result.reports['architectures']['facts']['architecture_count']}")
            print(f"Objective-C classes: {classes['total_classes']}")
            print(f"Assets: {result.reports['assets']['facts']['asset_count']}")
            print(f"Report: {result.paths.report_path}")
            return 0
        if args.command == "decompile":
            result = decompile_workspace(
                args.workspace,
                ghidra_home=args.ghidra_home,
                function_timeout=args.function_timeout,
                analysis_timeout=args.analysis_timeout,
            )
            functions = result.reports["functions"]["facts"]
            decompilation = result.reports["decompilation"]["facts"]
            print(f"Decompiled workspace with Ghidra {result.ghidra_version}")
            print(f"Workspace: {result.workspace}")
            print(f"Discovered functions: {functions['discovered_function_count']}")
            print(
                f"Successful decompilations: {decompilation['success_count']}/"
                f"{decompilation['eligible_internal_non_thunk_count']}"
            )
            print(f"Report: {result.report_path}")
            return 0
        if args.command == "recover-objc":
            result = recover_objc_workspace(args.workspace)
            facts = result.index["facts"]
            print(f"Organized Objective-C evidence in {result.workspace}")
            print(f"Indexed functions: {facts['function_count']}")
            print(
                f"Objective-C methods: {facts['mapped_objective_c_method_count']}/"
                f"{facts['objective_c_method_count']} mapped"
            )
            print(f"Generated views: {facts['generated_file_count']}")
            print(f"Report: {result.report_path}")
            return 0
        if args.command == "resolve-objc-dispatch":
            result = resolve_objc_dispatch(args.workspace)
            facts = result.dispatch["facts"]
            counts = facts["classification_counts"]
            print(f"Analyzed Objective-C dispatch in {result.workspace}")
            print(f"Dispatch callsites: {facts['dispatch_callsite_count']}")
            print(
                f"Resolved: {counts['resolved']}; candidate sets: {counts['candidate_set']}; "
                f"unresolved: {counts['unresolved']}"
            )
            print(f"Inferred edges: {facts['inferred_edge_count']}")
            print(f"Report: {result.report_path}")
            return 0
        if args.command == "infer-objc-types":
            result = infer_objc_types(args.workspace)
            facts = result.type_flow["facts"]
            counts = facts["classification_counts"]
            print(f"Inferred Objective-C type flow in {result.workspace}")
            print(f"Type values: {facts['value_count']}")
            print(
                f"Exact: {counts['exact']}; candidate sets: {counts['candidate_set']}; "
                f"unresolved: {counts['unresolved']}"
            )
            print(
                f"Fixed point: {facts['fixed_point']['iteration_count']} iterations; "
                f"{facts['fixed_point']['cyclic_component_count']} cyclic components"
            )
            print(f"Dispatch refinements: {facts['dispatch_refinement_count']}")
            print(f"Report: {result.report_path}")
            return 0
        if args.command == "map-platform-apis":
            result = map_platform_apis(args.workspace)
            facts = result.platform_map["facts"]
            summary = facts["summary"]
            counts = summary["classification_counts"]
            print(f"Mapped platform APIs in {result.workspace}")
            print(f"Dependencies: {summary['dependency_count']}")
            print(
                f"Exact: {counts['exact']}; candidate sets: {counts['candidate_set']}; "
                f"unresolved: {counts['unresolved']}"
            )
            print(f"Objective-C message callsites: {summary['message_callsite_count']}")
            print(f"Catalog version: {facts['catalog']['catalog_version']}")
            print(f"Report: {result.report_path}")
            return 0
        if args.command == "recover-cpp-model":
            result = recover_cpp_model(args.workspace)
            facts = result.cpp_model["facts"]
            summary = facts["summary"]
            counts = summary["classification_counts"]
            print(f"Recovered C++ object models in {result.workspace}")
            print(f"Classes: {summary['class_count']}; vtables: {summary['vtable_count']}")
            print(
                f"Exact: {counts['exact']}; candidate sets: {counts['candidate_set']}; "
                f"unresolved: {counts['unresolved']}"
            )
            print(f"Indirect callsites: {summary['indirect_callsite_count']}")
            print(f"Report: {result.report_path}")
            return 0
        if args.command == "infer-native-types":
            result = infer_native_types(args.workspace)
            summary = result.native_type_flow["facts"]["summary"]
            counts = summary["classification_counts"]
            print(f"Inferred native types and layouts in {result.workspace}")
            print(f"Values: {summary['value_count']}; layouts: {summary['layout_count']}")
            print(
                f"Exact: {counts['exact']}; candidate sets: {counts['candidate_set']}; "
                f"unresolved: {counts['unresolved']}"
            )
            print(
                f"Virtual refinements: {summary['virtual_refinement_count']}; "
                f"changed: {summary['changed_virtual_refinement_count']}"
            )
            print(f"Report: {result.report_path}")
            return 0
    except IPALiftError as exc:
        print(f"ipalift: error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ipalift: I/O error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ipalift: interrupted", file=sys.stderr)
        return 130
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
