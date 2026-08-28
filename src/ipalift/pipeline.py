"""End-to-end IPALift analysis orchestration."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .archive import bundle_metadata, extract_and_inventory
from .errors import InvalidIPAError
from .macho import parse_macho_file
from .objc import analyze_objective_c
from .plugins import AnalysisPlugin, PluginContext, run_plugins
from .report import render_report
from .util import report_envelope, sha256_file, write_json_atomic, write_text_atomic


@dataclass(frozen=True)
class AnalysisPaths:
    output_root: Path
    analysis_root: Path
    report_path: Path


@dataclass
class AnalysisResult:
    paths: AnalysisPaths
    reports: dict[str, dict[str, Any]]


def _prepare_output(ipa_path: Path, output_path: Path) -> AnalysisPaths:
    try:
        source = ipa_path.resolve(strict=True)
    except OSError as exc:
        raise InvalidIPAError(f"Cannot access source IPA {ipa_path}: {exc}") from exc
    if not source.is_file():
        raise InvalidIPAError(f"Input is not a file: {source}")
    output = output_path.resolve()
    if output == source:
        raise InvalidIPAError("Output path cannot be the source IPA")
    if output.exists() and not output.is_dir():
        raise InvalidIPAError(f"Output path exists and is not a directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    analysis_root = output / "analysis"
    report_path = output / "reports" / "analysis-report.md"
    analysis_root.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    return AnalysisPaths(output, analysis_root, report_path)


def analyze_ipa(
    ipa_path: Path,
    output_path: Path,
    *,
    plugins: tuple[AnalysisPlugin, ...] = (),
) -> AnalysisResult:
    paths = _prepare_output(ipa_path, output_path)
    extraction = extract_and_inventory(ipa_path, paths.output_root)
    executable_path = extraction.evidence_root.joinpath(*extraction.bundle.executable_path.split("/"))
    executable_sha256 = sha256_file(executable_path)
    macho = parse_macho_file(executable_path)
    objc = analyze_objective_c(macho)

    plugin_context = PluginContext(extraction.bundle, executable_path, extraction.evidence_root, macho)
    plugin_results = run_plugins(plugin_context, plugins)
    plugin_facts = {name: result.facts for name, result in plugin_results.items()}
    plugin_hypotheses = [
        {"plugin": name, **hypothesis}
        for name, result in plugin_results.items()
        for hypothesis in result.hypotheses
    ]
    plugin_errors = [
        {"plugin": name, **error}
        for name, result in plugin_results.items()
        for error in result.errors
    ]

    extraction.source.assert_unchanged()
    application_facts = {
        "tool": {"name": "ipalift", "version": __version__},
        "source": {
            "file_name": extraction.source.path.name,
            "size": extraction.source.size,
            "sha256": extraction.source.sha256,
            "format": "ipa-zip",
            "preserved_unchanged": True,
        },
        "archive": {
            "file_count": len(extraction.files),
            "total_uncompressed_bytes": extraction.total_uncompressed_bytes,
            "extraction_root": "evidence/extracted",
        },
        "bundle": bundle_metadata(extraction.bundle),
        "executable": {
            "archive_path": extraction.bundle.executable_path,
            "size": executable_path.stat().st_size,
            "sha256": executable_sha256,
        },
        "plugins": plugin_facts,
    }
    architecture_facts = macho.architecture_facts
    framework_facts = macho.framework_facts
    category_counts = Counter(record["asset_category"] for record in extraction.assets)
    asset_facts = {
        "file_count": len(extraction.files),
        "asset_count": len(extraction.assets),
        "total_uncompressed_bytes": extraction.total_uncompressed_bytes,
        "category_counts": dict(sorted(category_counts.items())),
        "files": extraction.files,
        "assets": extraction.assets,
    }

    unresolved_items: list[dict[str, Any]] = list(extraction.issues)
    for macho_slice in macho.slices:
        if macho_slice.deployment_target is None:
            unresolved_items.append({
                "code": "macho_deployment_target_absent",
                "severity": "info",
                "architecture": macho_slice.architecture_name,
                "message": "Mach-O has no deployment-target load command; consult verified Info.plist metadata",
            })
        if not macho_slice.encryption["command_present"]:
            unresolved_items.append({
                "code": "macho_encryption_command_absent",
                "severity": "warning",
                "architecture": macho_slice.architecture_name,
                "message": "Mach-O has no encryption-info command, so encryption state is unknown",
            })
        elif macho_slice.encryption["is_encrypted"]:
            unresolved_items.append({
                "code": "macho_executable_encrypted",
                "severity": "error",
                "architecture": macho_slice.architecture_name,
                "message": "Mach-O cryptid is nonzero; code bytes remain encrypted",
            })
    for error in objc["errors"]:
        unresolved_items.append({
            "code": error["code"],
            "severity": "warning",
            "architecture": error.get("architecture"),
            "address": error.get("address"),
            "message": error["message"],
        })
    for error in plugin_errors:
        unresolved_items.append({
            "code": error.get("code", "plugin_error"),
            "severity": error.get("severity", "warning"),
            "plugin": error["plugin"],
            "message": error.get("message", "Plugin reported an unspecified error"),
        })
    unresolved_items.sort(
        key=lambda item: (item["severity"], item["code"], item.get("architecture") or "", item.get("address") or -1)
    )
    unresolved_facts = {"item_count": len(unresolved_items), "items": unresolved_items}

    reports = {
        "application": report_envelope("application", application_facts),
        "architectures": report_envelope("architectures", architecture_facts),
        "frameworks": report_envelope("frameworks", framework_facts),
        "classes": report_envelope(
            "classes", objc["facts"], hypotheses=objc["hypotheses"], errors=objc["errors"]
        ),
        "assets": report_envelope("assets", asset_facts),
        "unresolved": report_envelope(
            "unresolved", unresolved_facts, hypotheses=plugin_hypotheses, errors=plugin_errors
        ),
    }
    for name, value in reports.items():
        write_json_atomic(paths.analysis_root / f"{name}.json", value)
    human_report = render_report(
        application_facts,
        architecture_facts,
        framework_facts,
        objc["facts"],
        asset_facts,
        unresolved_facts,
    )
    write_text_atomic(paths.report_path, human_report)
    extraction.source.assert_unchanged()
    return AnalysisResult(paths, reports)
