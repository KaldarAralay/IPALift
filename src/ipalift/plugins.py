"""Stable extension seam for target- or engine-specific analyzers.

The MVP intentionally ships without target-specific code. Future game or engine
knowledge can implement this protocol without contaminating the evidence core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .archive import Bundle
from .macho import MachOAnalysis


@dataclass(frozen=True)
class PluginContext:
    bundle: Bundle
    executable_path: Path
    evidence_root: Path
    macho: MachOAnalysis


@dataclass
class PluginResult:
    facts: dict[str, Any] = field(default_factory=dict)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


class AnalysisPlugin(Protocol):
    name: str

    def analyze(self, context: PluginContext) -> PluginResult:
        """Analyze extracted evidence without modifying it."""


def run_plugins(context: PluginContext, plugins: tuple[AnalysisPlugin, ...]) -> dict[str, PluginResult]:
    return {plugin.name: plugin.analyze(context) for plugin in sorted(plugins, key=lambda item: item.name)}
