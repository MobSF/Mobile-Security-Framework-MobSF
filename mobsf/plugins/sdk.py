"""SDK for MobSF plugin developers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class AnalyzerContext(Protocol):
    """Represents available context during plugin execution."""

    app_path: str
    report_dir: str


@dataclass
class PluginMetadata:
    """Metadata describing the plugin."""

    name: str
    version: str
    description: str
    masvs_controls: list[str]


class AnalyzerPlugin(Protocol):
    """Interface for analyzer plugins."""

    metadata: PluginMetadata

    def run_static(self, context: AnalyzerContext) -> None:
        """Run static analysis hooks."""

    def run_dynamic(self, context: AnalyzerContext) -> None:
        """Run dynamic analysis hooks."""


__all__ = ["AnalyzerContext", "PluginMetadata", "AnalyzerPlugin"]
