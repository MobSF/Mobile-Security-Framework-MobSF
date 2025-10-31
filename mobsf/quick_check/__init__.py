"""MASVS quick compliance checker CLI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class ControlResult:
    """Represents a MASVS control outcome."""

    control: str
    description: str
    passed: bool
    notes: str

    def to_dict(self) -> dict[str, object]:
        return {
            "control": self.control,
            "description": self.description,
            "status": "OK" if self.passed else "FAIL",
            "notes": self.notes,
        }


def evaluate(defaults_path: Path, overrides: dict[str, bool] | None = None) -> list[ControlResult]:
    """Return the evaluation results for MASVS controls.

    Parameters
    ----------
    defaults_path: Path
        Path to the JSON file with default control expectations.
    overrides: dict[str, bool] | None
        Optional overrides coming from automated scanners.
    """

    data = json.loads(defaults_path.read_text(encoding="utf-8"))
    overrides = overrides or {}
    results: list[ControlResult] = []
    for control in data["controls"]:
        control_id = control["id"]
        passed = overrides.get(control_id, control.get("default_pass", False))
        results.append(
            ControlResult(
                control=control_id,
                description=control["description"],
                passed=passed,
                notes=control.get("notes", ""),
            )
        )
    return results


def render_console(results: Iterable[ControlResult]) -> str:
    """Render results as a console table."""

    lines = ["CONTROL\tSTATUS\tNOTES"]
    for result in results:
        lines.append(f"{result.control}\t{'OK' if result.passed else 'FAIL'}\t{result.notes}")
    return "\n".join(lines)


def write_report(results: Iterable[ControlResult], output_path: Path) -> None:
    """Write the results to a JSON file."""

    payload = [result.to_dict() for result in results]
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


__all__ = [
    "ControlResult",
    "evaluate",
    "render_console",
    "write_report",
]
