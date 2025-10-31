#!/usr/bin/env python3
"""Run the MASVS quick check from the command line."""

from pathlib import Path
import argparse
import json

from mobsf.quick_check import evaluate, render_console, write_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run MASVS quick compliance check")
    parser.add_argument(
        "--controls",
        type=Path,
        default=Path("docs/security/masvs_controls.json"),
        help="Path to MASVS control definitions",
    )
    parser.add_argument(
        "--overrides",
        type=Path,
        help="Optional JSON file containing automated overrides",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON report output path",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    overrides = None
    if args.overrides:
        overrides = json.loads(args.overrides.read_text(encoding="utf-8"))
    results = evaluate(args.controls, overrides)
    print(render_console(results))
    if args.output:
        write_report(results, args.output)


if __name__ == "__main__":
    main()
