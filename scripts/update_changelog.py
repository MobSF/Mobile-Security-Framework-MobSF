#!/usr/bin/env python3
"""Append entries to the changelog."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path


CHANGELOG = Path("CHANGELOG.md")


def append_entry(summary: str) -> None:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d")
    entry = f"- {timestamp} {summary}\n"
    content = CHANGELOG.read_text(encoding="utf-8")
    if "## [Unreleased]" not in content:
        raise SystemExit("Missing [Unreleased] section in changelog")
    updated = content.replace("## [Unreleased]\n", f"## [Unreleased]\n{entry}")
    CHANGELOG.write_text(updated, encoding="utf-8")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("summary", help="Changelog summary line")
    args = parser.parse_args()
    append_entry(args.summary)


if __name__ == "__main__":
    main()
