#!/usr/bin/env python3
"""Run vulture to detect unused code."""

import subprocess
import sys


def main() -> int:
    return subprocess.call([sys.executable, "-m", "vulture", "mobsf", "--min-confidence", "80"])


if __name__ == "__main__":
    raise SystemExit(main())
