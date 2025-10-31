#!/usr/bin/env bash
set -euo pipefail

poetry export -f requirements.txt --with dev | pip install --quiet --upgrade pip pip-audit >/dev/null
pip-audit "$@"

yarn --version >/dev/null 2>&1 && yarn outdated || echo "Yarn not available; skipping JS dependency audit" >&2
