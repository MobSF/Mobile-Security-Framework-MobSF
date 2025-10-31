#!/usr/bin/env bash
set -euo pipefail

if ! command -v detect-secrets >/dev/null; then
  pip install --quiet detect-secrets
fi

detect-secrets scan "$@"
