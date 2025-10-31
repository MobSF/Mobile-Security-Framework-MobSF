#!/usr/bin/env bash
set -euo pipefail

pytest tests/security tests/storage tests/crypto tests/network tests/masvs -q --json-report --json-report-file=docs/security/reports/mastg_test_report.json "$@"
