#!/usr/bin/env bash
# Runs a CI-gate self-test. A `ci` job is one status check this repository's
# ruleset requires, so logic deciding that job carries its own tests: see
# scripts/tests/ci-gate/ci_gate_selftest.py for what each assertion guards
# against.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

PYTHON="python3"
command -v python3.12 >/dev/null 2>&1 && PYTHON="python3.12"

exec "$PYTHON" scripts/tests/ci-gate/ci_gate_selftest.py
