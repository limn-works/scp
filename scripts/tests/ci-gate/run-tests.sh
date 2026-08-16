#!/usr/bin/env bash
# Runs the CI-gate self-test. The `ci` job is the only status check the
# repository ruleset requires, so the logic that decides it carries its own
# tests: see scripts/tests/ci-gate/ci_gate_selftest.py for what each assertion
# guards against.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

PYTHON="python3"
command -v python3.12 >/dev/null 2>&1 && PYTHON="python3.12"

exec "$PYTHON" scripts/tests/ci-gate/ci_gate_selftest.py
