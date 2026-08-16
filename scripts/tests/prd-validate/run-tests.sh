#!/usr/bin/env bash
# Runs a PRD-validator self-test. See
# scripts/tests/prd-validate/prd_validate_selftest.py for what each assertion
# guards against and why this validator ran in no workflow until now.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

PYTHON="python3"
command -v python3.12 >/dev/null 2>&1 && PYTHON="python3.12"

exec "$PYTHON" scripts/tests/prd-validate/prd_validate_selftest.py
