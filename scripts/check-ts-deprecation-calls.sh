#!/usr/bin/env bash
# check-ts-deprecation-calls.sh
#
# Enforces that every top-level `export (async) function` in
# `bindings/typescript/src/` that belongs to a module routing through the
# process-wide default bridge calls `deprecatedDefaultInstance(<name>)`
# at the top of its body.
#
# The simplifier review on #1549 Phase 4 PR 1 (ADR-048) flagged inline
# `deprecatedDefaultInstance("…")` calls at the top of every free
# function as a "forgot-to-add-the-line" footgun. We picked the
# lightweight enforcement path (this gate) over a HOF refactor to avoid
# touching dozens of call sites and potentially breaking the exported
# SDK shape; this script ensures no new free function in a
# deprecation-bearing module slips through without the call.
#
# Allowlisted files (see `check-ts-deprecation-calls.py`) export free
# functions that intentionally do NOT route through the default bridge
# — pure helpers, static class members, or re-exports.
#
# Exit 0: every monitored free function calls `deprecatedDefaultInstance`.
# Exit 1: at least one free function is missing the call.

set -euo pipefail

# Resolve to the python3 that mise/env provides.
PY=python3
if command -v python3.12 >/dev/null 2>&1; then
    PY=python3.12
fi

exec "$PY" "$(dirname "$0")/check-ts-deprecation-calls.py" "$@"
