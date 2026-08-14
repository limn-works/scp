#!/usr/bin/env bash
# check-pyi-generated.sh — CI gate enforcing that the Python type stub
# `bindings/python/scp_sdk/_scp_core.pyi` is in signature parity with the
# authoritative PyO3 exports in `crates/scp-ffi/src/`.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# The hand-maintained `.pyi` has repeatedly drifted from the real
# `#[pyfunction]` / `#[pymethods]` signatures with NO mechanical check. PyO3
# binds positional parameters by declaration order (absent an explicit
# `#[pyo3(signature = ...)]`), so the Rust parameter names, order, and arity
# are ground truth for the Python-visible keyword surface. When they diverge,
# the drift is invisible to mypy/pyright because the stub itself is what those
# tools trust. Concretely: after `verify_participation_requirements` was
# realigned to `(expected_subject, requirements_json, profile_json)`, the stub
# was left declaring the two adjacent `str` params transposed — a shipped,
# type-checker-invisible defect. This gate closes that class.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# It runs the generator (`scripts/generate-pyi.py`) in `--check` mode, which:
#   (1) parses the PyO3 exports from the Rust source (tree-sitter), and the
#       committed `.pyi` (Python `ast`);
#   (2) asserts SET PARITY — every export has a stub and every stubbed symbol
#       (outside a small justified allowlist) is a real export (no missing /
#       extra methods, free functions, or getters);
#   (3) reconciles each stub signature's positional parameter NAMES, ORDER,
#       and ARITY against the authoritative Rust signature, then normalizes
#       with `ruff format`, and fails if the committed stub differs byte-for-
#       byte from that regenerated form.
# Because both the committed stub and the regenerated candidate pass through
# the SAME `ruff format`, the comparison is formatting-stable: only a genuine
# signature difference (name / order / arity) can produce a diff.
#
# This gate needs only the Rust source and the `.pyi` — it does NOT build the
# extension (`maturin develop`), so it is fast and cheap in CI.
#
# ---------------------------------------------------------------------------
# ENFORCEMENT FILE (see CLAUDE.md)
# ---------------------------------------------------------------------------
# Do not weaken this gate to hide drift. The only legitimate change is to
# regenerate the stub (`python3.12 scripts/generate-pyi.py`) after changing a
# Rust export, and commit the result. Expanding coverage is always fine.
#
# Usage:
#   bash scripts/check-pyi-generated.sh              # verify the committed tree
#   bash scripts/check-pyi-generated.sh --self-test  # prove the gate rejects
#                                                     # a deliberately-drifted stub
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="${REPO_ROOT}/scripts/generate-pyi.py"
PYI="${REPO_ROOT}/bindings/python/scp_sdk/_scp_core.pyi"

PY="${PYTHON:-python3.12}"

if [[ ! -f "${GENERATOR}" ]]; then
  echo "error: generator not found at ${GENERATOR}" >&2
  exit 1
fi
if [[ ! -f "${PYI}" ]]; then
  echo "error: stub not found at ${PYI}" >&2
  exit 1
fi

if [[ "${1:-}" == "--self-test" ]]; then
  # Prove the gate is alive: plant a deliberate parameter TRANSPOSITION in the
  # committed stub, confirm `--check` REJECTS it, then restore the file exactly.
  # A trap guarantees the original stub is restored even if the check aborts.
  BACKUP="$(mktemp)"
  cp "${PYI}" "${BACKUP}"
  # shellcheck disable=SC2064
  trap "cp '${BACKUP}' '${PYI}'; rm -f '${BACKUP}'" EXIT

  # Transpose the first two positional parameters of the
  # `check_capability_requirements` free function. Their names differ, so the
  # generator's name-keyed reconciliation heals the order back to the Rust
  # signature and the byte comparison against the on-disk (transposed) stub
  # fails — exactly the drift this gate must catch.
  "${PY}" - "${PYI}" <<'PY'
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()
old = (
    "def check_capability_requirements(\n"
    "    context_id: str,\n"
    "    subject_did: str,\n"
)
new = (
    "def check_capability_requirements(\n"
    "    subject_did: str,\n"
    "    context_id: str,\n"
)
if old not in text:
    sys.exit(
        "self-test anchor not found: the `check_capability_requirements` "
        "signature shape changed; update scripts/check-pyi-generated.sh"
    )
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY

  if "${PY}" "${GENERATOR}" --check >/dev/null 2>&1; then
    echo "SELF-TEST FAILED: the gate PASSED on a transposed stub — it is not enforcing parity." >&2
    exit 1
  fi
  echo "self-test OK: the gate correctly REJECTED a deliberately-transposed stub."
  exit 0
fi

exec "${PY}" "${GENERATOR}" --check
