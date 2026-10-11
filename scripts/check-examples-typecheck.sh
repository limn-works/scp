#!/usr/bin/env bash
# check-examples-typecheck.sh — every Python and TypeScript example, scaffold and
# template type-checks against the SDK source in this tree.
#
# CRITERION. Every tracked `.py` file and every tracked `.ts` file under
# `docs/examples/`, `scaffolds/` and `templates/` passes `mypy --strict` (Python)
# or `tsc --noEmit` (TypeScript), resolving `scp_sdk` to `bindings/python/scp_sdk`
# and `@limn-works/scp-ts` to `bindings/typescript/src/index.ts`. A site that calls
# an SDK method the SDK no longer defines, passes an argument of the wrong type, or
# reads an attribute the returned object lacks fails this gate.
#
# One exclusion: `scaffolds/typescript-web/` imports `@limn-works/scp-ts-wasm`, the
# in-browser package (ADR-057), and the `scaffold-typescript-web-check` job of
# `.github/workflows/ci.yml` type-checks it against that package.
#
# The file list comes from `git ls-files`, so a site added under those directories
# is checked without an edit here. The gate fails closed: when either list is
# empty, when mypy is missing, or when `bindings/typescript/node_modules` lacks the
# TypeScript compiler, it exits 1 and says what to install.
#
# Setup: `pip install mypy==1.20.2` (the version the `python-test` job pins) and
# `bun install` in `bindings/typescript`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3.12}"
CONF_DIR="$ROOT/scripts/examples-typecheck"
TSC="$ROOT/bindings/typescript/node_modules/typescript/bin/tsc"

py_files=()
ts_files=()
while IFS= read -r f; do
    case $f in
        scaffolds/typescript-web/*) ;;
        *.py) py_files+=("$f") ;;
        *.ts) ts_files+=("$f") ;;
    esac
done < <(git ls-files -- 'docs/examples/*.py' 'docs/examples/*.ts' 'scaffolds/*.py' \
    'scaffolds/*.ts' 'templates/*.py' 'templates/*.ts')

fail=0
if [[ ${#py_files[@]} -eq 0 ]]; then
    echo "check-examples-typecheck: FAIL: git ls-files found no Python site, so mypy would check nothing" >&2
    fail=1
fi
if [[ ${#ts_files[@]} -eq 0 ]]; then
    echo "check-examples-typecheck: FAIL: git ls-files found no TypeScript site, so tsc would check nothing" >&2
    fail=1
fi
if ! "$PY" -m mypy --version >/dev/null 2>&1; then
    echo "check-examples-typecheck: FAIL: $PY cannot run mypy. Install it with: $PY -m pip install mypy==1.20.2" >&2
    fail=1
fi
if [[ ! -f $TSC ]]; then
    echo "check-examples-typecheck: FAIL: $TSC is missing. Run: (cd bindings/typescript && bun install)" >&2
    fail=1
fi
if ! command -v bun >/dev/null 2>&1; then
    echo "check-examples-typecheck: FAIL: bun is not on PATH, and it runs the TypeScript compiler" >&2
    fail=1
fi
[[ $fail -eq 0 ]] || exit 1

echo "check-examples-typecheck: mypy over ${#py_files[@]} Python site(s)"
if ! MYPYPATH="$ROOT/bindings/python" "$PY" -m mypy --config-file "$CONF_DIR/mypy.ini" \
    --no-incremental "${py_files[@]}"; then
    fail=1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
{
    printf '{\n  "extends": "%s",\n  "files": [\n' "$CONF_DIR/tsconfig.base.json"
    for i in "${!ts_files[@]}"; do
        sep=","
        [[ $i -eq $((${#ts_files[@]} - 1)) ]] && sep=""
        printf '    "%s"%s\n' "$ROOT/${ts_files[$i]}" "$sep"
    done
    printf '  ]\n}\n'
} > "$tmp/tsconfig.json"

echo "check-examples-typecheck: tsc --noEmit over ${#ts_files[@]} TypeScript site(s)"
if ! bun "$TSC" --noEmit -p "$tmp/tsconfig.json"; then
    fail=1
fi

if [[ $fail -ne 0 ]]; then
    echo "check-examples-typecheck: FAIL: a site above calls SDK API that does not type-check" >&2
    exit 1
fi
echo "check-examples-typecheck: OK: ${#py_files[@]} Python and ${#ts_files[@]} TypeScript site(s) type-check against the SDK"
