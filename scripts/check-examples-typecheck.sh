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
# The gate also checks the live migration guides. Every Python and TypeScript code
# block in a tracked `.docs/migration/*.md` guide whose `**Status:**` line begins with
# `live` passes the same check as a standalone module, so a guide that tells an
# upgrader to call a removed SDK member fails here.
# `scripts/examples-typecheck/guide_blocks.py` writes the blocks out. It leaves a block
# out only when the line directly above the block's opening fence reads
# `<!-- examples-typecheck: skip: REASON -->`, and it prints every skipped block, every
# block in another language, and every guide that is not live, each with its guide,
# line and reason, so a reviewer reads every block this gate did not check. The gate
# loads the `bun` types for guide blocks as well, because the guides' TypeScript test
# recipe runs under `bun test`. `scripts/tests/examples-typecheck/run-tests.sh` feeds
# this gate guides that must pass and guides that must fail.
#
# One exclusion: `scaffolds/typescript-web/` imports `@limn-works/scp-ts-wasm`, the
# in-browser package (ADR-057), and the `scaffold-typescript-web-check` job of
# `.github/workflows/ci.yml` type-checks it against that package.
#
# The file list comes from `git ls-files`, so a site added under those directories
# is checked without an edit here. The gate fails closed: when either list is
# empty, when mypy is missing, or when `bindings/typescript/node_modules` lacks the
# TypeScript compiler, it exits 1 and says what to install. The guide list comes from
# `git ls-files` too, and the gate fails when it lists no guide, or when
# guide_blocks.py rejects a guide: a guide with no `**Status:**` line, a fence that never
# closes, or a skip marker with no reason or with no Python or TypeScript fence directly
# below it.
#
# Setup: `pip install -r scripts/examples-typecheck/requirements.txt` (mypy, and the
# packages the sites and guide blocks import, each pinned) and `bun install` in
# `bindings/typescript`.
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

guides=()
while IFS= read -r f; do
    guides+=("$f")
done < <(git ls-files -- '.docs/migration/*.md')

fail=0
if [[ ${#guides[@]} -eq 0 ]]; then
    echo "check-examples-typecheck: FAIL: git ls-files found no guide under .docs/migration/, so no guide block would be checked" >&2
    fail=1
fi
if [[ ${#py_files[@]} -eq 0 ]]; then
    echo "check-examples-typecheck: FAIL: git ls-files found no Python site, so mypy would check nothing" >&2
    fail=1
fi
if [[ ${#ts_files[@]} -eq 0 ]]; then
    echo "check-examples-typecheck: FAIL: git ls-files found no TypeScript site, so tsc would check nothing" >&2
    fail=1
fi
if ! "$PY" -m mypy --version >/dev/null 2>&1; then
    echo "check-examples-typecheck: FAIL: $PY cannot run mypy. Install it with: $PY -m pip install -r scripts/examples-typecheck/requirements.txt" >&2
    fail=1
fi
for module in cryptography pytest; do
    if ! "$PY" -c "import $module" >/dev/null 2>&1; then
        echo "check-examples-typecheck: FAIL: $PY cannot import $module, so mypy cannot resolve its types. Install it with: $PY -m pip install -r scripts/examples-typecheck/requirements.txt" >&2
        fail=1
    fi
done
if [[ ! -f $TSC ]]; then
    echo "check-examples-typecheck: FAIL: $TSC is missing. Run: (cd bindings/typescript && bun install)" >&2
    fail=1
fi
if ! command -v bun >/dev/null 2>&1; then
    echo "check-examples-typecheck: FAIL: bun is not on PATH, and it runs the TypeScript compiler" >&2
    fail=1
fi
[[ $fail -eq 0 ]] || exit 1

# An outlet capability names its stem in a hand-written string only by mistake: a
# Query outlet takes `outlet:query:` and an Action outlet `outlet:call:` (spec 05
# §5.4.2), and the SDK helpers (`Capability.outlet_query` / `outletQuery` and the
# `*_ALL` constants) name the stem for the caller. No code site under these
# directories, in any SDK language, spells either stem as a literal.
literal_stems="$(git grep -nE "[\"'\`]outlet:(call|query):" -- 'docs/examples/*.py' \
    'docs/examples/*.ts' 'docs/examples/*.swift' 'docs/examples/*.kt' 'scaffolds/*.py' \
    'scaffolds/*.ts' 'scaffolds/*.swift' 'scaffolds/*.kt' 'templates/*.py' 'templates/*.ts' \
    'templates/*.swift' 'templates/*.kt' || true)"
if [[ -n $literal_stems ]]; then
    printf '%s\n' "$literal_stems" >&2
    echo "check-examples-typecheck: FAIL: the site(s) above spell an outlet capability stem by hand; call the SDK helper for the outlet's kind" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if ! "$PY" "$CONF_DIR/guide_blocks.py" "$tmp/guides" "${guides[@]}"; then
    echo "check-examples-typecheck: FAIL: guide_blocks.py rejected a guide above, so the gate type-checked nothing" >&2
    exit 1
fi
guide_py=()
guide_ts=()
while IFS= read -r f; do guide_py+=("$f"); done < <(command find "$tmp/guides/py" -name '*.py' | sort)
while IFS= read -r f; do guide_ts+=("$f"); done < <(command find "$tmp/guides/ts" -name '*.ts' | sort)

echo "check-examples-typecheck: mypy over ${#py_files[@]} Python site(s) and ${#guide_py[@]} Python guide block(s)"
if ! MYPYPATH="$ROOT/bindings/python" "$PY" -m mypy --config-file "$CONF_DIR/mypy.ini" \
    --no-incremental "${py_files[@]}" ${guide_py[@]+"${guide_py[@]}"}; then
    fail=1
fi

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

if [[ ${#guide_ts[@]} -gt 0 ]]; then
    {
        printf '{\n  "extends": "%s",\n  "compilerOptions": { "types": ["node", "bun"] },\n  "files": [\n' \
            "$CONF_DIR/tsconfig.base.json"
        for i in "${!guide_ts[@]}"; do
            sep=","
            [[ $i -eq $((${#guide_ts[@]} - 1)) ]] && sep=""
            printf '    "%s"%s\n' "${guide_ts[$i]}" "$sep"
        done
        printf '  ]\n}\n'
    } > "$tmp/tsconfig.guides.json"
    echo "check-examples-typecheck: tsc --noEmit over ${#guide_ts[@]} TypeScript guide block(s)"
    if ! bun "$TSC" --noEmit -p "$tmp/tsconfig.guides.json"; then
        fail=1
    fi
fi

if [[ $fail -ne 0 ]]; then
    echo "check-examples-typecheck: FAIL: a site or guide block above calls SDK API that does not type-check" >&2
    exit 1
fi
echo "check-examples-typecheck: OK: ${#py_files[@]} Python and ${#ts_files[@]} TypeScript site(s), and ${#guide_py[@]} Python and ${#guide_ts[@]} TypeScript guide block(s), type-check against the SDK"
