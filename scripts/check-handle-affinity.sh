#!/usr/bin/env bash
# check-handle-affinity.sh — CI gate enforcing handle-affinity checks on all
# FFI functions that accept a handle-typed parameter.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Every FFI function in one of the three non-WASM bridges
#   crates/scp-ffi/src/        (PyO3   — #[pyfunction])
#   crates/scp-ffi/napi/src/   (NAPI   — #[napi])
#   crates/scp-ffi/uniffi/src/ (UniFFI — #[uniffi::export])
# whose signature includes a parameter whose type ends in one of the handle
# type suffixes (Handle, Identity, UcanToken, TransportManager, Message,
# MessageReceiver, RelayHandle, NodeHandle, DIDDocument) MUST invoke the
# per-bridge handle-affinity macro at the top of its body:
#
#   PyO3   — pyscp_check_handle!(self, handle, ...)
#   NAPI   — napi_check_handle!(self, handle, ...)
#   UniFFI — uniffi_check_handle!(self, handle, ...)
#
# This guarantees that a handle minted by one `SCP` instance cannot be used
# against a different `SCP` instance within the same process. Mismatches
# return the error code SCP-PERM-3030 at runtime.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# Informational during PR 1 of the Phase 4 remainder (issue #1549) — the
# macros themselves are introduced across PR 1 and PR 2; until both land, the
# gate will report failures that are expected to clear once coders B/C/D and
# the PR 2 migration complete.
#
# Enforced in CI starting PR 4 of the Phase 4 remainder.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# Add the bridge's handle-affinity macro call as the FIRST statement in the
# body of the offending function, before any validation or logic:
#
#   PyO3 example:
#     fn py_context_join(handle: &PyContextHandle, identity_did: &str)
#         -> PyResult<()>
#     {
#         pyscp_check_handle!(self, handle);
#         validate::validate_did(identity_did)?;
#         ...
#     }
#
# If the parameter whose type matches the suffix is NOT a caller-minted
# handle (e.g. an internal helper type that happens to end in `Message`),
# hoist it out of the FFI function into a pure helper and forward the
# concrete handle-typed arguments through the macro. Do not annotate-away
# a real handle — mismatched-instance use must fail with SCP-PERM-3030.
#
# ---------------------------------------------------------------------------
# ERROR CODE RETURNED AT RUNTIME
# ---------------------------------------------------------------------------
# SCP-PERM-3030  — "handle was minted by a different SCP instance"
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Uses only POSIX-
# compatible bash, awk, grep features; no gawk-specific extensions, no GNU
# sed -E with perl-style lookarounds.
#
# Usage:
#   bash scripts/check-handle-affinity.sh
# Exit codes:
#   0  — all handle-accepting FFI functions invoke the matching macro
#   1  — one or more functions missing the required macro
#   2  — invocation error (missing directory, invalid arguments)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# TTY-aware coloring
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_DIM=$'\033[2m'
    C_RESET=$'\033[0m'
else
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_DIM=""
    C_RESET=""
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Handle type suffixes. A parameter whose type ends in any of these needs
# an affinity check.
HANDLE_SUFFIXES=(
    Handle
    Identity
    UcanToken
    TransportManager
    Message
    MessageReceiver
    RelayHandle
    NodeHandle
    DIDDocument
    # Feature-gated full-stack test nodes are per-instance handles too —
    # `&bi.core.check_handle(node.instance_id())` must run at every
    # `fullstack_*_on` entry point or a caller can hand a `NapiFullStackNode`
    # minted by SCP A into SCP B's testing helpers. The suffix is the
    # concrete Rust type name because the three bridges use different
    # prefixes (`PyFullStackNode`, `NapiFullStackNode`, `FullStackNode`).
    FullStackNode
)

# Build a regex alternation for the suffixes.
HANDLE_REGEX=""
for suffix in "${HANDLE_SUFFIXES[@]}"; do
    if [[ -z "$HANDLE_REGEX" ]]; then
        HANDLE_REGEX="$suffix"
    else
        HANDLE_REGEX="${HANDLE_REGEX}|${suffix}"
    fi
done

# Per-bridge: directory, attribute, expected macro.
BRIDGES=(
    "pyo3|crates/scp-ffi/src|pyfunction|pyscp_check_handle"
    "napi|crates/scp-ffi/napi/src|napi|napi_check_handle"
    "uniffi|crates/scp-ffi/uniffi/src|uniffi::export|uniffi_check_handle"
)

TOTAL_CHECKED=0
TOTAL_MISSING=0
MISSING_LIST=()

# ---------------------------------------------------------------------------
# Scan one bridge.
#
# Strategy:
#   1. Find every file matching `*.rs` under the bridge src directory.
#   2. Run an awk pass per file that:
#      - tracks whether we are inside a `#[cfg(test)]` module (depth-counted
#        by brace balance from the `mod name {` line)
#      - recognizes the attribute line for the bridge
#      - collects the following function signature across lines until the
#        opening `{` of the body is seen
#      - inspects that signature for a parameter type ending in a handle
#        suffix
#      - if so, peeks forward a short window into the body and checks for
#        the expected macro name
#      - emits `MISS\t<file>\t<line>\t<fn_name>\t<param_type>` on stdout when
#        a handle-accepting function omits the macro
#      - emits `CHK\t<file>\t<line>\t<fn_name>` for every inspected function
# ---------------------------------------------------------------------------
scan_bridge() {
    local bridge_name="$1"
    local bridge_dir="$2"
    local attr="$3"
    local macro_name="$4"

    if [[ ! -d "$bridge_dir" ]]; then
        printf '%swarning:%s bridge dir %s does not exist, skipping %s\n' \
            "$C_YELLOW" "$C_RESET" "$bridge_dir" "$bridge_name" >&2
        return 0
    fi

    # shellcheck disable=SC2016
    # (single-quoted awk script — $n are awk fields, not shell vars)
    find "$bridge_dir" -type f -name '*.rs' -print0 \
        | while IFS= read -r -d '' file; do
            awk \
                -v FILE="$file" \
                -v ATTR="$attr" \
                -v MACRO="$macro_name" \
                -v HANDLE_REGEX="$HANDLE_REGEX" '
            BEGIN {
                in_cfg_test_depth = 0
                pending_cfg_test = 0
                saw_attr = 0
                collecting = 0
                sig = ""
                sig_start_line = 0
                brace_depth = 0
                # Pending-scan FIFO. `pending_n` is the number of active
                # body scans; each slot `i` (1..=pending_n) stores:
                #   pending_fn_name[i]   — function name
                #   pending_fn_line[i]   — signature start line
                #   pending_param[i]     — handle-typed param type string
                #   pending_remaining[i] — lines left in the scan window
                #   pending_found[i]     — 1 if macro seen, else 0
                # A FIFO (rather than a single set of globals) is required
                # so that overlapping scans — e.g. a 1-line function body
                # whose neighbour starts its own signature before the
                # window closes — each get their own MISS emission. The
                # single-global design silently dropped the earlier scan
                # every time `finalize_sig` was re-entered.
                pending_n = 0
            }

            # Track cfg(test) depth by counting braces after a `mod X {` that
            # is preceded by #[cfg(test)]. Simple but effective: awk-based
            # scope tracking. A brace on a cfg(test) line opens the scope; a
            # matching close returns to 0.
            {
                line = $0

                # Advance every pending scan by one line. A pending scan
                # that hits zero without having seen the macro emits a
                # MISS. We walk in order and compact the array in place so
                # the remaining entries keep their FIFO ordering — new
                # pushes always land at `pending_n + 1`.
                if (pending_n > 0) {
                    write_idx = 0
                    for (read_idx = 1; read_idx <= pending_n; read_idx++) {
                        if (index(line, MACRO "!") > 0) {
                            pending_found[read_idx] = 1
                        }
                        pending_remaining[read_idx]--
                        if (pending_remaining[read_idx] <= 0) {
                            if (pending_found[read_idx] == 0) {
                                printf("MISS\t%s\t%d\t%s\t%s\n",
                                    FILE,
                                    pending_fn_line[read_idx],
                                    pending_fn_name[read_idx],
                                    pending_param[read_idx])
                            }
                            # Retire this entry by not copying it forward.
                        } else {
                            write_idx++
                            if (write_idx != read_idx) {
                                pending_fn_name[write_idx]   = pending_fn_name[read_idx]
                                pending_fn_line[write_idx]   = pending_fn_line[read_idx]
                                pending_param[write_idx]     = pending_param[read_idx]
                                pending_remaining[write_idx] = pending_remaining[read_idx]
                                pending_found[write_idx]     = pending_found[read_idx]
                            }
                        }
                    }
                    # Clear the tail slots so stale data does not leak if
                    # pending_n grows later.
                    for (clear_idx = write_idx + 1; clear_idx <= pending_n; clear_idx++) {
                        pending_fn_name[clear_idx]   = ""
                        pending_fn_line[clear_idx]   = 0
                        pending_param[clear_idx]     = ""
                        pending_remaining[clear_idx] = 0
                        pending_found[clear_idx]     = 0
                    }
                    pending_n = write_idx
                }

                # Maintain cfg(test) state.
                if (match(line, /#\[cfg\(test\)\]/)) {
                    pending_cfg_test = 1
                }
                if (pending_cfg_test && match(line, /mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/)) {
                    in_cfg_test_depth++
                    pending_cfg_test = 0
                }
                else if (pending_cfg_test && match(line, /^[[:space:]]*$/) == 0 && match(line, /#\[/) == 0) {
                    # Something other than mod followed the attr; reset.
                    pending_cfg_test = 0
                }

                # If we are inside a cfg(test) block, track brace balance
                # crudely: count { and } on each line. (Good enough for the
                # typical mod X { ... } layout; the files do not mix
                # attributes with complex inner blocks at the mod boundary.)
                if (in_cfg_test_depth > 0) {
                    o = gsub(/\{/, "{", line)
                    c = gsub(/\}/, "}", line)
                    in_cfg_test_depth += (o - c)
                    if (in_cfg_test_depth < 0) {
                        in_cfg_test_depth = 0
                    }
                    next
                }

                # Look for the bridge attribute. Match either the bare
                # attribute (`#[pyfunction]`, `#[napi]`, `#[uniffi::export]`)
                # or with arguments (`#[napi(...)]`, `#[pyo3(...)]`).
                # For PyO3, also accept a trailing #[pyo3(signature = ...)].
                attr_pat = "#\\[" ATTR "(\\]|\\()"
                if (match(line, attr_pat)) {
                    saw_attr = 1
                    next
                }

                # Accept additional decorative attrs that may follow the
                # main attribute (e.g. pyo3 signature, napi(ts_return_type)).
                if (saw_attr && match(line, /^[[:space:]]*#\[/)) {
                    next
                }

                # Start of a function signature.
                if (saw_attr && match(line, /^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
                    saw_attr = 0
                    collecting = 1
                    sig = line
                    sig_start_line = NR
                    brace_depth = 0
                    # Extract function name.
                    tmp = line
                    sub(/^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+/, "", tmp)
                    match(tmp, /[A-Za-z_][A-Za-z0-9_]*/)
                    fn_name = substr(tmp, RSTART, RLENGTH)
                    # Does this line already contain { ?
                    if (index(line, "{") > 0) {
                        finalize_sig(fn_name, sig_start_line, sig)
                        collecting = 0
                        sig = ""
                    }
                    next
                }

                if (collecting) {
                    sig = sig " " line
                    if (index(line, "{") > 0) {
                        finalize_sig(fn_name, sig_start_line, sig)
                        collecting = 0
                        sig = ""
                    }
                    next
                }

                # Reset saw_attr if we hit a non-attr, non-fn line (e.g. a
                # use statement between attr and struct). Defensive.
                if (saw_attr && match(line, /^[[:space:]]*$/) == 0) {
                    # allow attrs (handled above); if we got here, treat as
                    # unrelated and reset.
                    saw_attr = 0
                }
            }

            function finalize_sig(fname, fline, signature,
                                  # locals
                                  params, param_type_found, re, i, n, part) {
                # Strip from the start up through the first `(` of the
                # signature. If there is no `(`, bail out (unlikely for a
                # function that has an attribute).
                i = index(signature, "(")
                if (i == 0) return
                params = substr(signature, i + 1)
                # Strip from the closing `)` onward — matches the LAST `)`
                # before the `{`, which handles nested `(…)` inside types
                # (e.g. `impl Fn(A) -> B`).
                n = index(params, "{")
                if (n > 0) {
                    # Trim trailing { and everything after.
                    params = substr(params, 1, n - 1)
                }
                # Trim the final `)` — naive rightmost-) strip.
                # (awk does not have rfind; do a reverse scan.)
                j = length(params)
                while (j > 0) {
                    c = substr(params, j, 1)
                    if (c == ")") {
                        params = substr(params, 1, j - 1)
                        break
                    }
                    j--
                }

                # Now `params` is the comma-separated parameter list (minus
                # return type, minus the body-open brace). Commas inside
                # generic arguments (e.g. `HashMap<String, DID>`) would
                # confuse a naive split — walk the string and split on
                # top-level commas only.
                split_params(params, parts)
                param_type_found = ""
                for (k = 1; k <= parts_n; k++) {
                    part = parts[k]
                    # Strip leading/trailing whitespace.
                    sub(/^[[:space:]]+/, "", part)
                    sub(/[[:space:]]+$/, "", part)
                    if (part == "") continue
                    # A parameter has the shape `name: Type` or `mut name:
                    # Type`. Take everything after the first colon.
                    cpos = index(part, ":")
                    if (cpos == 0) continue
                    type_part = substr(part, cpos + 1)
                    sub(/^[[:space:]]+/, "", type_part)
                    # Look for a handle suffix that terminates an
                    # identifier inside the type part. We match the suffix
                    # followed by a non-identifier character (space, `,`,
                    # `>`, `)`, etc.). Padding the string with a trailing
                    # space sidesteps BSD awk'\''s weak support for the `$`
                    # anchor inside an alternation group, and still rejects
                    # suffix-in-the-middle cases like `Handler` (where `r`
                    # after `Handle` is alphanumeric, so no match).
                    type_part_padded = type_part " "
                    re = "(" HANDLE_REGEX ")[^A-Za-z0-9_]"
                    if (match(type_part_padded, re)) {
                        # Record the whole type_part as the finding.
                        param_type_found = type_part
                        break
                    }
                }

                if (param_type_found == "") {
                    # No handle-typed param — record a CHK for the caller
                    # to know we looked at this function.
                    printf("CHK\t%s\t%d\t%s\n", FILE, fline, fname)
                    return
                }

                # Start body scan. Look at up to BODY_WINDOW lines for the
                # macro. Matching just the macro name covers both
                # `pyscp_check_handle!(...)` and any future variants; we
                # intentionally accept any call-site form.
                #
                # Push onto the FIFO so multiple overlapping scans can be
                # in flight at once — a short function body whose sibling
                # starts its own signature within the window must NOT
                # silently overwrite the prior scan state (pre-fix bug).
                pending_n++
                pending_fn_name[pending_n]   = fname
                pending_fn_line[pending_n]   = fline
                pending_param[pending_n]     = param_type_found
                pending_remaining[pending_n] = 8
                pending_found[pending_n]     = 0
                printf("CHK\t%s\t%d\t%s\n", FILE, fline, fname)
            }

            function split_params(s, out,    depth, start, i, c, piece) {
                delete out
                parts_n = 0
                depth = 0
                start = 1
                for (i = 1; i <= length(s); i++) {
                    c = substr(s, i, 1)
                    if (c == "<" || c == "(" || c == "[") depth++
                    else if (c == ">" || c == ")" || c == "]") depth--
                    else if (c == "," && depth == 0) {
                        piece = substr(s, start, i - start)
                        parts_n++
                        out[parts_n] = piece
                        start = i + 1
                    }
                }
                piece = substr(s, start)
                if (piece != "") {
                    parts_n++
                    out[parts_n] = piece
                }
            }

            END {
                # Flush every pending body scan at EOF. A function whose
                # window is still open at file end has not emitted a
                # macro — treat it the same as a window that closed
                # without finding one.
                for (flush_idx = 1; flush_idx <= pending_n; flush_idx++) {
                    if (pending_found[flush_idx] == 0) {
                        printf("MISS\t%s\t%d\t%s\t%s\n",
                            FILE,
                            pending_fn_line[flush_idx],
                            pending_fn_name[flush_idx],
                            pending_param[flush_idx])
                    }
                }
            }
            ' "$file"
        done
}

# ---------------------------------------------------------------------------
# Self-test: guards the scan-state FIFO against the single-global regression.
# ---------------------------------------------------------------------------
# The pre-fix version of this gate used a single global
# (`body_scan_remaining` + `body_fn_name` + `body_found_macro`) for the
# forward-peek window. Two consecutive handle-accepting functions whose
# bodies fit inside the 8-line window would race: the second function's
# `finalize_sig` would overwrite the first function's pending scan state
# BEFORE the first function's MISS could fire, silently burying the gap.
#
# This self-test synthesises exactly that shape — a one-line function
# body missing the macro, immediately followed by another handle-accepting
# function — and asserts the queue-based implementation emits MISS for
# BOTH. Runs before the real scan so a bad edit to the awk script fails
# the gate loudly instead of silently reporting PASS on a broken scanner.
# ---------------------------------------------------------------------------
self_test_gate() {
    local tmpdir
    tmpdir=$(mktemp -d)

    local fixture_dir="$tmpdir/fixture"
    mkdir -p "$fixture_dir"
    local fixture_file="$fixture_dir/fixture.rs"
    cat > "$fixture_file" <<'RUST'
// Self-test fixture. Two handle-accepting fns, neither invokes the macro.
#[pyfunction]
fn first(h: &PyContextHandle) -> PyResult<()> { Ok(()) }
#[pyfunction]
fn second(h: &PyContextHandle) -> PyResult<()> { Ok(()) }
RUST

    local out
    out=$(scan_bridge selftest "$fixture_dir" pyfunction pyscp_check_handle 2>/dev/null || true)
    local miss_count
    miss_count=$(printf '%s\n' "$out" | grep -c $'^MISS\t' || true)
    miss_count=${miss_count:-0}

    rm -rf "$tmpdir"

    if [[ "$miss_count" -lt 2 ]]; then
        printf '%sinternal error:%s self-test of check-handle-affinity.sh\n' \
            "$C_RED" "$C_RESET" >&2
        printf '  expected 2 MISS lines from the fixture, got %d\n' "$miss_count" >&2
        printf '  the awk scan-state FIFO is broken; a neighbouring function\n' >&2
        printf '  is overwriting an earlier pending scan before MISS can fire.\n' >&2
        printf '  fixture output:\n%s\n' "$out" >&2
        exit 2
    fi
}
self_test_gate

# ---------------------------------------------------------------------------
# Drive the scan
# ---------------------------------------------------------------------------
TMPDIR_RESULT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RESULT"' EXIT

for entry in "${BRIDGES[@]}"; do
    IFS='|' read -r bridge_name bridge_dir attr macro_name <<< "$entry"
    out_file="$TMPDIR_RESULT/$bridge_name.out"
    scan_bridge "$bridge_name" "$bridge_dir" "$attr" "$macro_name" > "$out_file"
done

# ---------------------------------------------------------------------------
# Aggregate results
# ---------------------------------------------------------------------------
for entry in "${BRIDGES[@]}"; do
    IFS='|' read -r bridge_name bridge_dir attr macro_name <<< "$entry"
    out_file="$TMPDIR_RESULT/$bridge_name.out"
    [[ -s "$out_file" ]] || continue

    # `grep -c` prints `0` AND exits 1 on no match; a `|| printf 0` fallback
    # would double the count. Use `|| true` to absorb the non-zero exit and
    # keep the printed `0`.
    chk_count=$(grep -c $'^CHK\t' "$out_file" 2>/dev/null || true)
    miss_count=$(grep -c $'^MISS\t' "$out_file" 2>/dev/null || true)
    chk_count=${chk_count:-0}
    miss_count=${miss_count:-0}

    TOTAL_CHECKED=$((TOTAL_CHECKED + chk_count))
    TOTAL_MISSING=$((TOTAL_MISSING + miss_count))

    if [[ "$miss_count" -gt 0 ]]; then
        printf '%s[%s]%s %d function(s) missing %s!\n' \
            "$C_RED" "$bridge_name" "$C_RESET" "$miss_count" "$macro_name" >&2
        while IFS=$'\t' read -r tag file line fn param_type; do
            [[ "$tag" == "MISS" ]] || continue
            printf '  %s%s:%s%s  fn %s%s%s  (param type: %s%s%s)\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$fn" "$C_RESET" \
                "$C_DIM" "$param_type" "$C_RESET" >&2
            MISSING_LIST+=("$bridge_name:$file:$line:$fn")
        done < "$out_file"
        printf '\n' >&2
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n'
printf 'checked %d FFI function(s) across 3 bridges\n' "$TOTAL_CHECKED"

if [[ "$TOTAL_MISSING" -eq 0 ]]; then
    printf '%sPASSED%s: every handle-accepting FFI function invokes its bridge'\''s handle-affinity macro.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi

printf '%sFAILED%s: %d handle-accepting FFI function(s) missing their handle-affinity macro.\n' \
    "$C_RED" "$C_RESET" "$TOTAL_MISSING" >&2
printf '\n' >&2
printf 'To fix: add the bridge'\''s macro call as the FIRST statement in each\n' >&2
printf 'function body (pyscp_check_handle! / napi_check_handle! /\n' >&2
printf 'uniffi_check_handle!). Mismatched-instance handle use returns the\n' >&2
printf 'error code SCP-PERM-3030 at runtime.\n' >&2
printf '\n' >&2
printf 'See .docs/adrs/ADR-048-scp-multi-instance.md for rationale.\n' >&2

exit 1
