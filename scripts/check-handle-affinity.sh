#!/usr/bin/env bash
# check-handle-affinity.sh — CI gate enforcing handle-affinity checks on all
# FFI functions that accept a handle-typed parameter.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Every FFI function in one of the three non-WASM bridges
#   crates/scp-ffi/src/        (PyO3   — #[pyfunction] / #[pymethods])
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
# Two shapes are covered:
#   1. Free functions annotated with the bridge attribute directly
#      (e.g. `#[pyfunction] fn foo(handle: &CtxHandle)`).
#   2. Methods inside an FFI-exported `impl` block
#      (e.g. `#[napi] impl Scp { fn foo(&self, handle: &CtxHandle) }`
#      or `#[pymethods] impl Scp { fn foo(&self, handle: &CtxHandle) }`
#      or `#[uniffi::export] impl Scp { fn foo(&self, handle: Arc<CtxHandle>) }`).
#
# Shape 2 is load-bearing for the SCP multi-instance migration (PR 4+,
# issue #1687) — as handle-taking operations move from free functions to
# `Scp` instance methods, the gate must catch a missing affinity check on
# the method as it would on a free function.
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

# Per-bridge: directory, free-function attribute, impl-block attribute,
# expected macro.
#
# The free-function attribute is the one that precedes a `fn` directly
# (e.g. `#[pyfunction] fn foo()`). The impl-block attribute is the one
# that precedes `impl Scp { ... }` (e.g. `#[pymethods] impl Scp { fn ... }`).
# For NAPI and UniFFI the two attributes are the same; for PyO3 they
# differ (`#[pyfunction]` vs `#[pymethods]`).
BRIDGES=(
    "pyo3|crates/scp-ffi/src|pyfunction|pymethods|pyscp_check_handle"
    "napi|crates/scp-ffi/napi/src|napi|napi|napi_check_handle"
    "uniffi|crates/scp-ffi/uniffi/src|uniffi::export|uniffi::export|uniffi_check_handle"
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
    local impl_attr="$4"
    local macro_name="$5"

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
                -v IMPL_ATTR="$impl_attr" \
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
                # body_scan: when > 0, we are inside the first N lines of a
                # function body and looking for the macro.
                body_scan_remaining = 0
                body_fn_name = ""
                body_fn_line = 0
                body_param_type = ""
                body_found_macro = 0
                # impl-block tracking: when we see the impl-block attribute
                # followed by `impl ... {`, every `fn` method inside the
                # block is subject to the same handle-affinity check as a
                # free-function FFI export. We track nesting via a single
                # depth counter (outer-most `{` of the impl block opens;
                # matching `}` closes).
                pending_impl_attr = 0
                in_impl_depth = 0
                impl_block_open = 0
            }

            # Track cfg(test) depth by counting braces after a `mod X {` that
            # is preceded by #[cfg(test)]. Simple but effective: awk-based
            # scope tracking. A brace on a cfg(test) line opens the scope; a
            # matching close returns to 0.
            {
                line = $0

                # If we are currently scanning a body for the macro, count
                # this line toward the window and check for the macro name.
                if (body_scan_remaining > 0) {
                    if (index(line, MACRO "!") > 0) {
                        body_found_macro = 1
                    }
                    body_scan_remaining--
                    if (body_scan_remaining == 0) {
                        if (body_found_macro == 0) {
                            printf("MISS\t%s\t%d\t%s\t%s\n",
                                FILE, body_fn_line, body_fn_name,
                                body_param_type)
                        }
                        body_fn_name = ""
                        body_fn_line = 0
                        body_param_type = ""
                        body_found_macro = 0
                    }
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

                # Look for the impl-block attribute preceding an
                # FFI-exported impl (e.g. `#[pymethods] impl Scp { ... }`
                # or `#[napi] impl Scp { ... }`). Flag pending_impl_attr
                # so the next `impl ... {` line opens an impl-tracked
                # block. Note: impl_attr may equal attr (napi, uniffi)
                # so we must check impl-first so a line like `#[napi]
                # impl Scp {` opens the impl block rather than being
                # consumed as a free-function attribute.
                #
                # Only arm pending_impl_attr at the top level (not inside
                # an existing impl block). Inside an impl, the same
                # attribute decorates methods, not nested impls — treating
                # it as pending_impl_attr would cause the gate to latch
                # onto the NEXT `impl ... {` in the file (e.g. a private
                # helper impl below the exported one) and spuriously
                # flag its methods.
                impl_attr_pat = "#\\[" IMPL_ATTR "(\\]|\\()"
                if (in_impl_depth == 0 && match(line, impl_attr_pat)) {
                    pending_impl_attr = 1
                    saw_attr = 1
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

                # If pending_impl_attr is set and we encounter an
                # `impl ... {` line, open a tracked impl block. The
                # opening `{` is counted as depth 1; subsequent `{` and
                # `}` lines balance it. When depth returns to 0, the
                # block closes.
                if (pending_impl_attr && match(line, /^[[:space:]]*impl[[:space:]]/)) {
                    # Count braces on this line. Typical pattern has the
                    # opening `{` on the same line as `impl Scp`.
                    o = gsub(/\{/, "{", line)
                    c = gsub(/\}/, "}", line)
                    in_impl_depth += (o - c)
                    pending_impl_attr = 0
                    saw_attr = 0
                    next
                }
                # pending_impl_attr is armed but this line is neither a
                # continuation attribute nor an impl header. The usual
                # reason is that the attribute decorated a free
                # function (e.g. `#[napi] pub fn foo()` — napi uses the
                # same attribute for free fns and impl blocks). Leave
                # saw_attr set (the free-function path will consume
                # it), but disarm pending_impl_attr so the NEXT `impl`
                # in the file is not mistakenly treated as the target
                # of this attribute.
                if (pending_impl_attr && match(line, /^[[:space:]]*$/) == 0 \
                    && match(line, /^[[:space:]]*#\[/) == 0) {
                    pending_impl_attr = 0
                }

                # Inside an impl-tracked block, balance every line so we
                # close when the outermost `}` lands. We also run the
                # free-function-like fn detection below for every
                # `fn` we encounter inside the block.
                if (in_impl_depth > 0) {
                    o = gsub(/\{/, "{", line)
                    c = gsub(/\}/, "}", line)
                    # Detect `fn ...` lines as implicitly bridge-exported.
                    # Skip if this line starts a private / non-exported
                    # helper (we treat all `fn` inside a bridge-exported
                    # impl block as exported — UniFFI/NAPI/pymethods
                    # only expose what the impl attribute covers, and
                    # private methods are a future concern tracked by
                    # the NAPI `#[napi(skip)]` / UniFFI `#[uniffi::method]`
                    # visibility flags).
                    if (!collecting && match(line, /^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
                        saw_attr = 1
                    }
                    in_impl_depth += (o - c)
                    if (in_impl_depth <= 0) {
                        in_impl_depth = 0
                    }
                    # Fall through so the fn-detection block below
                    # consumes the `fn` line on the same pass.
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
                body_scan_remaining = 8
                body_fn_name = fname
                body_fn_line = fline
                body_param_type = param_type_found
                body_found_macro = 0
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
                # Flush any pending body scan.
                if (body_scan_remaining > 0 && body_fn_name != "") {
                    if (body_found_macro == 0) {
                        printf("MISS\t%s\t%d\t%s\t%s\n",
                            FILE, body_fn_line, body_fn_name,
                            body_param_type)
                    }
                }
            }
            ' "$file"
        done
}

# ---------------------------------------------------------------------------
# Drive the scan
# ---------------------------------------------------------------------------
TMPDIR_RESULT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RESULT"' EXIT

for entry in "${BRIDGES[@]}"; do
    IFS='|' read -r bridge_name bridge_dir attr impl_attr macro_name <<< "$entry"
    out_file="$TMPDIR_RESULT/$bridge_name.out"
    scan_bridge "$bridge_name" "$bridge_dir" "$attr" "$impl_attr" "$macro_name" > "$out_file"
done

# ---------------------------------------------------------------------------
# Aggregate results
# ---------------------------------------------------------------------------
for entry in "${BRIDGES[@]}"; do
    IFS='|' read -r bridge_name bridge_dir attr impl_attr macro_name <<< "$entry"
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
