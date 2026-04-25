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

# Per-bridge: directory, attribute, expected macro, container attribute.
#
# `container_attr` is the attribute that wraps an `impl` block and exposes
# EVERY method inside as an FFI entry point, regardless of whether the
# inner methods carry the bridge's per-function attribute. When set, the
# scanner treats every `fn` inside the block as attributed for as long as
# the block's brace balance remains open.
#
# * PyO3 — `#[pymethods] impl T { pub fn foo() }` — `foo` has no
#   `#[pyfunction]` but is still a Python-callable FFI entry point and
#   therefore needs a handle-affinity check when it accepts handle-typed
#   parameters. Without container-scope tracking, every `fullstack_*`
#   method on `PyScp` (and every method on every other `#[pymethods]`
#   impl) escapes the gate silently.
# * NAPI — `#[napi] impl Scp { #[napi(...)] fn foo() }`. Inner `fn` items
#   already carry `#[napi(...)]` so the per-function path catches them;
#   the container attr is still recorded for defense-in-depth.
# * UniFFI — `#[uniffi::export] impl Scp { pub fn foo() }` exports every
#   method in the impl. Works today because coders mark each method
#   individually; container-scope tracking catches any regression.
BRIDGES=(
    "pyo3|crates/scp-ffi/src|pyfunction|pyscp_check_handle|pymethods"
    "napi|crates/scp-ffi/napi/src|napi|napi_check_handle|napi"
    "uniffi|crates/scp-ffi/uniffi/src|uniffi::export|uniffi_check_handle|uniffi::export"
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
    local container_attr="${5:-}"

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
                -v CONTAINER_ATTR="$container_attr" \
                -v HANDLE_REGEX="$HANDLE_REGEX" '
            BEGIN {
                in_cfg_test_depth = 0
                pending_cfg_test = 0
                saw_attr = 0
                collecting = 0
                sig = ""
                sig_start_line = 0
                brace_depth = 0
                # Method-scope tracking for bridge container attributes.
                # See the BRIDGES config comments below (outside the awk
                # block) for the full rationale — kept out of this awk
                # string because single-quoted awk source cannot contain
                # shell-breaking apostrophes in embedded comments.
                in_method_scope_depth = 0
                pending_method_scope = 0
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
                    # Two accepted forms in the body window:
                    #  1. The bridge macro: `pyscp_check_handle!`,
                    #     `napi_check_handle!`, `uniffi_check_handle!`.
                    #  2. An inline `.check_handle(` method call on a
                    #     `CoreFields` reference. UniFFI was migrated to
                    #     inline calls for ergonomic reasons (no macro
                    #     expansion in doctests); PyO3/NAPI may also
                    #     expand inline at hot paths. Accepting both
                    #     keeps the gate enforcing affinity at the
                    #     behavioural level — a missing check is a bug
                    #     regardless of its syntactic form.
                    for (read_idx = 1; read_idx <= pending_n; read_idx++) {
                        # Two-stage acceptance: track whether we saw a
                        # valid-receiver preamble (`self.inner`, `.inner`,
                        # `bi`, or `&bi.core`) in the body window, then
                        # accept a `.check_handle(` only if the receiver
                        # was also observed. This tolerates the UniFFI
                        # multi-line chain
                        # `self.inner\n .core\n .check_handle(...)` while
                        # rejecting a bare `.check_handle(` on a foreign
                        # core (Round-2 black-hat finding).
                        if (index(line, MACRO "!") > 0) {
                            pending_found[read_idx] = 1
                        } else {
                            if (index(line, "self.inner") > 0 || \
                                index(line, "&bi.core") > 0 || \
                                index(line, "bi.core.") > 0 || \
                                match(line, /[[:space:]]bi\./) > 0 || \
                                index(line, ".inner.core") > 0) {
                                pending_saw_recv[read_idx] = 1
                            }
                            if (index(line, ".check_handle(") > 0 && \
                                pending_saw_recv[read_idx] == 1) {
                                pending_found[read_idx] = 1
                            }
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

                # Maintain method-scope state for the bridge'\''s container
                # attribute (#[pymethods], #[napi] on impl, #[uniffi::export]
                # on impl). When we see the container attr, arm the
                # pending_method_scope flag; the next `impl` line opens the
                # scope. Every `fn` inside the balanced braces that follow
                # is treated as an attributed FFI entry point — critical
                # for `#[pymethods] impl PyScp { pub fn foo() }` where
                # `foo` has no `#[pyfunction]` of its own.
                if (CONTAINER_ATTR != "") {
                    # Escape :: for regex literal match.
                    ca = CONTAINER_ATTR
                    gsub(/:/, "\\:", ca)
                    container_pat = "#\\[" ca "(\\]|\\()"
                    if (match(line, container_pat)) {
                        pending_method_scope = 1
                        # Do not `next` — `#[napi]` on a struct is not an
                        # impl block; we still want the normal attr/fn
                        # scanning to run so per-function `#[napi]` items
                        # continue to match. For `#[pymethods]`, the line
                        # above this `impl` is the only one where the
                        # attr appears, so `pending_method_scope` will be
                        # consumed on the next non-empty line.
                    }
                }

                # Track braces for the currently-open method-scope impl.
                # When depth drops to 0, the scope closes.
                if (in_method_scope_depth > 0) {
                    o2 = gsub(/\{/, "{", line)
                    c2 = gsub(/\}/, "}", line)
                    in_method_scope_depth += (o2 - c2)
                    if (in_method_scope_depth < 0) {
                        in_method_scope_depth = 0
                    }
                }

                # If a container attr was just seen and this line opens
                # an `impl ... {` block, activate the method scope.
                if (pending_method_scope && match(line, /^[[:space:]]*(unsafe[[:space:]]+)?impl[[:space:]]/)) {
                    # Count opening and closing braces on the impl line.
                    # Most `impl T {` lines have a single `{`, but the
                    # macro form `#[pymethods] impl T { fn ... }` may
                    # contain both on one line in edge cases — the net
                    # balance is what matters.
                    o3 = gsub(/\{/, "{", line)
                    c3 = gsub(/\}/, "}", line)
                    if (o3 > 0) {
                        in_method_scope_depth = o3 - c3
                        pending_method_scope = 0
                        # Fall through — the impl line itself does not
                        # declare a function, so no further work here.
                    } else {
                        # Attribute-impl-on-separate-lines shape:
                        #   #[pymethods]
                        #   impl PyScp
                        #   {
                        #       ...
                        # The `{` lands on a later line; activate the
                        # scope when we see it.
                        in_method_scope_depth = -1
                        pending_method_scope = 0
                    }
                    next
                }
                if (in_method_scope_depth < 0 && index(line, "{") > 0) {
                    # Brace appeared on a line after the `impl` header —
                    # promote to an active scope starting at depth 1.
                    o4 = gsub(/\{/, "{", line)
                    c4 = gsub(/\}/, "}", line)
                    in_method_scope_depth = o4 - c4
                    if (in_method_scope_depth < 1) {
                        in_method_scope_depth = 1
                    }
                    next
                }

                # If the pending flag is set but this line is neither the
                # container attr nor an impl opener, cancel it — the attr
                # must be followed by an `impl` to open a method scope.
                # Doc comments (`///`, `//!`, block `/*` and its `*`
                # continuation) between the container attr and the `impl`
                # line must NOT cancel the pending flag — otherwise a
                # documented `#[pymethods] impl T` slips through the gate.
                # (Round-2 bug-catcher finding MEDIUM #3.)
                if (pending_method_scope && match(line, /^[[:space:]]*$/) == 0 && \
                    match(line, /^[[:space:]]*#\[/) == 0 && \
                    match(line, /^[[:space:]]*\/\//) == 0 && \
                    match(line, /^[[:space:]]*\/\*/) == 0 && \
                    match(line, /^[[:space:]]*\*/) == 0) {
                    pending_method_scope = 0
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

                # Inside an open method-scope impl (#[pymethods] / #[napi] /
                # #[uniffi::export] on impl), every `fn` is attributed.
                # Non-function lines inside the scope (doc comments,
                # type aliases, impl bodies) do not trigger anything —
                # we only light up `saw_attr` when the line is a fn
                # signature start.
                if (in_method_scope_depth > 0 && !saw_attr && \
                    match(line, /^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
                    saw_attr = 1
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
    out=$(scan_bridge selftest "$fixture_dir" pyfunction pyscp_check_handle pymethods 2>/dev/null || true)
    local miss_count
    miss_count=$(printf '%s\n' "$out" | grep -c $'^MISS\t' || true)
    miss_count=${miss_count:-0}

    if [[ "$miss_count" -lt 2 ]]; then
        printf '%sinternal error:%s self-test of check-handle-affinity.sh\n' \
            "$C_RED" "$C_RESET" >&2
        printf '  expected 2 MISS lines from the fixture, got %d\n' "$miss_count" >&2
        printf '  the awk scan-state FIFO is broken; a neighbouring function\n' >&2
        printf '  is overwriting an earlier pending scan before MISS can fire.\n' >&2
        printf '  fixture output:\n%s\n' "$out" >&2
        rm -rf "$tmpdir"
        exit 2
    fi

    # ---------------------------------------------------------------------
    # Second self-test: verify that methods inside a `#[pymethods] impl T`
    # block with no per-method `#[pyfunction]` attribute are still scanned
    # for the handle-affinity macro. Pre-fix, every `fullstack_*` method
    # on `PyScp` escaped the gate because only the outer `#[pymethods]`
    # wraps the impl; individual methods only carry `#[pyo3(name = ...)]`.
    # ---------------------------------------------------------------------
    local fixture2_dir="$tmpdir/fixture2"
    mkdir -p "$fixture2_dir"
    local fixture2_file="$fixture2_dir/fixture.rs"
    cat > "$fixture2_file" <<'RUST'
// Self-test fixture 2. A #[pymethods] impl with a method that accepts a
// handle but does not call the macro. The outer #[pymethods] alone should
// be enough for the gate to scan every fn inside.
#[pymethods]
impl PyScp {
    #[pyo3(name = "does_work")]
    pub fn does_work(&self, h: &PyContextHandle) -> PyResult<()> { Ok(()) }
}
RUST

    local out2
    out2=$(scan_bridge selftest2 "$fixture2_dir" pyfunction pyscp_check_handle pymethods 2>/dev/null || true)
    local miss_count2
    miss_count2=$(printf '%s\n' "$out2" | grep -c $'^MISS\t' || true)
    miss_count2=${miss_count2:-0}

    rm -rf "$tmpdir"

    if [[ "$miss_count2" -lt 1 ]]; then
        printf '%sinternal error:%s self-test 2 of check-handle-affinity.sh\n' \
            "$C_RED" "$C_RESET" >&2
        printf '  expected >=1 MISS line from the #[pymethods] fixture, got %d\n' "$miss_count2" >&2
        printf '  the scanner is not tracking container-attr scope — methods\n' >&2
        printf '  inside `#[pymethods] impl T { ... }` are silently skipped,\n' >&2
        printf '  which means the outer `#[pymethods] impl PyScp` fullstack\n' >&2
        printf '  helpers (#1549) escape the gate.\n' >&2
        printf '  fixture output:\n%s\n' "$out2" >&2
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
    IFS='|' read -r bridge_name bridge_dir attr macro_name container_attr <<< "$entry"
    out_file="$TMPDIR_RESULT/$bridge_name.out"
    scan_bridge "$bridge_name" "$bridge_dir" "$attr" "$macro_name" "$container_attr" > "$out_file"
done

# ---------------------------------------------------------------------------
# Aggregate results
# ---------------------------------------------------------------------------
for entry in "${BRIDGES[@]}"; do
    IFS='|' read -r bridge_name bridge_dir attr macro_name container_attr <<< "$entry"
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
