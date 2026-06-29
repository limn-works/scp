#!/usr/bin/env bash
# check-bridge-symmetry.sh — Enforce surface-area symmetry across the three
# FFI bridges (PyO3, UniFFI, NAPI).
#
# Scope: SURFACE AREA ONLY. For every canonical operation declared in
# `scripts/bridge-aliases.json`, verify that each required bridge exposes at
# least one documented alias (`fn <alias>(`) unless the bridge has a
# documented exemption in the same JSON file.
#
# Out of scope: call-ordering invariants. Call-ordering checks are handled by
# Layer B (`scripts/check-call-invariants.py`), which uses a proper Rust
# tokenizer (tree-sitter-rust) and reliably handles raw strings, format
# strings with `{}`, and block comments — things a shell+awk implementation
# cannot handle correctly on BSD awk (macOS).
#
# This script complements (does not replace) the Rust-side enforcement in
# crates/scp-testing/tests/integration/ffi_conformance.rs. The two MUST agree
# — `aliases_json_is_in_sync_with_parity_operations` in that file checks the
# same `scripts/bridge-aliases.json` the script reads here, and additional
# tests verify that every alias resolves to a real `fn` definition or falls
# under a documented exemption.
#
# ─── Modes ────────────────────────────────────────────────────────────────
#
# CI mode (no args or `--ci`):
#   • Scan every canonical operation in bridge-aliases.json across all four
#     bridges. Emit a finding for any required bridge missing the operation
#     (unless it has a documented exemption in bridge-aliases.json).
#   • Exit 1 if any findings, else 0.
#
# Hook mode (`--hook <file1> <file2> ...`):
#   • Intended for Claude Code PreToolUse hooks on Edit/Write/MultiEdit.
#   • Fast bail if no path touches crates/scp-ffi/.
#   • Only blocks on REGRESSIONS: a symbol that exists in a sibling bridge
#     but was REMOVED in the edit (diff edited file vs `git show HEAD:<path>`).
#     Additions that siblings lack → stdout warning, exit 0.
#
# Exit codes:
#   0 — pass (no findings, or warnings only in hook mode)
#   1 — CI mode: findings detected, or hook mode: path outside repo
#   2 — hook mode: regression detected
#
# Environment:
#   SCP_BRIDGE_ROOT — override the root repo directory (used by fixture tests).
#                     Defaults to the git top-level above this script.
#
# Known limitations:
#   • Function-definition detection is regex-based (`fn NAME(`). It does not
#     tokenize Rust; functions whose signatures span unusual whitespace may
#     be missed. Matched by both the Rust conformance test and this script,
#     so drift is detectable but pathological inputs could fool both.
#   • `#[cfg(test)] mod tests { ... }` and `#[cfg(test)] impl Foo { ... }`
#     exclusion tracks braces via awk and may over-match if non-test code
#     opens a nested module or brace-balanced gadget inside a cfg-test block.
#     Not observed in practice. The Rust `syn` scanner in
#     `ffi_conformance.rs` overrides both `visit_item_mod` and
#     `visit_item_impl` to skip cfg(test) subtrees — the two must stay in
#     lockstep, which is enforced by the
#     `every_alias_resolves_to_a_real_fn_or_exemption` test and the
#     `bad-alias-in-test-impl` fixture under
#     `scripts/tests/bridge-symmetry/fixtures/`.
#   • UniFFI bridge is a single 14k-line file; per-function body scans
#     still complete well under 500ms on current hardware.
#   • cfg-predicate evaluation: we evaluate whether a `#[cfg(...)]` expression
#     is satisfied ONLY when the `test` predicate is enabled. `cfg(test)` /
#     `cfg(any(test, ...))` / `cfg(all(test, ...))` count as test-only;
#     `cfg(not(test))` / `cfg(all(not(test), ...))` are production gates and
#     are NOT treated as test-only. The nested-paren walker in
#     `is_test_gated_cfg_segment` mirrors the Rust `meta_is_test_gated` walker
#     so the bash and syn scanners stay in lockstep.

set -euo pipefail

# Force a deterministic locale for grep/awk/sort/comm across macOS/Linux/CI.
# Without this, non-ASCII bytes in Rust source files (rare but present in
# test fixtures and doc-comments) can change regex-class semantics and
# sort/comm ordering, causing spurious findings.
export LC_ALL=C

# ---------------------------------------------------------------------------
# Locate repo root
# ---------------------------------------------------------------------------
if [[ -n "${SCP_BRIDGE_ROOT:-}" ]]; then
    REPO_ROOT="$SCP_BRIDGE_ROOT"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
cd "$REPO_ROOT"

ALIASES_JSON="$REPO_ROOT/scripts/bridge-aliases.json"
if [[ ! -f "$ALIASES_JSON" ]]; then
    echo "ERROR: scripts/bridge-aliases.json not found at $ALIASES_JSON" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required but not installed. Install with:" >&2
    echo "  macOS:  brew install jq" >&2
    echo "  Linux:  apt-get install -y jq" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
MODE="ci"
HOOK_FILES=()
if [[ $# -gt 0 ]]; then
    case "$1" in
        --ci)
            MODE="ci"
            shift
            ;;
        --hook)
            MODE="hook"
            shift
            HOOK_FILES=("$@")
            ;;
        --help|-h)
            sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1 (use --ci or --hook)" >&2
            exit 1
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# Bridge source directories (relative to REPO_ROOT)
# ---------------------------------------------------------------------------
PYO3_DIR="crates/scp-ffi/src"
UNIFFI_DIR="crates/scp-ffi/uniffi/src"
NAPI_DIR="crates/scp-ffi/napi/src"

bridge_dir() {
    case "$1" in
        pyo3)   echo "$PYO3_DIR" ;;
        uniffi) echo "$UNIFFI_DIR" ;;
        napi)   echo "$NAPI_DIR" ;;
        *)
            echo "ERROR: unknown bridge: $1" >&2
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Helper: list .rs files in a bridge directory (not inside tests/)
# ---------------------------------------------------------------------------
bridge_sources() {
    local bridge="$1"
    local dir
    dir="$(bridge_dir "$bridge")" || return 1
    local bridge_root="$REPO_ROOT/$dir"
    if [[ ! -d "$bridge_root" ]]; then
        return 0
    fi
    # Exclude target builds and any `tests/` subtree BELOW the bridge root
    # (we want bridge impl only, not integration tests). We rely on bridge_root
    # being the anchor: `-path "$bridge_root/*/tests/*"` matches tests/ inside
    # any direct child dir. Paths above bridge_root are never traversed.
    find "$bridge_root" -type f -name '*.rs' \
        -not -path "$bridge_root/*/tests/*" \
        -not -path "$bridge_root/tests/*" \
        -not -path "*/target/*" \
        2>/dev/null | sort
}

# ---------------------------------------------------------------------------
# Extract every `fn NAME(` / `fn NAME (` / `fn NAME<` definition from a file,
# EXCLUDING those inside `#[cfg(test)] mod <name> { ... }` blocks.
#
# Prints one function name per line. Single awk pass per file.
# ---------------------------------------------------------------------------
collect_fn_names_from_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0

    # Portable (BSD + GNU awk) single-pass collector.
    #
    # What it extracts: every `fn NAME(` or `fn NAME<` DEFINITION at module or
    # impl-block scope, EXCLUDING:
    #   • Functions inside `#[cfg(test)] mod <name> { ... }` blocks. Without
    #     this filter an adversary can hide a fake alias behind a test module.
    #   • Functions inside `#[cfg(test)] impl Foo { ... }` blocks. Same
    #     rationale — an impl block gated on test is not production code. Real
    #     instances exist in `crates/scp-ffi/napi/src/context.rs` and
    #     `runtime.rs`, so the shell scanner MUST handle this or it will emit
    #     phantom production symbols alongside real ones.
    #   • Text inside `//` line comments (doc comments, explanatory comments).
    #     A doc-comment containing `#[cfg(test)]` or `fn foo(` would otherwise
    #     poison the scanner state and emit phantom names.
    #
    # Limitations: `/* ... */` block comments are not stripped. We do not see
    # block comments in the SCP bridge source tree (clippy discourages them),
    # so an adversary using block comments to hide a fake alias would be caught
    # by the ffi_conformance syn-based parser on the Rust side. Both layers
    # read the same alias JSON so drift is the only concern, and drift is
    # caught by the `every_alias_resolves_to_a_real_fn_or_exemption` test.
    #
    # Word boundary for `mod`: BSD awk (macOS) lacks `\<` / `\>`. We require a
    # non-identifier char BEFORE `mod` (or start-of-line) by scanning via an
    # explicit regex with a char class, sidestepping POSIX vs GNU divergence.
    awk '
    function strip_line_comment(s,   idx, i, n, c, in_str, in_ch) {
        # Strip `//` line comment, ignoring `//` inside a string or char
        # literal. Conservative: bail if we see unescaped backslash before the
        # string end (we just return the whole line unchanged then — worst
        # case the scanner sees a false comment, but the awk collector only
        # needs to be right for SCP bridge files which never embed `//` inside
        # string literals on fn-declaration lines.
        n = length(s)
        in_str = 0
        in_ch = 0
        for (i = 1; i <= n; i++) {
            c = substr(s, i, 1)
            if (!in_str && !in_ch && c == "\"") { in_str = 1; continue }
            if (in_str && c == "\"") { in_str = 0; continue }
            if (!in_str && !in_ch && c == "\47") { in_ch = 1; continue }
            if (in_ch && c == "\47") { in_ch = 0; continue }
            if (!in_str && !in_ch && c == "/" && substr(s, i + 1, 1) == "/") {
                return substr(s, 1, i - 1)
            }
        }
        return s
    }

    function line_has_mod_open(s) {
        # Matches `mod <ident> {` with a non-identifier char (or SOL) before
        # `mod`. Avoids using `\<` which is GNU-only.
        return (s ~ /^[ \t]*mod[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\{/) \
            || (s ~ /[^A-Za-z0-9_]mod[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\{/)
    }

    function line_has_impl_open(s) {
        # Matches `impl ...` followed (possibly across later lines) by `{`.
        # We only require the `impl` keyword on this line; an `impl` without
        # an opening brace on the same line still starts an impl block whose
        # brace arrives later. The brace counter will bump `brace_depth` when
        # the `{` is seen, so we enter the cfg-test-impl state now and seal
        # the boundary with the first `{` increment. Avoids `\<` (GNU-only).
        return (s ~ /^[ \t]*impl([ \t]|<)/) \
            || (s ~ /^[ \t]*unsafe[ \t]+impl([ \t]|<)/) \
            || (s ~ /[^A-Za-z0-9_]impl([ \t]|<)/)
    }

    function line_has_fn_open(s) {
        # Matches `fn <ident>(` or `fn <ident><` at any indent.
        return (s ~ /fn[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*[(<]/)
    }

    function is_test_gated_cfg_segment(seg,    ng, depth, ch, cur_ident, i, j, n_children, gr, any_not, limit) {
        # Returns 1 iff the cfg(...) payload in seg is satisfied ONLY when
        # test is enabled. Fold semantics per group (rustc-equivalent):
        #   cfg(X)    -> test-gated iff X is test-gated.
        #   all(A, B) compiles iff A && B; test-gated iff ANY child is
        #             test-gated (a single test-gated predicate forces
        #             the conjunction to require test).
        #   any(A, B) compiles iff A || B; test-gated iff EVERY child is
        #             test-gated (any non-test child could activate the
        #             item in production via the disjunction).
        #   not(X)    conservatively NOT test-gated.
        #   bare test -> test-gated (when not inside a not(...) group).
        # Counter-example the older any-everywhere walker misclassified:
        #   #[cfg(all(any(feature = "x", test), not(test)))]
        # is production-only, but the naked test inside the inner any
        # propagates up and marks the item test-gated. Splitting the fold
        # by group op fixes it.
        # Implementation: iterate chars, maintain a stack of open groups
        # keyed by depth. On "(" push a new frame; on ")" fold the frame
        # with its op and push the result as a child of the parent frame.
        # _cfg_op[depth], _cfg_count[depth], _cfg_res[depth SUBSEP idx].
        ng = length(seg)
        depth = 0
        _cfg_op[0] = "cfg"
        _cfg_count[0] = 0
        cur_ident = ""
        split("", _cfg_res)
        i = 1
        limit = ng + 1
        while (i <= limit) {
            if (i <= ng) {
                ch = substr(seg, i, 1)
            } else {
                ch = ")"
            }
            if (i <= ng && ch ~ /[A-Za-z0-9_]/) {
                cur_ident = cur_ident ch
                i = i + 1
                continue
            }
            if (ch == "(") {
                depth = depth + 1
                _cfg_op[depth] = cur_ident
                _cfg_count[depth] = 0
                cur_ident = ""
                i = i + 1
                continue
            }
            if (cur_ident != "") {
                gr = 0
                if (cur_ident == "test") {
                    any_not = 0
                    for (j = 1; j <= depth; j = j + 1) {
                        if (_cfg_op[j] == "not") {
                            any_not = 1
                            break
                        }
                    }
                    if (any_not == 0) {
                        gr = 1
                    }
                }
                _cfg_count[depth] = _cfg_count[depth] + 1
                _cfg_res[depth SUBSEP _cfg_count[depth]] = gr
                cur_ident = ""
            }
            if (ch == ")") {
                if (depth == 0) {
                    i = i + 1
                    continue
                }
                n_children = _cfg_count[depth]
                if (n_children == 0) {
                    gr = 0
                } else if (_cfg_op[depth] == "any") {
                    gr = 1
                    for (j = 1; j <= n_children; j = j + 1) {
                        if (_cfg_res[depth SUBSEP j] == 0) {
                            gr = 0
                            break
                        }
                    }
                } else if (_cfg_op[depth] == "not") {
                    gr = 0
                } else {
                    gr = 0
                    for (j = 1; j <= n_children; j = j + 1) {
                        if (_cfg_res[depth SUBSEP j] == 1) {
                            gr = 1
                            break
                        }
                    }
                }
                for (j = 1; j <= n_children; j = j + 1) {
                    delete _cfg_res[depth SUBSEP j]
                }
                depth = depth - 1
                _cfg_count[depth] = _cfg_count[depth] + 1
                _cfg_res[depth SUBSEP _cfg_count[depth]] = gr
            }
            i = i + 1
        }
        if (_cfg_count[0] >= 1 && _cfg_res[0 SUBSEP 1] == 1) {
            return 1
        }
        return 0
    }

    BEGIN {
        in_cfg_test = 0
        cfg_test_depth = 0
        brace_depth = 0
        pending_cfg_test = 0
        pending_ffi_attr = 0
        # impl_state: 0 = not inside an impl, 1 = inside an FFI-decorated
        # impl block, 2 = inside an undecorated impl block. The brace_depth
        # at which the impl opened is recorded in impl_depth; emission exits
        # the impl when brace_depth drops back to impl_depth (the impl
        # block-closing right-brace). Mirrors the Rust `FfiFnCollector`
        # impl_decorated_stack in
        # `crates/scp-testing/tests/integration/ffi_conformance.rs` — both
        # scanners reject fns inside undecorated impls.
        impl_state = 0
        impl_depth = 0
    }
    {
        # Strip `//` line comments FIRST so neither cfg(test) detection nor
        # fn extraction nor brace counting is poisoned by comment content.
        code = strip_line_comment($0)
        blank = (code ~ /^[ \t]*$/)

        # Detect #[cfg(...)] annotation. Parse the predicate to determine
        # whether the enclosing item is test-ONLY (parity with the Rust
        # `attrs_contain_cfg_test` / `meta_is_test_gated` walker). Handles
        # `#[cfg(test)]`, `#[cfg(any(test, ...))]`, `#[cfg(all(test, ...))]`
        # — AND correctly rejects `#[cfg(not(test))]` / `#[cfg(all(not(test),
        # ...))]` which are production-only gates, not test gates.
        if (match(code, /#\[cfg\([^\]]*\)\]/)) {
            seg2 = substr(code, RSTART, RLENGTH)
            if (is_test_gated_cfg_segment(seg2)) {
                pending_cfg_test = 1
            }
        }

        # Detect any FFI-bridge export attribute on this line. The macros
        # that mark a fn or impl as exported through SCP binding tooling:
        #   PyO3:   #[pyfunction]          (free fn only)
        #           #[pymethods]           (impl block only)
        #   NAPI:   #[napi] / #[napi(...)] (free fn OR impl block)
        #   UniFFI: #[uniffi::export]      (free fn OR impl block)
        # Bare-token and parenthesized-arg forms must both match. Detection
        # mirrors `attrs_have_free_fn_ffi_export` /
        # `attrs_have_impl_block_ffi_export` in the syn scanner; both layers
        # must accept the same surface or an adversary can thread a phantom
        # alias through whichever layer is weaker.
        if (code ~ /#\[pyfunction\]/ \
            || code ~ /#\[pymethods\]/ \
            || code ~ /#\[napi\]/ \
            || code ~ /#\[napi\(/ \
            || code ~ /#\[uniffi::export\]/ \
            || code ~ /#\[uniffi::export\(/) {
            pending_ffi_attr = 1
        }

        # --- Phase A: cfg(test) state transitions (priority over FFI) ---
        consumed = 0
        if (pending_cfg_test && line_has_mod_open(code)) {
            in_cfg_test = 1
            cfg_test_depth = brace_depth
            pending_cfg_test = 0
            pending_ffi_attr = 0
            consumed = 1
        } else if (pending_cfg_test && line_has_impl_open(code)) {
            # Impl-level #[cfg(test)]: the annotation applies to an entire
            # `impl Foo { ... }` block inside a non-test module. Every fn
            # defined in the block must be excluded. We enter the same
            # brace-depth-tracked exclusion state as cfg(test) mod — impl
            # blocks cannot nest and cannot contain `mod`, so the exit
            # condition `brace_depth == cfg_test_depth` applies identically.
            # Real instances exist at `crates/scp-ffi/napi/src/context.rs`
            # and `runtime.rs`; without this branch the awk collector leaks
            # methods from `#[cfg(test)] impl NapiContextHandle { ... }` as
            # production symbols, which an adversary could use to satisfy a
            # phantom alias. Mirrors the Rust `visit_item_impl` guard.
            in_cfg_test = 1
            cfg_test_depth = brace_depth
            pending_cfg_test = 0
            pending_ffi_attr = 0
            consumed = 1
        } else if (pending_cfg_test && line_has_fn_open(code)) {
            # Fn-level #[cfg(test)]: the annotation applies to a single fn
            # inside a non-test module. Suppress the fn for this line by
            # rewriting code to strip out every fn-open token so the later
            # extractor does not pick it up. A bare cfg-only line followed by
            # a fn-declaration line is the common form; the same line carrying
            # both attribute and signature is rare but also handled (we blank
            # every fn-open token on that line).
            gsub(/fn[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*[(<]/, " ", code)
            pending_cfg_test = 0
            pending_ffi_attr = 0
            consumed = 1
        } else if (!blank && pending_cfg_test) {
            # Non-empty line without matching mod/impl/fn — if the line is
            # another attribute (#[doc = "..."], #[allow(...)], #[inline],
            # #[must_use], #[derive(...)], #[cfg_attr(...)], etc.), keep
            # `pending_cfg_test` alive across it: rustfmt often emits
            #
            #     #[cfg(test)]
            #     #[allow(dead_code)]
            #     fn foo() {}
            #
            # and the syn + tree-sitter walkers correctly collect every
            # preceding attribute when deciding whether `foo` is test-gated.
            # Only clear `pending_cfg_test` when we reach a non-attribute
            # non-mod/impl/fn line — at that point the attribute landed on
            # something else (a `use`, `const`, `static`, `struct` etc.)
            # and must not leak onto the next fn.
            if (code !~ /^[ \t]*#!?\[/) {
                pending_cfg_test = 0
            }
        }

        # --- Phase B: FFI-attribute / impl_state transitions ---
        # Run AFTER Phase A so that any cfg(test) handler that fired above
        # has already consumed pending_ffi_attr (test-gated items never
        # become exports, regardless of decoration).
        if (!consumed) {
            if (pending_ffi_attr && line_has_impl_open(code)) {
                # FFI-decorated impl: every fn defined inside the block
                # counts as an export. Mirrors `FfiFnCollector::visit_item_impl`
                # tracking `impl_decorated_stack.last() == true`.
                if (impl_state == 0) {
                    impl_state = 1
                    impl_depth = brace_depth
                }
                pending_ffi_attr = 0
            } else if (line_has_impl_open(code) && impl_state == 0) {
                # Undecorated impl: every fn inside is INVISIBLE to the FFI
                # tooling and must not be collected. The strict scanner
                # closes the phantom-alias hole where someone could add a
                # `pub fn alias_name()` method inside `impl Helper { ... }`
                # (no FFI macro) and satisfy a naive substring check.
                impl_state = 2
                impl_depth = brace_depth
            } else if (!blank && pending_ffi_attr) {
                # Continuation rule for pending_ffi_attr: KEEP alive until
                # the attribute is consumed by a fn / impl emission handler
                # above OR until we see a line that opens a non-fn item
                # the attribute clearly landed on instead. Concretely, the
                # rule "clear only when this line opens a struct / enum /
                # trait / union / mod / const / static / type / use"
                # tolerates the messy multi-line attribute patterns rustfmt
                # produces — e.g.
                #
                #     #[pyfunction]
                #     #[pyo3(name = "bridge_register")]
                #     #[pyo3(signature = (
                #         context_id,
                #         operator_did,
                #         ...
                #     ))]
                #     #[allow(clippy::too_many_arguments)]
                #     pub fn py_bridge_register(...)
                #
                # without clearing pending on the `    context_id,` or
                # `    ))]` continuation lines (which the simpler
                # "starts with #[" check would mishandle). Doc-comment
                # continuation lines have already been stripped to blank
                # by `strip_line_comment` above. An attribute that lands
                # on a struct is correctly absorbed by the struct line so
                # a later, unrelated `fn` cannot inherit the pending
                # decoration.
                if (code ~ /^[ \t]*(pub[ \t]*(\([^)]*\)[ \t]*)?)?(async[ \t]+)?(unsafe[ \t]+)?(extern([ \t]+\"[^\"]*\")?[ \t]+)?(struct|enum|trait|union|mod|const|static|type|use)[ \t]+/) {
                    pending_ffi_attr = 0
                }
            }
        }

        # Track brace depth char-by-char on the COMMENT-STRIPPED source so
        # `//` comments with stray braces do not desynchronize the counter.
        # Brace tracking handles BOTH cfg(test) exit and impl_state exit:
        # cfg_test_depth and impl_depth are independent counters because an
        # adversary could plausibly nest one inside the other (e.g.,
        # `#[cfg(test)] impl Foo { ... }` is a distinct scope from a plain
        # `impl Foo { ... }`).
        n = length(code)
        for (i = 0; i < n; i++) {
            c = substr(code, i + 1, 1)
            if (c == "{") brace_depth++
            else if (c == "}") {
                brace_depth--
                if (in_cfg_test && brace_depth == cfg_test_depth) {
                    in_cfg_test = 0
                }
                if (impl_state > 0 && brace_depth == impl_depth) {
                    impl_state = 0
                    impl_depth = 0
                }
            }
        }

        if (!in_cfg_test) {
            # Strict-scanner emission gate (PR-E #26 hardening). A fn name
            # is collected only when the binding tooling would actually
            # export it:
            #   * impl_state == 1 (inside FFI-decorated impl): every method
            #     counts. The decoration on the impl block applies to all
            #     its methods.
            #   * impl_state == 0 (free) + pending_ffi_attr (free-fn FFI
            #     macro on a preceding line): emit, then consume the
            #     pending flag so it cannot bleed into the next fn.
            #   * impl_state == 2 (undecorated impl): skip; the FFI tooling
            #     never sees these methods.
            #   * impl_state == 0 + !pending_ffi_attr: skip; an undecorated
            #     free fn is not an export.
            # The looser pre-hardening behaviour (emit every `fn NAME(`) is
            # gone. Existing fixtures got `#[napi]` / `#[uniffi::export]`
            # / `#[pyfunction]` decorations on their
            # widget_create production fns; the new
            # `bad-alias-undecorated-fn` fixture exercises the undecorated
            # phantom-alias case the strict scanner now rejects.
            emit = 0
            if (impl_state == 1) {
                emit = 1
            } else if (impl_state == 0 && pending_ffi_attr) {
                emit = 1
            }
            if (emit) {
                emitted_any = 0
                rest = code
                while (match(rest, /fn[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*[(<]/)) {
                    seg = substr(rest, RSTART, RLENGTH)
                    sub(/^fn[ \t]+/, "", seg)
                    sub(/[ \t]*[(<].*$/, "", seg)
                    print seg
                    rest = substr(rest, RSTART + RLENGTH)
                    emitted_any = 1
                }
                # Free-fn decoration is per-fn; impl-block decoration is
                # sticky for the lifetime of the impl block (impl_state).
                # Only consume pending_ffi_attr when we actually emitted a
                # fn name on this line — otherwise the attribute is still
                # waiting for its fn (rustfmt frequently puts the macro
                # alone on one line and the fn signature on the next).
                if (impl_state != 1 && emitted_any) {
                    pending_ffi_attr = 0
                }
            }
        }
    }
    ' "$file"
}

# Build a cached set of function names defined in a bridge.
# Uses a single temp dir with per-bridge files (portable across bash 3.x
# without requiring associative arrays).
CACHE_DIR=""
init_cache_dir() {
    if [[ -z "$CACHE_DIR" ]]; then
        CACHE_DIR=$(mktemp -d -t scp-bridge-symmetry.XXXXXX)
        trap cleanup_cache_dir EXIT
    fi
}
cleanup_cache_dir() {
    # Preserve cache if SCP_KEEP_CACHE is set, for debugging.
    if [[ -n "${SCP_KEEP_CACHE:-}" ]]; then
        echo "KEEPING cache at $CACHE_DIR" >&2
        return 0
    fi
    if [[ -n "$CACHE_DIR" && -d "$CACHE_DIR" ]]; then
        rm -rf "$CACHE_DIR"
    fi
}

cache_bridge_fns() {
    local bridge="$1"
    init_cache_dir
    local cache_file="$CACHE_DIR/fns-$bridge"
    if [[ -f "$cache_file" ]]; then
        return 0
    fi
    local f
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        collect_fn_names_from_file "$f"
    done < <(bridge_sources "$bridge") | sort -u > "$cache_file"
}

# Does the cached set for `bridge` contain function name `name`?
fn_exists_in_bridge() {
    local bridge="$1"
    local name="$2"
    cache_bridge_fns "$bridge"
    local cache_file="$CACHE_DIR/fns-$bridge"
    grep -Fxq -- "$name" "$cache_file"
}

# ---------------------------------------------------------------------------
# Exemption set (single-source precompute).
#
# Writes one `<bridge>|<canonical>` line per documented exemption into
# $CACHE_DIR/exemptions with ONE jq invocation. CI mode and hook mode both
# consult this file via O(1) grep -Fxq, avoiding per-(bridge,op,alias)
# jq invocations.
# ---------------------------------------------------------------------------
EXEMPT_FILE=""
load_exemptions() {
    init_cache_dir
    if [[ -n "$EXEMPT_FILE" && -f "$EXEMPT_FILE" ]]; then
        return 0
    fi
    EXEMPT_FILE="$CACHE_DIR/exemptions"
    jq -r '
        .exemptions | to_entries[] |
        select(.key | startswith("_") | not) |
        .key as $bridge |
        .value[] | "\($bridge)|\(.canonical)"
    ' "$ALIASES_JSON" > "$EXEMPT_FILE"
}

is_op_exempt() {
    local bridge="$1"
    local canonical="$2"
    load_exemptions
    grep -Fxq -- "$bridge|$canonical" "$EXEMPT_FILE"
}

# ---------------------------------------------------------------------------
# CI mode driver
#
# Batches all jq queries up-front to avoid O(ops × bridges) jq invocations.
# Output format: `<canonical>|<bridge>|<alias1>,<alias2>,...`
# (one line per (op, bridge) tuple, aliases comma-separated).
# ---------------------------------------------------------------------------
run_ci_mode() {
    local total_findings=0

    # Pre-cache all three bridges.
    cache_bridge_fns pyo3
    cache_bridge_fns uniffi
    cache_bridge_fns napi
    load_exemptions

    # One jq pass: emit `canonical|bridge|alias1,alias2,...`
    # and check each tuple in a tight bash loop.
    local tuples
    tuples=$(jq -r '
        .operations[] as $op |
        ["pyo3", "uniffi", "napi"][] as $b |
        "\($op.canonical)|\($b)|\(($op[$b] // []) | join(","))"
    ' "$ALIASES_JSON")

    local canonical bridge aliases alias found
    while IFS='|' read -r canonical bridge aliases; do
        [[ -z "$canonical" ]] && continue
        # Documented exemption?
        if is_op_exempt "$bridge" "$canonical"; then
            continue
        fi
        # Check aliases.
        found=0
        IFS=',' read -r -a alias_arr <<< "$aliases"
        for alias in "${alias_arr[@]}"; do
            [[ -z "$alias" ]] && continue
            if fn_exists_in_bridge "$bridge" "$alias"; then
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            echo "FINDING: bridge=$bridge missing operation $canonical (aliases checked: $aliases)"
            total_findings=$((total_findings + 1))
        fi
    done <<< "$tuples"

    echo ""
    echo "check-bridge-symmetry: $total_findings finding(s)"

    if [[ $total_findings -gt 0 ]]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Hook mode driver — only block on regressions in the edited files.
# ---------------------------------------------------------------------------
touched_bridge_for_file() {
    local f="$1"
    case "$f" in
        *"crates/scp-ffi/src/"*)          echo "pyo3" ;;
        *"crates/scp-ffi/uniffi/src/"*)   echo "uniffi" ;;
        *"crates/scp-ffi/napi/src/"*)     echo "napi" ;;
        *)                                 echo "" ;;
    esac
}

# For a single file path, compare current content vs `git show HEAD:<path>`.
# For each function name `fn NAME(` present in HEAD but absent in the edited
# file, check if any sibling bridge still exports it. If yes → regression.
# Additions that siblings lack emit warnings to stdout but do not block.
check_hook_file() {
    local file="$1"
    local bridge
    bridge=$(touched_bridge_for_file "$file")
    if [[ -z "$bridge" ]]; then
        return 0
    fi

    local abs_path
    if [[ "$file" = /* ]]; then
        abs_path="$file"
    else
        abs_path="$REPO_ROOT/$file"
    fi
    # Portable "strip REPO_ROOT/ prefix" — avoids macOS realpath's lack of
    # --relative-to and Linux vs macOS `readlink -f` differences.
    local rel_path
    case "$abs_path" in
        "$REPO_ROOT"/*)
            rel_path="${abs_path#"$REPO_ROOT"/}"
            ;;
        *)
            # The hook runner handed us a path outside the repo. That is a
            # configuration bug — fail loudly rather than silently degrading
            # the regression check into a no-op.
            echo "ERROR: hook received path outside repo: $abs_path (REPO_ROOT=$REPO_ROOT)" >&2
            return 1
            ;;
    esac

    # Extract function names defined in HEAD and in working tree using the
    # SAME awk-based collector as CI mode (`collect_fn_names_from_file`), so
    # hook and CI modes cannot diverge. cfg(test) mod exclusion is applied
    # uniformly — grep-based scanning here was a bypass (a removed canonical
    # alias could be masked by a matching fn inside `#[cfg(test)] mod tests`).
    init_cache_dir
    local head_fns current_fns
    local head_tmp="$CACHE_DIR/head-$(printf '%s' "$rel_path" | tr '/' '_').rs"
    # git show prints to stdout on success and non-zero on missing file/object.
    if git show "HEAD:$rel_path" > "$head_tmp" 2>/dev/null; then
        head_fns=$(collect_fn_names_from_file "$head_tmp" | sort -u)
    else
        # File didn't exist in HEAD — all new. No regression possible.
        head_fns=""
    fi
    rm -f -- "$head_tmp"
    if [[ -f "$abs_path" ]]; then
        current_fns=$(collect_fn_names_from_file "$abs_path" | sort -u)
    else
        current_fns=""
    fi

    local regressions=0

    # Removed functions = HEAD \ current
    local removed
    removed=$(comm -23 <(echo "$head_fns") <(echo "$current_fns") 2>/dev/null || true)
    if [[ -n "$removed" ]]; then
        # For each removed function, check if the canonical (or any alias group
        # containing it) is still required, and whether sibling bridges have it.
        while IFS= read -r fname; do
            [[ -z "$fname" ]] && continue
            # Is this function name listed as an alias for any canonical op
            # in the current bridge? If so, check siblings.
            local canonical
            canonical=$(jq -r --arg b "$bridge" --arg f "$fname" \
                '.operations[] | select(.[$b] | index($f)) | .canonical' \
                "$ALIASES_JSON" | head -n 1)
            if [[ -z "$canonical" ]]; then
                continue
            fi
            # Is ANY sibling still exposing it via any alias?
            local any_sibling=0
            local sib
            for sib in pyo3 uniffi napi; do
                [[ "$sib" == "$bridge" ]] && continue
                local sib_aliases
                sib_aliases=$(jq -r --arg c "$canonical" --arg b "$sib" \
                    '.operations[] | select(.canonical == $c) | .[$b][]' \
                    "$ALIASES_JSON")
                while IFS= read -r sa; do
                    [[ -z "$sa" ]] && continue
                    if fn_exists_in_bridge "$sib" "$sa"; then
                        any_sibling=1
                        break 2
                    fi
                done <<< "$sib_aliases"
            done
            if [[ $any_sibling -eq 1 ]]; then
                echo "REGRESSION: $rel_path removed '$fname' (canonical: $canonical) — sibling bridges still export this operation." >&2
                regressions=$((regressions + 1))
            fi
        done <<< "$removed"
    fi

    # Added functions = current \ HEAD — emit warnings to stdout for alias hits
    local added
    added=$(comm -13 <(echo "$head_fns") <(echo "$current_fns") 2>/dev/null || true)
    if [[ -n "$added" ]]; then
        while IFS= read -r fname; do
            [[ -z "$fname" ]] && continue
            local canonical
            canonical=$(jq -r --arg b "$bridge" --arg f "$fname" \
                '.operations[] | select(.[$b] | index($f)) | .canonical' \
                "$ALIASES_JSON" | head -n 1)
            if [[ -z "$canonical" ]]; then
                continue
            fi
            # Siblings missing?
            local missing_sibs=()
            local sib
            for sib in pyo3 uniffi napi; do
                [[ "$sib" == "$bridge" ]] && continue
                if is_op_exempt "$sib" "$canonical"; then continue; fi
                local sib_aliases
                sib_aliases=$(jq -r --arg c "$canonical" --arg b "$sib" \
                    '.operations[] | select(.canonical == $c) | .[$b][]' \
                    "$ALIASES_JSON")
                local found_sib=0
                while IFS= read -r sa; do
                    [[ -z "$sa" ]] && continue
                    if fn_exists_in_bridge "$sib" "$sa"; then
                        found_sib=1
                        break
                    fi
                done <<< "$sib_aliases"
                if [[ $found_sib -eq 0 ]]; then
                    missing_sibs+=("$sib")
                fi
            done
            if [[ ${#missing_sibs[@]} -gt 0 ]]; then
                echo "warning: added '$fname' (canonical: $canonical) — sibling bridges without this op: ${missing_sibs[*]}"
            fi
        done <<< "$added"
    fi

    return "$regressions"
}

run_hook_mode() {
    # Fast bail if none of the files are under crates/scp-ffi/.
    local any_ffi=0
    local f
    for f in "${HOOK_FILES[@]}"; do
        if [[ "$f" == *"crates/scp-ffi/"* ]]; then
            any_ffi=1
            break
        fi
    done
    if [[ $any_ffi -eq 0 ]]; then
        return 0
    fi

    # Pre-load the exemption set once for the whole hook invocation.
    load_exemptions

    local total_block=0
    local had_error=0
    for f in "${HOOK_FILES[@]}"; do
        set +e
        check_hook_file "$f"
        local rc=$?
        set -e
        if [[ $rc -eq 1 ]]; then
            # Path-outside-repo or other fail-loud error: mark and keep
            # scanning the rest so the operator sees every bad path at once.
            had_error=1
        else
            total_block=$((total_block + rc))
        fi
    done

    if [[ $had_error -eq 1 ]]; then
        return 1
    fi
    if [[ $total_block -gt 0 ]]; then
        return 2
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
if [[ "$MODE" == "hook" ]]; then
    run_hook_mode
    exit $?
else
    run_ci_mode
    exit $?
fi
