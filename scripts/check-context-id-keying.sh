#!/usr/bin/env bash
# check-context-id-keying.sh — CI tripwire enforcing the ADR-056
# single-chokepoint convention for context-id keying, across BOTH the runtime
# core and the FFI bridges.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# ADR-056 (Canonical Context Identity = 32-byte digest): a context's canonical
# identity IS its 32-byte digest; the id STRING is `hex(digest)`. Any layer
# MUST resolve a context-id string to keying bytes by DECODING the hex (for a
# real 64-hex id) — never by RE-HASHING it. Re-hashing a real id with the raw
# SHA-256 primitive `context::context_id_bytes(id)` is a DOUBLE HASH
# (`SHA-256(hex(digest))`) that diverges from the digest the §6.2.4 wire saga,
# the MLS group, the sender keys, and the event log all address — the
# double-hash fail-open the canonical-digest fix closed. Adversarial review
# later found four FFI event-log sites still calling the raw primitive (via the
# `scp_core::` re-export), silently keying the wrong event-log slot (empty
# queries + empty inclusion/absence proofs for every real context — a
# fail-OPEN).
#
# Every context-id → keying-bytes resolution MUST therefore funnel through the
# single chokepoint `scp_runtime::context::state::context_id_to_bytes` (reached
# from the FFI bridges as `scp_core::context::state::context_id_to_bytes`),
# which decodes a canonical 64-hex id and falls back to the raw SHA-256
# primitive ONLY for synthetic / non-context labels that were never 64-hex.
#
# ---------------------------------------------------------------------------
# WHAT THIS GATE IS — AND IS NOT
# ---------------------------------------------------------------------------
# This is a COARSE, LINE-BASED defense-in-depth TRIPWIRE for the COMMON
# accidental-copy regression (a new keying site copies the raw primitive
# instead of the chokepoint). It is NOT a security boundary and NOT a proof of
# correctness. The REAL guarantee is the chokepoint resolver
# `context_id_to_bytes` itself — the single source of truth for keying bytes.
#
# This tripwire targets ONLY the common accidental-copy shape: fully-qualified
# `scp_protocol::`/`scp_core::context::context_id_bytes(` calls, plus a bare
# `context_id_bytes(` call in a file that imports the raw symbol unqualified.
# An accidental copy inherits the surrounding fully-qualified idiom, so those
# shapes are what a real regression looks like. DELIBERATE evasion shapes — a
# symbol alias (`use … context_id_bytes as raw; raw(id)`), a module alias
# (`use scp_core::context as cx; cx::context_id_bytes(id)`), a bare
# module-path, or a multiline-split call — are insider shapes that cannot arise
# from an accidental copy-paste. They are EXPLICITLY OUT OF SCOPE here and are
# NOT chased: doing so would turn this into an ever-expanding denylist of "one
# more spelling." Those shapes are closed instead by the principled compiler
# enforcement (see INTERIM note below), not by this script.
#
# INTERIM: this is a temporary coarse tripwire. The PRINCIPLED, compiler-
# enforced path is a `ContextDigest` newtype that ONLY the chokepoint resolver
# can mint, so the raw primitive's bytes can never reach a keying call site —
# making every evasion shape a compile error, not a grep target. When that
# newtype lands, DELETE this script outright; do NOT extend it with more
# call-shapes in the meantime.
#
# Known, accepted blind spots (coarse by design — do NOT grow this into a
# Rust lexer):
#   - A multiline-split qualified call, e.g.
#         scp_protocol::context::
#             context_id_bytes(id)
#     is line-based-evadable here. It is caught instead by `cargo fmt --check`
#     in CI: rustfmt never emits that split, so any such call fails formatting.
#   - The test-scope tracker (below) strips `//` line comments and string/char
#     literals before arming on `#[cfg(test)]` and before counting braces, so a
#     prose mention of `#[cfg(test)]` or a stray brace inside a comment/literal
#     no longer miscounts. BLOCK comments (`/* … */`) are NOT stripped and
#     remain a coarse blind spot — acceptable, because they never appear on an
#     attribute line or a raw-primitive keying line.
#
# ---------------------------------------------------------------------------
# WHAT IT SCANS / MATCHES
# ---------------------------------------------------------------------------
# Scans `crates/scp-runtime/src`, `crates/scp-ffi` (the latter recursively
# covers `src/`, `napi/src/`, `uniffi/src/`, `wasm/`), AND `crates/scp-testing/
# src` (the E2E full-stack harness keys real contexts too). It FAILS if any
# PRODUCTION site calls the raw primitive, matched as any of:
#
#   - the qualified `scp_protocol::context::context_id_bytes(` spelling, OR
#   - the qualified `scp_core::context::context_id_bytes(` spelling (the
#     literal spelling the FFI fail-open bug used — matching it is required to
#     catch the real regression), OR
#   - a bare `context_id_bytes(` call in a file that imports the raw symbol
#     unqualified (`use {scp_protocol,scp_core}::context::{ … context_id_bytes …
#     }`) — the realistic accidental shape when a file already imports the raw
#     symbol for a legitimate synthetic-label use.
#
# …OUTSIDE a small, positively-enumerated allowlist:
#
#   (i)  the resolver's OWN fallback in `state.rs` — `context_id_to_bytes`
#        delegates to the raw primitive for non-64-hex labels; this is the
#        single permitted production call, by construction.
#   (ii) the documented synthetic `"identity-private-state"` site in
#        `supervisor.rs` (`recovery_send_notification_direct`, §9.12 PSK
#        rotation) — a never-registered pseudo-context that is never 64-hex and
#        is deliberately hashed.
#
# The allowlist anchors match the `scp_protocol::…` text those production sites
# use. All four FFI sites are fixed to the chokepoint, so there are NO scp-ffi
# allowlist entries.
#
# Test scope is exempt (it keys synthetic `"ctx-…"` / fixture labels and may
# call the primitive directly):
#   - any `*_tests.rs` file (whole-file test module),
#   - any `testing.rs` file (test-support module that keys synthetic fixtures),
#   - and code inside a `#[cfg(test)]` item, tracked by BRACE DEPTH so that
#     production code AFTER an early test module is NOT exempted.
#
# This is a POSITIVE BOUNDED allowlist (two named production sites), not a
# denylist chasing spellings.
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   bash scripts/check-context-id-keying.sh             # scan the real tree
#   bash scripts/check-context-id-keying.sh --self-test # prove the gate is alive
#
# Exit codes:
#   0  — every raw-primitive call is allowlisted or in test scope
#   1  — a raw-primitive call appeared at a non-allowlisted production site,
#        or a self-test expectation failed
#   2  — invocation error (a scoped source directory is missing)
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). POSIX bash + grep +
# awk only. No ripgrep, no GNU-specific flags.

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

# The raw SHA-256 primitive. Matches BOTH qualified call spellings:
#   - `scp_protocol::context::context_id_bytes(` (the routing primitive's home)
#   - `scp_core::context::context_id_bytes(`     (the facade re-export — the
#                                                 literal spelling the FFI bug
#                                                 used)
# plus a bare `context_id_bytes(` call IN A FILE THAT IMPORTS the raw primitive
# unqualified (see RAW_IMPORT_RE). The bare `fn context_id_bytes` local wrappers
# in builder.rs / ttl.rs delegate to the chokepoint and are NOT the primitive —
# they live in files that do NOT import the raw symbol, so a bare call there is
# not flagged. Aliased / module-path spellings are deliberately NOT matched (see
# the out-of-scope note in the header).
RAW_QUALIFIED_PROTOCOL='scp_protocol::context::context_id_bytes('
RAW_QUALIFIED_CORE='scp_core::context::context_id_bytes('
# Unaliased brace-group import of the raw symbol, from either crate.
RAW_IMPORT_RE='use[[:space:]]+scp_(protocol|core)::context::\{[^}]*context_id_bytes'

# ---------------------------------------------------------------------------
# Positively-enumerated PRODUCTION allowlist.
#
# Format: "REPO_REL_PATH|ANCHOR_SUBSTRING|REASON"
#   REPO_REL_PATH  — exact source file permitted to hold a production call.
#   ANCHOR_SUBSTRING — a stable substring that MUST appear on the offending
#                      line for it to be allowlisted (pins the specific call,
#                      so a new unrelated call in the same file is still
#                      caught).
#   REASON         — why this site is permitted.
# ---------------------------------------------------------------------------
ALLOWLIST=(
    "crates/scp-runtime/src/context/state.rs|scp_protocol::context::context_id_bytes(context_id)|ADR-056 resolver fallback: context_id_to_bytes delegates to the raw primitive for non-64-hex labels"
    "crates/scp-runtime/src/context/supervisor/supervisor.rs|let context_id_bytes = scp_protocol::context::context_id_bytes(context_id)|ADR-056 synthetic identity-private-state (recovery_send_notification_direct, §9.12) — deliberately hashed, never a real 64-hex id"
)

# Directories scanned. ADR-056's chokepoint convention is a cross-layer
# property: the runtime core, the FFI bridges (which reach the chokepoint via
# the `scp_core::` re-export), AND the scp-testing full-stack harness (which
# keys real contexts in its E2E `add_member` path). `find … -name '*.rs'`
# recurses, so listing `crates/scp-ffi` covers `src/`, `napi/src/`,
# `uniffi/src/`, and `wasm/`. The `tests/` integration dir is NOT under `src/`,
# so it is not scanned.
SCAN_DIRS=(
    "crates/scp-runtime/src"
    "crates/scp-ffi"
    "crates/scp-testing/src"
)

# ---------------------------------------------------------------------------
# is_allowlisted FILE LINE_TEXT  ->  0 if allowlisted, 1 otherwise
# ---------------------------------------------------------------------------
is_allowlisted() {
    local file="$1" line_text="$2" entry path anchor
    for entry in "${ALLOWLIST[@]}"; do
        IFS='|' read -r path anchor _reason <<< "$entry"
        if [[ "$file" == "$path" ]] && [[ "$line_text" == *"$anchor"* ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# scan_tree ROOT  ->  prints "FILE:LINENO:TEXT" for every NON-allowlisted,
#                     NON-test production call of the raw primitive.
#
# Raw-primitive call shapes detected:
#   - qualified `scp_protocol::context::context_id_bytes(` (always),
#   - qualified `scp_core::context::context_id_bytes(`     (always),
#   - bare `context_id_bytes(` when the file imports the raw symbol unqualified.
#
# Test scope (exempt), tracked by BRACE DEPTH on a comment/literal-stripped view
# of each line so that production code AFTER an early `#[cfg(test)]` module is
# NOT exempted, and so that a prose `#[cfg(test)]` mention or a brace inside a
# string/comment does not miscount:
#   - a file whose basename is `*_tests.rs` or `testing.rs` (whole-file exempt),
#   - any line inside a `#[cfg(test)]` item (the item's brace span).
# ---------------------------------------------------------------------------
scan_tree() {
    local root="$1"
    [[ -d "$root" ]] || { printf '%serror:%s scan dir missing: %s\n' "$C_RED" "$C_RESET" "$root" >&2; exit 2; }

    local f basename imports_raw
    # NUL-safe file walk; only *.rs.
    while IFS= read -r -d '' f; do
        basename="${f##*/}"
        # Whole-file test / test-support modules: exempt entirely.
        [[ "$basename" == *_tests.rs ]] && continue
        [[ "$basename" == testing.rs ]] && continue

        # Does this file import the raw primitive unqualified (brace group)?
        if grep -Eq "$RAW_IMPORT_RE" -- "$f" 2>/dev/null; then
            imports_raw=1
        else
            imports_raw=0
        fi

        # Emit every raw-primitive call line. Qualified spellings always; bare
        # only when the file imports the raw symbol unqualified. Aliased /
        # module-path spellings are deliberately NOT matched (insider shapes,
        # out of scope — see the header).
        awk -v qual_protocol="$RAW_QUALIFIED_PROTOCOL" \
            -v qual_core="$RAW_QUALIFIED_CORE" \
            -v imports_raw="$imports_raw" \
            -v fname="$f" '
            BEGIN {
                # Test-scope brace-depth tracker state.
                depth = 0          # running brace depth across the file
                pending = 0        # saw #[cfg(test)], awaiting the opening brace
                in_test = 0        # currently inside a #[cfg(test)] item
                test_open_depth = 0
            }
            {
                line = $0

                # --- detect raw-primitive call shapes on THIS line -----------
                # Runs on the ORIGINAL line text — the call is real code.
                is_raw = 0
                if (index(line, qual_protocol) > 0) is_raw = 1
                if (index(line, qual_core) > 0)     is_raw = 1
                if (imports_raw == 1) {
                    if (line ~ /(^|[^:_[:alnum:]])context_id_bytes\(/ && line !~ /fn[[:space:]]+context_id_bytes/) {
                        is_raw = 1
                    }
                }

                # --- build a comment/literal-stripped "code" view ------------
                # Used ONLY for structural decisions (cfg-test arming + brace
                # depth), so a prose `#[cfg(test)]` mention or a brace inside a
                # string/char literal or `//` comment cannot miscount. Block
                # comments (/* ... */) are a documented coarse blind spot — they
                # never appear on an attribute or keying line.
                code = line
                gsub(/"([^"\\]|\\.)*"/, "", code)            # strip string literals
                gsub(/'\''([^'\''\\]|\\.)*'\''/, "", code)   # strip char literals
                sub(/\/\/.*/, "", code)                      # strip // line-comment tail (incl ///)
                # NOTE: stripping balanced string/char literals first removes
                # their inner braces; the trailing // strip then drops any line
                # comment. Block comments (/* ... */) remain a coarse blind spot.

                # --- brace-depth test-scope tracking -------------------------
                # depth_before = depth at the START of this line.
                depth_before = depth
                opens = gsub(/{/, "{", code)   # count "{" on the code view
                closes = gsub(/}/, "}", code)  # count "}" on the code view

                # Decide test-scope membership for THIS line BEFORE mutating
                # in_test on its own closing brace, so the line that closes the
                # test item is itself still treated as test scope.
                this_line_in_test = in_test

                # Is this code line the leading `#[cfg(test)]` attribute itself?
                is_cfg_attr = (code ~ /^[[:space:]]*#\[cfg\(test\)\]/)

                # Arm the tracker ONLY on a LEADING `#[cfg(test)]` attribute on
                # the code view — never a prose mention buried in a comment or
                # string (those are stripped from `code`, and the leading-token
                # anchor is the real guard). The attribute governs the very next
                # item; the item may open a block on this same line or later.
                if (is_cfg_attr) {
                    pending = 1
                }

                # If armed and this line opens a block, record the item-open
                # depth: this is a `#[cfg(test)]` item with a body (mod/fn/impl).
                if (pending == 1 && opens > 0) {
                    test_open_depth = depth_before
                    in_test = 1
                    this_line_in_test = 1
                    pending = 0
                }
                # If armed but the awaited item turns out to be BRACELESS — a
                # `#[cfg(test)] use …;` / `#[cfg(test)] mod foo;` etc., i.e. the
                # next code-bearing line carries a `;` and opens no block — then
                # the attribute did NOT open a test window; disarm so following
                # production code is not wrongly exempted. (Skip the attribute
                # line itself and blank/comment-only lines.)
                else if (pending == 1 && !is_cfg_attr && code ~ /[^[:space:]]/ && index(code, ";") > 0) {
                    pending = 0
                }

                # Update running depth by the net brace delta on this line.
                depth = depth + opens - closes

                # If we were in a test item and depth has returned to the item
                # open depth, the test item has closed.
                if (in_test == 1 && depth <= test_open_depth) {
                    in_test = 0
                }

                # --- emit -----------------------------------------------------
                if (is_raw && this_line_in_test == 0) {
                    printf "%s:%d:%s\n", fname, NR, $0
                }
            }
        ' "$f"
    done < <(find "$root" -name '*.rs' -type f -print0)
}

# ---------------------------------------------------------------------------
# run_real_check ROOT...  ->  exit 0 (clean) / 1 (violation)
#   Accepts one or more scan roots; scans each and aggregates.
# ---------------------------------------------------------------------------
run_real_check() {
    local raw="" fail=0 file lineno text root rest
    for root in "$@"; do
        raw+="$(scan_tree "$root")"$'\n'
    done

    printf '\n%scontext-id keying scan (ADR-056 single chokepoint):%s\n' "$C_DIM" "$C_RESET"

    # Strip blank lines that the per-root accumulation can introduce.
    raw="$(printf '%s' "$raw" | grep -v '^[[:space:]]*$' || true)"

    if [[ -z "$raw" ]]; then
        printf '  %sno production raw-primitive calls found at all%s\n' "$C_GREEN" "$C_RESET"
        printf '%sPASSED%s: every context-id keying site routes through context_id_to_bytes.\n' "$C_GREEN" "$C_RESET"
        return 0
    fi

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        file="${match%%:*}"
        rest="${match#*:}"
        lineno="${rest%%:*}"
        text="${rest#*:}"
        if is_allowlisted "$file" "$text"; then
            printf '  %s[allow]%s %s:%s\n' "$C_GREEN" "$C_RESET" "$file" "$lineno"
        else
            fail=1
            printf '  %s[DENY]%s %s:%s\n' "$C_RED" "$C_RESET" "$file" "$lineno"
            printf '      %s%s%s\n' "$C_DIM" "$text" "$C_RESET" >&2
        fi
    done <<< "$raw"

    if [[ "$fail" -eq 0 ]]; then
        printf '%sPASSED%s: every production raw-primitive call is allowlisted (ADR-056).\n' "$C_GREEN" "$C_RESET"
        return 0
    fi

    printf '\n%sFAILED%s: a production site calls the raw SHA-256 primitive\n' "$C_RED" "$C_RESET" >&2
    printf '`context::context_id_bytes(...)` (scp_protocol or scp_core) outside the ADR-056 allowlist.\n' >&2
    printf 'Route context-id keying through `scp_core::context::state::context_id_to_bytes`\n' >&2
    printf '(it DECODES a real 64-hex id and only hashes genuine non-context labels).\n' >&2
    printf 'See .docs/adrs/ADR-056-canonical-context-identity.md\n' >&2
    return 1
}

# ---------------------------------------------------------------------------
# Self-test: build a throwaway tree, plant a battery of calls covering every
# detection / exemption rule, and assert the gate's verdicts.
# ---------------------------------------------------------------------------
run_self_test() {
    local tmp ok=1
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    # Mirror the real allowlisted paths so the anchor match applies.
    mkdir -p "$tmp/crates/scp-runtime/src/context/supervisor"
    mkdir -p "$tmp/crates/scp-ffi/src"
    local state_f="$tmp/crates/scp-runtime/src/context/state.rs"
    local sup_f="$tmp/crates/scp-runtime/src/context/supervisor/supervisor.rs"
    local bad_f="$tmp/crates/scp-runtime/src/context/messaging_helpers.rs"
    local core_f="$tmp/crates/scp-runtime/src/context/core_spelling.rs"
    local ffi_f="$tmp/crates/scp-ffi/src/event_log.rs"
    local early_f="$tmp/crates/scp-runtime/src/context/early_test.rs"
    local testing_f="$tmp/crates/scp-ffi/src/testing.rs"
    local trailtest_f="$tmp/crates/scp-runtime/src/context/export_import.rs"
    # New lexing-soundness fixtures (Task 1).
    local doccomment_f="$tmp/crates/scp-runtime/src/context/doc_mention.rs"
    local strbrace_f="$tmp/crates/scp-runtime/src/context/str_brace.rs"
    local cfguse_f="$tmp/crates/scp-runtime/src/context/cfg_use.rs"

    # (i) allowlisted resolver fallback in state.rs.
    {
        echo 'pub fn context_id_to_bytes(context_id: &str) -> [u8; 32] {'
        echo '    scp_protocol::context::context_id_bytes(context_id)'
        echo '}'
    } > "$state_f"

    # (ii) allowlisted synthetic site in supervisor.rs.
    {
        echo 'fn recovery_send_notification_direct(context_id: &str) {'
        echo '    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);'
        echo '}'
    } > "$sup_f"

    # (BAD-protocol) forbidden production call (scp_protocol spelling) at a
    # non-allowlisted site, before any test module: MUST be denied.
    {
        echo 'pub fn destroy(context_id: &str) {'
        echo '    let ctx_bytes = scp_protocol::context::context_id_bytes(context_id);'
        echo '}'
    } > "$bad_f"

    # (BAD-core) forbidden production call using the `scp_core::` spelling — the
    # literal spelling the FFI fail-open bug used: MUST be denied.
    {
        echo 'pub fn query(context_id: &str) {'
        echo '    let ctx_bytes = scp_core::context::context_id_bytes(context_id);'
        echo '}'
    } > "$core_f"

    # (BAD-ffi) forbidden production call under crates/scp-ffi/src/ — proves
    # scp-ffi is scanned: MUST be denied.
    {
        echo 'pub fn event_log_query(context_id: &str) {'
        echo '    let ctx_id_bytes = scp_core::context::context_id_bytes(context_id);'
        echo '}'
    } > "$ffi_f"

    # (EARLY-TEST) an EARLY #[cfg(test)] module (closing before EOF) followed by
    # a PRODUCTION raw call: the production call MUST be denied (B4 soundness).
    {
        echo '#[cfg(test)]'
        echo 'mod helpers {'
        echo '    pub fn h() {'
        echo '        let _ = scp_protocol::context::context_id_bytes("ctx-fixture");'
        echo '    }'
        echo '}'
        echo ''
        echo 'pub fn production_after_test(context_id: &str) {'
        echo '    let ctx_bytes = scp_protocol::context::context_id_bytes(context_id);'
        echo '}'
    } > "$early_f"

    # (TESTING) a whole-file `testing.rs` raw call: MUST be exempt.
    {
        echo 'pub fn fixture() {'
        echo '    let _ = scp_protocol::context::context_id_bytes("ctx-fixture");'
        echo '}'
    } > "$testing_f"

    # (TRAILING-TEST) a raw-primitive call inside an end-of-file #[cfg(test)]
    # module: MUST be exempt.
    {
        echo 'pub fn nothing() {}'
        echo '#[cfg(test)]'
        echo 'mod tests {'
        echo '    #[test]'
        echo '    fn t() {'
        echo '        let _ = scp_protocol::context::context_id_bytes("ctx-test");'
        echo '    }'
        echo '}'
    } > "$trailtest_f"

    # (DOC-MENTION) a `///` doc comment that merely MENTIONS `#[cfg(test)]`
    # above a PRODUCTION raw call, with NO real test module. The old line-based
    # arming would fire on the prose mention and silently exempt the call
    # (fail-OPEN); with comment-stripping + leading-token arming, the call MUST
    # be DENIED. Note: there is a stray `{` inside the comment to also prove a
    # comment brace does not inflate depth.
    {
        echo '/// Production keying. Do NOT confuse this with a #[cfg(test)] helper {'
        echo 'pub fn doc_mention_keying(context_id: &str) {'
        echo '    let ctx_bytes = scp_protocol::context::context_id_bytes(context_id);'
        echo '}'
    } > "$doccomment_f"

    # (STR-BRACE) a trailing #[cfg(test)] mod whose FIRST #[test] fn contains a
    # string literal with a stray `}`; a SECOND #[test] fn then makes a raw
    # call. The old naive brace count would close the test window early on the
    # literal `}` and wrongly DENY the second call (false-POSITIVE / CI break).
    # With literal-stripping the second call MUST stay exempt.
    {
        echo 'pub fn prod_noop() {}'
        echo '#[cfg(test)]'
        echo 'mod tests {'
        echo '    #[test]'
        echo '    fn first() {'
        echo '        let s = "x } y";'
        echo '        let _ = s;'
        echo '    }'
        echo '    #[test]'
        echo '    fn second() {'
        echo '        let _ = scp_protocol::context::context_id_bytes("ctx-second");'
        echo '    }'
        echo '}'
    } > "$strbrace_f"

    # (CFG-USE) a BRACELESS `#[cfg(test)] use …;` line followed later by a
    # PRODUCTION raw call. The braceless cfg-test line must NOT open a test
    # window (no `{`), so the later production call MUST be DENIED.
    {
        echo '#[cfg(test)]'
        echo 'use std::collections::HashMap;'
        echo ''
        echo 'pub fn after_cfg_use(context_id: &str) {'
        echo '    let ctx_bytes = scp_protocol::context::context_id_bytes(context_id);'
        echo '}'
    } > "$cfguse_f"

    printf '%sself-test:%s planted forbidden (protocol/core/ffi/early-after-test/doc-mention/cfg-use) + allowlisted + exempt (testing/trailing-test/str-brace-2nd) calls\n' "$C_DIM" "$C_RESET"

    # Expect the real-check logic to DENY the forbidden files and allow/exempt
    # the rest. Scan BOTH roots (runtime + ffi).
    local out rc=0
    out="$(run_real_check "$tmp/crates/scp-runtime/src" "$tmp/crates/scp-ffi" 2>&1)" || rc=$?

    # Helper: assert a DENY line names the given basename.
    assert_deny() {
        local needle="$1" label="$2"
        if grep -E "\[DENY\].*${needle}" <<< "$out" >/dev/null 2>&1; then
            printf '  %sOK%s   %s → DENY\n' "$C_GREEN" "$C_RESET" "$label"
        else
            printf '  %sFAIL%s %s was NOT denied\n' "$C_RED" "$C_RESET" "$label" >&2
            ok=0
        fi
    }
    # Helper: assert a basename never appears in output at all (fully exempt).
    assert_exempt() {
        local needle="$1" label="$2"
        if ! grep -q "$needle" <<< "$out"; then
            printf '  %sOK%s   %s → exempt\n' "$C_GREEN" "$C_RESET" "$label"
        else
            printf '  %sFAIL%s %s was not exempted\n' "$C_RED" "$C_RESET" "$label" >&2
            ok=0
        fi
    }

    # 1. scp_protocol-spelled forbidden call → DENY.
    assert_deny "messaging_helpers.rs" "forbidden scp_protocol:: production call"
    # 2. scp_core-spelled forbidden call → DENY (new spelling).
    assert_deny "core_spelling.rs" "forbidden scp_core:: production call"
    # 3. forbidden call under crates/scp-ffi/src → DENY (scp-ffi is scanned).
    assert_deny "event_log.rs" "forbidden production call in scp-ffi"
    # 4. production call AFTER an early test module → DENY (B4 soundness).
    assert_deny "early_test.rs" "production call after an early #[cfg(test)] module"
    # 5. production call below a `///` doc comment that MENTIONS #[cfg(test)] →
    #    DENY (fail-open closed: prose mention must not arm test scope).
    assert_deny "doc_mention.rs" "production call under a doc-comment #[cfg(test)] mention"
    # 6. production call after a BRACELESS `#[cfg(test)] use …;` → DENY
    #    (braceless cfg-test must not open a test window).
    assert_deny "cfg_use.rs" "production call after a braceless #[cfg(test)] use"
    # 7. Overall verdict must be failure (rc != 0).
    if [[ "$rc" -ne 0 ]]; then
        printf '  %sOK%s   overall verdict = FAIL with forbidden calls present\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %sFAIL%s gate passed despite forbidden calls\n' "$C_RED" "$C_RESET" >&2
        ok=0
    fi
    # 8. The allowlisted sites must appear but NOT as DENY.
    if grep -q "state.rs" <<< "$out" && grep -q "supervisor.rs" <<< "$out" \
        && ! grep -E "state.rs.*\[DENY\]|supervisor.rs.*\[DENY\]" <<< "$out"; then
        printf '  %sOK%s   allowlisted sites → allow\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %sFAIL%s an allowlisted site was misclassified\n' "$C_RED" "$C_RESET" >&2
        ok=0
    fi
    # 9. Trailing end-of-file test-module call → exempt.
    assert_exempt "export_import.rs" "trailing #[cfg(test)] call"
    # 10. testing.rs whole-file → exempt.
    assert_exempt "testing.rs" "testing.rs whole-file call"
    # 11. Second #[test] fn's raw call after a string with a stray `}` in the
    #     first #[test] fn → exempt (literal-stripping keeps the test window
    #     open; no false-positive DENY).
    assert_exempt "str_brace.rs" "raw call in 2nd #[test] after a stray-brace string literal"

    if [[ "$ok" -eq 1 ]]; then
        printf '%sself-test PASSED%s\n' "$C_GREEN" "$C_RESET"
        return 0
    fi
    printf '%sself-test FAILED%s\n' "$C_RED" "$C_RESET" >&2
    return 1
}

# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------
case "${1:-}" in
    --self-test)
        run_self_test
        ;;
    "")
        run_real_check "${SCAN_DIRS[@]}"
        ;;
    *)
        printf '%serror:%s unknown argument: %s (use --self-test or no args)\n' "$C_RED" "$C_RESET" "$1" >&2
        exit 2
        ;;
esac
