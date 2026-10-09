#!/usr/bin/env bash
# check-deleted-primitives.sh — CI gate banning primitives that must not
# reappear once the actor-per-context refactor (ADR-049) has deleted them.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Greps for literal token patterns inside a configured directory scope and
# fails the build if any are found. Each ban entry specifies:
#   - a token (regex)
#   - a directory scope (find path)
#   - a file-name filter (find -name)
#   - a reason string (prints on failure)
#
# Test submodules (`**/tests/**` and `**/tests.rs`) are included in the scan
# by default. Commit 12 of the actor refactor deletes the old types from
# production AND test code — nothing remains.
#
# ---------------------------------------------------------------------------
# INITIAL STATE: EMPTY BAN LIST
# ---------------------------------------------------------------------------
# Commit 3 of the actor refactor lands this script with ZERO ban entries.
# Commits 4-11 gradually move state into the actor system; commit 12
# deletes the old primitives and ACTIVATES the bans by appending entries
# to the BAN_ENTRIES array below. The script exists in this empty state
# because it must exercise on current code without reporting any
# violations — later commits populate it.
#
# The expected final set (populated by commit 12) per the plan:
#   scp-runtime/:
#     - relock_context
#     - ContextGeneration
#     - next_generation
#     - Mutex<PerContextState>
#     - RwLock<ContextInner>
#   scp-runtime/src/crypto/:
#     - pending_joins
#
# When you activate a ban: append a line to BAN_ENTRIES with the canonical
# pipe-delimited format documented below, and add a smoke assertion to
# SMOKE_TESTS that confirms the regex pattern is what you think it is.
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   bash scripts/check-deleted-primitives.sh
#
# Exit codes:
#   0  — no banned tokens found (or ban list empty)
#   1  — a banned token was found
#   2  — invocation error (missing directory, malformed ban entry)
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Uses only POSIX-
# compatible bash + grep + find. No ripgrep, no GNU-specific flags.

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
# BAN ENTRIES
#
# Format: "TOKEN|SCOPE_DIR|FILE_GLOB|REASON"
#   TOKEN     — grep -E regex to match. Escape regex metacharacters.
#   SCOPE_DIR — repo-relative directory to search.
#   FILE_GLOB — find -name pattern (e.g. "*.rs").
#   REASON    — short user-facing explanation.
#
# INITIALLY EMPTY. Commit 12 of the actor refactor populates this.
# ---------------------------------------------------------------------------
# ADR-049 Phase 2A finalization: the last `&Supervisor` caller of the
# per-context `contexts` DashMap lock primitives (the legacy tools economy
# wrapper `invoke_tool_with_economy`) moved to the actor-split economy
# reserve/settle path. The DashMap, its `Arc<Mutex<PerContextState>>`
# entries, and the lock/relock/get-arc accessors are deleted. Per-context
# state now lives ONLY inside the per-context actor; these bans stop any
# future refactor from reintroducing supervisor-side per-context locking.
#
# `contexts_ref` uses a leading non-`_` guard so it bans the deleted
# `.contexts_ref()` accessor without false-matching the legitimate
# `standing_contexts_ref` / `local_dids_ref` supervisor accessors.
BAN_ENTRIES=(
    "Mutex<PerContextState>|crates/scp-runtime|*.rs|Actor-per-context refactor (ADR-049) deleted the per-context Mutex; state is actor-owned"
    "get_context_arc|crates/scp-runtime|*.rs|Actor-per-context refactor (ADR-049) deleted the contexts DashMap accessor"
    "lock_context|crates/scp-runtime|*.rs|Actor-per-context refactor (ADR-049) deleted the per-context lock/relock primitives"
    "relock_context|crates/scp-runtime|*.rs|Actor-per-context refactor (ADR-049) deleted the per-context lock/relock primitives"
    "[^_]contexts_ref|crates/scp-runtime|*.rs|Actor-per-context refactor (ADR-049) deleted the contexts DashMap accessor"
    "ContextGeneration|crates/scp-runtime|*.rs|Actor-per-context refactor deleted this (ADR-049)"
    "next_generation|crates/scp-runtime|*.rs|Actor-per-context refactor deleted this (ADR-049)"
    "take_send_tracker|crates/scp-runtime|*.rs|Actor-per-context refactor deleted the send-tracker take/merge primitives (ADR-049)"
    "merge_send_tracker|crates/scp-runtime|*.rs|Actor-per-context refactor deleted the send-tracker take/merge primitives (ADR-049)"
    "MutationStateView|crates/scp-runtime|*.rs|Actor-per-context refactor deleted the transitional mutation/query borrow adapters (ADR-049)"
    "QueryStateView|crates/scp-runtime|*.rs|Actor-per-context refactor deleted the transitional mutation/query borrow adapters (ADR-049)"
    "RwLock<ContextInner>|crates/scp-runtime|*.rs|ADR-049 §Decision 12: ContextHandle's read-path RwLock<ContextInner> was replaced by lock-free Arc<ArcSwap<ContextState>>; the RwLock<ContextInner> shape must not reappear"
    "pending_joins|crates/scp-runtime/src/crypto|*.rs|ADR-049 2F-residual deleted the legacy single-slot Welcome-join primitive (prepare_key_package_for_join + NodeMlsFactory::join_from_welcome); joins flow through the KeyPackageStoreActor reserve/confirm protocol"
    # The two definition-shaped tokens below ban re-defining the deleted
    # single-slot join methods themselves, completing the pending_joins ban
    # above. Both are shaped to skip the LIVE join surface: the production
    # trait/impl/mock methods are 'async fn join_from_welcome(' (no 'pub'),
    # and the scp-testing harness wrapper is 'pub async fn' outside this
    # scope, so neither matches 'pub fn join_from_welcome('. The name
    # prepare_key_package_for_join has zero live definitions in any form.
    "fn prepare_key_package_for_join|crates/scp-runtime|*.rs|ADR-049 2F-residual deleted the legacy prepare_key_package_for_join provider method; joiners reserve KeyPackages via the KeyPackageStoreActor reserve/confirm protocol"
    "pub fn join_from_welcome\\(|crates/scp-runtime|*.rs|ADR-049 2F-residual deleted the legacy synchronous NodeMlsFactory::join_from_welcome provider method; every join flows through the async MlsBackend::join_from_welcome fused-confirm primitive"
    # A peer's MLS bytes are decoded only through `crates/scp-mls/src/wire.rs`,
    # which runs tls_codec under `catch_unwind` because tls_codec
    # `debug_assert!`s on a peer-controlled length header. wire.rs decodes
    # through one generic `T::tls_deserialize`, so these type-named tokens
    # match every other call site. The profile override that once hid the
    # assertion covered only the root workspace; it must not return.
    "MlsMessageIn::tls_deserialize|crates|*.rs|Decode peer MLS messages with scp_mls::wire::parse_mls_message_in (catch_unwind over tls_codec's debug assertion)"
    "KeyPackageIn::tls_deserialize|crates|*.rs|Decode peer KeyPackages with scp_mls::wire::parse_key_package_in (catch_unwind over tls_codec's debug assertion)"
    "Welcome::tls_deserialize|crates|*.rs|Decode Welcome bodies with scp_mls::wire::parse_welcome (catch_unwind over tls_codec's debug assertion)"
    "profile\\.dev\\.package\\.tls_codec|.|Cargo.toml|The tls_codec debug-assertions override covered one workspace root only; scp_mls::wire handles the assertion in every build"
    # Envelopes are sealed and opened only in the context actor
    # (ContextCryptoState::seal / ContextCryptoState::open, then
    # messaging_helpers::verify_and_unwrap, which binds the inner sender to the
    # MLS sender before resolving a key). A free-standing seal or open function
    # with a caller-supplied sender-layer AAD bypassed that binding.
    "fn seal_envelope|crates|*.rs|Seal through the context actor (ContextCryptoState::seal); no free-standing envelope seal exists"
    "fn open_envelope|crates|*.rs|Open through the context actor (ContextCryptoState::open + verify_and_unwrap); no free-standing envelope open exists"
    "SenderLayerAad|crates|*.rs|The sender-layer AAD is built inside ContextCryptoState from the MLS-authenticated sender, never from caller input"
    # HPKE is a direct call to scp_protocol::crypto::hpke::p256. The runtime's
    # HpkeBackend trait had one implementation and no method callers.
    "HpkeBackend|crates|*.rs|Call scp_protocol::crypto::hpke::p256 directly; the HPKE backend trait is deleted"
    # #2148 (birth-into-actor): the six provider-dissolution symbols
    # (take_crypto_state / with_context / create_group_into_slot method defs, and
    # the contexts / taken_context_ids / broadcast_keys fields) are NOT banned
    # here. They are enforced, soundly and non-redundantly, by the typed
    # provider-scoped structural test
    # `pipeline_wiring.rs::provider_steady_state_crypto_methods_are_deleted`
    # (definition-shaped `fn NAME(` + `name: Type` field-absence over PROVIDER_SRC)
    # PLUS the compiler (a call to a deleted method fails to compile). A second
    # source-text scanner for the same deletion is negative value
    # (`.claude/agents/README.md` §Review rules, non-convergent enforcement), and a `\.with_context\(` token additionally
    # false-positives on anyhow's ubiquitous `.with_context()` — a landmine. See
    # #2148 F5.
)

# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------
if [[ ${#BAN_ENTRIES[@]} -eq 0 ]]; then
    printf '%sdeleted-primitives scan:%s ban list is empty — commit 12 of the actor refactor (ADR-049) activates entries.\n' \
        "$C_DIM" "$C_RESET"
    printf '%sPASSED%s: no primitives to ban yet.\n' "$C_GREEN" "$C_RESET"
    exit 0
fi

# ---------------------------------------------------------------------------
# Active scan (runs once ban entries are populated).
# ---------------------------------------------------------------------------
TOTAL_FAIL=0
TOTAL_MATCHED=0

printf '\n%sdeleted-primitives scan:%s\n' "$C_DIM" "$C_RESET"

for entry in "${BAN_ENTRIES[@]}"; do
    # Split on `|`. Reason may contain whitespace; do not split it further.
    IFS='|' read -r token scope glob reason <<< "$entry"

    # Validate entry shape.
    if [[ -z "$token" || -z "$scope" || -z "$glob" || -z "$reason" ]]; then
        printf '%serror:%s malformed ban entry: %s\n' \
            "$C_RED" "$C_RESET" "$entry" >&2
        exit 2
    fi
    if [[ ! -d "$scope" ]]; then
        printf '%serror:%s scope dir does not exist: %s\n' \
            "$C_RED" "$C_RESET" "$scope" >&2
        exit 2
    fi

    # Run the scan. grep -R with --include for the glob; -E for extended regex.
    # -n for line numbers; -H to always include filename (some greps omit
    # it for single-file matches, which would break our tab-split below).
    #
    # We exclude `scripts/`, `target/`, `.git/` to stay in source code.
    matches=$(
        grep -R -E -n -H \
            --include="$glob" \
            --exclude-dir=target \
            --exclude-dir=.git \
            --exclude-dir=node_modules \
            --exclude-dir=.claude \
            -- \
            "$token" \
            "$scope" 2>/dev/null || true
    )

    if [[ -n "$matches" ]]; then
        match_count=$(printf '%s\n' "$matches" | wc -l | tr -d ' ')
        TOTAL_MATCHED=$((TOTAL_MATCHED + match_count))
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        printf '  %s[%s]%s %d match(es) in %s (%s)\n' \
            "$C_RED" "$token" "$C_RESET" "$match_count" "$scope" "$glob" >&2
        printf '    reason: %s\n' "$reason" >&2
        printf '%s\n' "$matches" | head -20 | while IFS= read -r ln; do
            printf '      %s%s%s\n' "$C_DIM" "$ln" "$C_RESET" >&2
        done
        if [[ "$match_count" -gt 20 ]]; then
            printf '      %s... and %d more%s\n' \
                "$C_DIM" $((match_count - 20)) "$C_RESET" >&2
        fi
    else
        printf '  %s[%s]%s no matches in %s (%s)\n' \
            "$C_GREEN" "$token" "$C_RESET" "$scope" "$glob"
    fi
done

if [[ "$TOTAL_FAIL" -eq 0 ]]; then
    printf '\n%sPASSED%s: no banned primitives found across %d rule(s).\n' \
        "$C_GREEN" "$C_RESET" "${#BAN_ENTRIES[@]}"
    exit 0
fi

printf '\n%sFAILED%s: %d ban rule(s) matched (%d total lines).\n' \
    "$C_RED" "$C_RESET" "$TOTAL_FAIL" "$TOTAL_MATCHED" >&2
printf '\n' >&2
printf 'These primitives were deleted by the actor-per-context refactor\n' >&2
printf '(ADR-049) and must not reappear. See:\n' >&2
printf '  - .docs/adrs/ADR-049-actor-per-context.md\n' >&2
printf '  - crates/scp-runtime/src/context/README.md (post-commit 6)\n' >&2

exit 1
