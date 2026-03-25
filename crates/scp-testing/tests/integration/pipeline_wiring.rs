#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

//! Pipeline Wiring Structural Test
//!
//! Verifies that spec-required function calls exist in the correct functions
//! within the message send/receive pipeline. Uses `include_str!()` to embed
//! source files at compile time and a brace-matching parser to extract
//! individual function bodies.
//!
//! Baseline assertions (non-ignored) represent currently-wired pipeline steps.
//! `#[ignore]` assertions represent steps that are specified but not yet wired;
//! each references a GitHub issue tracking the work. As wiring PRs land, the
//! `#[ignore]` is removed and the assertion becomes enforced.

// ---------------------------------------------------------------------------
// Source files embedded at compile time
// ---------------------------------------------------------------------------

// Production submodules first so extract_fn_body finds real implementations
// before test mocks in mod.rs (the parser returns the first match).
const MANAGER_SRC: &str = concat!(
    include_str!("../../../../crates/scp-runtime/src/context/manager/messaging.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/broadcast.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/governance.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/lifecycle.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/queries.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/standing.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/trust_recovery.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/ttl_close.rs"),
    include_str!("../../../../crates/scp-runtime/src/context/manager/mod.rs"),
);
const PROVIDER_SRC: &str =
    include_str!("../../../../crates/scp-runtime/src/crypto/mls/provider.rs");

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================
const MIN_ACTIVE_PIPELINE_ASSERTIONS: usize = 20;

// ---------------------------------------------------------------------------
// Function body extraction — brace-matching parser
// ---------------------------------------------------------------------------

/// Extracts the body of a function named `fn_name` from `source`.
///
/// Searches for `fn <fn_name>(` or `fn <fn_name><` (generic params), then
/// finds the opening `{` and does brace-matching to locate the closing `}`.
/// Returns the text between (and including) the braces.
///
/// If the function appears multiple times (e.g. in test mocks), returns the
/// FIRST occurrence. For functions that may also appear in `#[cfg(test)]`
/// blocks, the first occurrence is the production implementation.
fn extract_fn_body(source: &str, fn_name: &str) -> Option<String> {
    // Find the function signature — match `fn <name>(` or `fn <name><`
    let needle_paren = format!("fn {fn_name}(");
    let needle_generic = format!("fn {fn_name}<");

    let sig_pos = source
        .find(&needle_paren)
        .or_else(|| source.find(&needle_generic))?;

    // Find the opening brace after the signature
    let after_sig = &source[sig_pos..];
    let open_brace_offset = after_sig.find('{')?;
    let body_start = sig_pos + open_brace_offset;

    // Brace-matching: count depth from the opening brace
    let mut depth = 0u32;
    let mut body_end = body_start;
    let mut in_line_comment = false;
    let mut in_string = false;
    let mut prev_char = '\0';

    for (i, ch) in source[body_start..].char_indices() {
        // Track line comments
        if ch == '/' && prev_char == '/' && !in_string {
            in_line_comment = true;
        }
        if ch == '\n' {
            in_line_comment = false;
        }

        // Track string literals (simplified — doesn't handle raw strings,
        // but sufficient for brace matching in Rust source)
        if ch == '"' && prev_char != '\\' && !in_line_comment {
            in_string = !in_string;
        }

        if !in_line_comment && !in_string {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    body_end = body_start + i;
                    break;
                }
            }
        }
        prev_char = ch;
    }

    if depth != 0 {
        return None; // Unbalanced braces
    }

    Some(source[body_start..=body_end].to_string())
}

/// Returns `true` if the body of `fn_name` in `source` contains `callee`.
fn fn_body_contains(source: &str, fn_name: &str, callee: &str) -> bool {
    extract_fn_body(source, fn_name).is_some_and(|body| body.contains(callee))
}

// ===========================================================================
// Baseline assertions — currently wired, must pass today
// ===========================================================================

// Manager level: send_message path calls crypto.seal (full envelope pipeline)
// seal is in build_encrypted_envelope helper called from send_message
#[test]
fn send_message_calls_seal() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", ".seal(")
            || fn_body_contains(MANAGER_SRC, "build_encrypted_envelope", ".seal("),
        "send_message path must call crypto.seal (envelope pipeline)"
    );
}

// Manager level: send_message calls transport.send_message
#[test]
fn send_message_calls_transport_send() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", ".send_message("),
        "send_message must call transport.send_message"
    );
}

// Manager level: deliver_incoming calls crypto.open (full envelope pipeline)
#[test]
fn deliver_incoming_calls_open() {
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", ".open("),
        "deliver_incoming must call crypto.open (envelope pipeline)"
    );
}

// Provider level: seal calls create_outer_envelope (envelope construction)
#[test]
fn seal_calls_create_outer_envelope() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "seal", "create_outer_envelope"),
        "seal (provider) must call create_outer_envelope"
    );
}

// Provider level: seal calls encrypt_sender_layer (sender key encryption)
#[test]
fn seal_calls_encrypt_sender_layer() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "seal", "encrypt_sender_layer"),
        "seal (provider) must call encrypt_sender_layer"
    );
}

// Provider level: open calls decrypt_sender_layer
#[test]
fn open_calls_decrypt_sender_layer() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "open", "decrypt_sender_layer"),
        "open (provider) must call decrypt_sender_layer"
    );
}

// --- Envelope layer (#1534) — NOW WIRED ---

#[test]
fn encrypt_path_calls_create_outer_envelope_or_seal() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "seal", "create_outer_envelope")
            || fn_body_contains(MANAGER_SRC, "send_message", "create_outer_envelope"),
        "send/encrypt path must call create_outer_envelope"
    );
}

// --- Inner envelope / signatures (#1534, #1547) — NOW WIRED ---

#[test]
fn encrypt_path_calls_create_inner_envelope() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "create_inner_envelope_raw")
            || fn_body_contains(
                MANAGER_SRC,
                "build_encrypted_envelope",
                "create_inner_envelope_raw"
            ),
        "send path must call create_inner_envelope_raw"
    );
}

#[test]
fn decrypt_path_calls_verify_inner_signature() {
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", "verify_inner_signature")
            || fn_body_contains(MANAGER_SRC, "verify_and_unwrap", "verify_inner_signature"),
        "receive/decrypt path must call verify_inner_signature"
    );
}

// --- Content wrapping (#1529) — NOW WIRED ---

#[test]
fn encrypt_path_calls_wrap_content() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "wrap_content")
            || fn_body_contains(MANAGER_SRC, "build_encrypted_envelope", "wrap_content"),
        "send path must call wrap_content"
    );
}

#[test]
fn decrypt_path_calls_unwrap_content() {
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", "unwrap_content")
            || fn_body_contains(MANAGER_SRC, "verify_and_unwrap", "unwrap_content"),
        "receive/decrypt path must call unwrap_content"
    );
}

// --- Padding (#1534) — NOW WIRED ---

#[test]
fn decrypt_path_calls_strip_padding() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "open", "strip_padding")
            || fn_body_contains(MANAGER_SRC, "deliver_incoming", "strip_padding")
            || fn_body_contains(MANAGER_SRC, "verify_and_unwrap", "strip_padding"),
        "receive/decrypt path must call strip_padding"
    );
}

// --- Provenance (#1536) — WIRED (conditional on cross-context source) ---
// attach_provenance is called in build_encrypted_envelope when
// source_provenance is Some (cross-context data flow). For intra-context
// direct messages source_provenance is None and attach_provenance is not
// invoked. The pipeline test verifies the code path exists.

#[test]
fn encrypt_path_references_attach_provenance() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "attach_provenance")
            || fn_body_contains(MANAGER_SRC, "build_encrypted_envelope", "attach_provenance"),
        "send path must reference attach_provenance"
    );
}

// --- Anti-replay + reorder buffer (#1546, §9.8.5) — NOW WIRED ---

#[test]
fn deliver_incoming_calls_validate_received_envelope() {
    // deliver_incoming delegates to validate_and_drain_timeouts which
    // uses SequenceTracker::validate and TimestampValidator::validate
    // separately, enabling out-of-order buffering per §9.8.5 while
    // maintaining anti-replay protection.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "deliver_incoming",
            "validate_and_drain_timeouts"
        ) && fn_body_contains(
            MANAGER_SRC,
            "validate_and_drain_timeouts",
            "sequence_tracker"
        ) && fn_body_contains(MANAGER_SRC, "validate_and_drain_timeouts", "tv.validate"),
        "deliver_incoming must validate timestamps and sequence numbers (anti-replay + reorder)"
    );
}

// --- Access key generation on member add (#1529) — NOW WIRED ---

#[test]
fn execute_add_member_calls_generate_access_key() {
    assert!(
        fn_body_contains(MANAGER_SRC, "execute_add_member", "generate_access_key"),
        "execute_add_member must call generate_access_key"
    );
}

// --- Negative assertion: send_message must NOT call old encrypt_message ---

#[test]
fn send_message_does_not_call_encrypt_message() {
    assert!(
        !fn_body_contains(MANAGER_SRC, "send_message", ".encrypt_message("),
        "send_message must NOT call the old encrypt_message (replaced by seal)"
    );
}

// ===========================================================================
// Ignored assertions — unwired pipeline steps
//
// Each assertion references the GitHub issue that will wire it.
// When the wiring PR lands, remove the #[ignore] attribute.
// ===========================================================================

// --- Governance / lifecycle ---

#[test]
fn execute_remove_member_calls_remove_member_sender_key() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "execute_remove_member",
            "remove_member_sender_key"
        ),
        "execute_remove_member must call remove_member_sender_key"
    );
}

// --- Standing (#1530) ---

#[test]
fn propose_governance_checks_standing() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "propose_governance_action_inner",
            "check_standing"
        ),
        "propose_governance_action_inner must consult standing scores"
    );
}

// --- Consequences (#1531) ---

#[test]
fn governance_dispatch_calls_evaluate_consequences() {
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "finalize_governance_action",
            "evaluate_consequence_rules"
        ),
        "finalize_governance_action must call evaluate_consequence_rules"
    );
}

// --- Economy (#1537) ---

#[test]
fn governance_enforces_economic_policy() {
    // propose_governance_action_inner calls enforce_economic_policy (helper),
    // which in turn calls evaluate_cost. Check both links in the call chain.
    assert!(
        fn_body_contains(
            MANAGER_SRC,
            "propose_governance_action_inner",
            "enforce_economic_policy"
        ),
        "propose_governance_action_inner must call enforce_economic_policy"
    );
    assert!(
        fn_body_contains(MANAGER_SRC, "enforce_economic_policy", "evaluate_cost"),
        "enforce_economic_policy must call evaluate_cost"
    );
}

// --- Content key rotation (#1548) ---

#[test]
fn rotate_content_keys_calls_advance_epoch() {
    assert!(
        fn_body_contains(MANAGER_SRC, "execute_rotate_content_keys", "advance_epoch"),
        "execute_rotate_content_keys must call advance_epoch for encrypted mode MLS rotation"
    );
}

// ===========================================================================
// Meta-tests — ratchet and tamper detection
// ===========================================================================

/// Ensures the number of active (non-ignored) pipeline assertions never
/// decreases. This prevents weakening the test suite by adding `#[ignore]`
/// to passing tests or removing assertions entirely.
#[test]
fn pipeline_active_assertions_never_decrease() {
    let source = include_str!("pipeline_wiring.rs");
    // Count lines that are exactly `#[test]` (after trim) — this excludes
    // #[test] appearing in comments, string literals, or this counting code.
    let total_tests = source
        .lines()
        .filter(|line| line.trim() == "#[test]")
        .count();
    let ignored = source.matches("#[ignore = \"").count();
    let meta_tests = 3; // this test + claude_md_enforcement_sections_present + no_stale_ignores
    let active = total_tests - ignored - meta_tests;
    assert!(
        active >= MIN_ACTIVE_PIPELINE_ASSERTIONS,
        "Active pipeline assertions ({active}) dropped below minimum \
         ({MIN_ACTIVE_PIPELINE_ASSERTIONS}). Do not weaken the test suite — \
         fix the code instead."
    );
}

/// Detects stale `#[ignore]` attributes. If a wiring PR lands but forgets
/// to remove the `#[ignore]`, this test catches it by running the same check
/// the ignored test would run. A passing check = stale ignore = CI failure.
#[test]
fn no_stale_ignores() {
    let stale: Vec<&str> = vec![];

    // All batch-2 governance tests (#1541, #1530, #1531, #1537, #1548) have
    // been wired and their #[ignore] attributes removed. No stale checks
    // needed for these — they are now enforced directly.

    assert!(
        stale.is_empty(),
        "Stale #[ignore] — these tests would pass but are still ignored. \
         Remove the #[ignore] attribute and bump MIN_ACTIVE_PIPELINE_ASSERTIONS:\n  {}",
        stale.join("\n  ")
    );
}

/// Verifies that CLAUDE.md contains the required enforcement sections.
/// These sections instruct agents to check integration wiring before
/// writing code and to never weaken enforcement files.
#[test]
fn claude_md_enforcement_sections_present() {
    let claude_md = include_str!("../../../../CLAUDE.md");
    assert!(
        claude_md.contains("Integration checklist (MANDATORY"),
        "CLAUDE.md must contain the 'Integration checklist (MANDATORY' section"
    );
    assert!(
        claude_md.contains("NEVER modify enforcement files"),
        "CLAUDE.md must contain the 'NEVER modify enforcement files' section"
    );
}
