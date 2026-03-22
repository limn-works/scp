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

const MANAGER_SRC: &str = include_str!("../../../../crates/scp-core/src/context/manager.rs");
const PROVIDER_SRC: &str = include_str!("../../../../crates/scp-core/src/crypto/mls/provider.rs");

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================
const MIN_ACTIVE_PIPELINE_ASSERTIONS: usize = 5;

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

// Manager level: send_message calls crypto.encrypt_message
#[test]
fn send_message_calls_encrypt_message() {
    assert!(
        fn_body_contains(MANAGER_SRC, "send_message", "encrypt_message"),
        "send_message must call encrypt_message (crypto provider)"
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

// Manager level: deliver_incoming calls crypto.decrypt_message
#[test]
fn deliver_incoming_calls_decrypt_message() {
    assert!(
        fn_body_contains(MANAGER_SRC, "deliver_incoming", "decrypt_message"),
        "deliver_incoming must call decrypt_message (crypto provider)"
    );
}

// Provider level: encrypt_message calls encrypt_sender_layer
#[test]
fn encrypt_message_calls_encrypt_sender_layer() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "encrypt_message", "encrypt_sender_layer"),
        "encrypt_message (provider) must call encrypt_sender_layer"
    );
}

// Provider level: decrypt_message calls decrypt_sender_layer
#[test]
fn decrypt_message_calls_decrypt_sender_layer() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "decrypt_message", "decrypt_sender_layer"),
        "decrypt_message (provider) must call decrypt_sender_layer"
    );
}

// ===========================================================================
// Ignored assertions — unwired pipeline steps
//
// Each assertion references the GitHub issue that will wire it.
// When the wiring PR lands, remove the #[ignore] attribute.
// ===========================================================================

// --- Envelope layer (#1534) ---

#[test]
#[ignore = "#1534 — envelope sealing not yet wired into encrypt path"]
fn encrypt_path_calls_seal_envelope() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "encrypt_message", "seal_envelope")
            || fn_body_contains(MANAGER_SRC, "send_message", "seal_envelope"),
        "send/encrypt path must call seal_envelope"
    );
}

#[test]
#[ignore = "#1534 — envelope opening not yet wired into decrypt path"]
fn decrypt_path_calls_open_envelope() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "decrypt_message", "open_envelope")
            || fn_body_contains(MANAGER_SRC, "deliver_incoming", "open_envelope"),
        "receive/decrypt path must call open_envelope"
    );
}

// --- Inner envelope / signatures (#1534, #1547) ---

#[test]
#[ignore = "#1534 — inner envelope creation not yet wired"]
fn encrypt_path_calls_create_inner_envelope() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "encrypt_message", "create_inner_envelope")
            || fn_body_contains(MANAGER_SRC, "send_message", "create_inner_envelope"),
        "send/encrypt path must call create_inner_envelope"
    );
}

#[test]
#[ignore = "#1547 — inner signature verification not yet wired"]
fn decrypt_path_calls_verify_inner_signature() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "decrypt_message", "verify_inner_signature")
            || fn_body_contains(MANAGER_SRC, "deliver_incoming", "verify_inner_signature"),
        "receive/decrypt path must call verify_inner_signature"
    );
}

// --- Content wrapping (#1529) ---

#[test]
#[ignore = "#1529 — content wrapping not yet wired"]
fn encrypt_path_calls_wrap_content() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "encrypt_message", "wrap_content")
            || fn_body_contains(MANAGER_SRC, "send_message", "wrap_content"),
        "send/encrypt path must call wrap_content"
    );
}

#[test]
#[ignore = "#1529 — content unwrapping not yet wired"]
fn decrypt_path_calls_unwrap_content() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "decrypt_message", "unwrap_content")
            || fn_body_contains(MANAGER_SRC, "deliver_incoming", "unwrap_content"),
        "receive/decrypt path must call unwrap_content"
    );
}

// --- Padding (#1534) ---

#[test]
#[ignore = "#1534 — padding not yet wired into encrypt path"]
fn encrypt_path_calls_pad_to_bucket() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "encrypt_message", "pad_to_bucket")
            || fn_body_contains(MANAGER_SRC, "send_message", "pad_to_bucket"),
        "send/encrypt path must call pad_to_bucket"
    );
}

#[test]
#[ignore = "#1534 — padding strip not yet wired into decrypt path"]
fn decrypt_path_calls_strip_padding() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "decrypt_message", "strip_padding")
            || fn_body_contains(MANAGER_SRC, "deliver_incoming", "strip_padding"),
        "receive/decrypt path must call strip_padding"
    );
}

// --- Provenance (#1536) ---

#[test]
#[ignore = "#1536 — provenance attachment not yet wired"]
fn encrypt_path_calls_attach_provenance() {
    assert!(
        fn_body_contains(PROVIDER_SRC, "encrypt_message", "attach_provenance")
            || fn_body_contains(MANAGER_SRC, "send_message", "attach_provenance"),
        "send/encrypt path must call attach_provenance"
    );
}

// --- Governance / lifecycle ---

#[test]
#[ignore = "#1541 — sender key cleanup on member removal not yet wired"]
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

#[test]
#[ignore = "#1529 — access key generation on member add not yet wired"]
fn execute_add_member_calls_generate_access_key() {
    assert!(
        fn_body_contains(MANAGER_SRC, "execute_add_member", "generate_access_key"),
        "execute_add_member must call generate_access_key"
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
    // Count assert!( and assert_eq!( calls (the actual assertion macros)
    let total_asserts = source.matches("assert!(").count() + source.matches("assert_eq!(").count();
    let ignored = source.matches("#[ignore = \"").count();
    let active = total_asserts - ignored;
    assert!(
        active >= MIN_ACTIVE_PIPELINE_ASSERTIONS,
        "Active pipeline assertions ({active}) dropped below minimum \
         ({MIN_ACTIVE_PIPELINE_ASSERTIONS}). Do not weaken the test suite — \
         fix the code instead."
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
