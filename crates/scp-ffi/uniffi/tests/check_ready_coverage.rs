//! Structural audit: every `#[uniffi::export]` function that touches
//! `ContextManager` or `CoreFields` state MUST route through the
//! lifecycle gate (`default_bridge_instance()?`, `context_manager()?`,
//! `context_manager_expect()?`, `bridge_instance()`, or `check_ready()`).
//!
//! This test is the mechanical enforcement for #1646 (ADR-048 PR 2
//! commit 14). It parses `bridge.rs` as text, enumerates every export,
//! classifies each into Category A (touches `ContextManager`),
//! Category B (touches `CoreFields`), or Category C (pure / getter),
//! and asserts every A/B export contains at least one gate token in
//! its body.
//!
//! If this test fails, it means a new stateful export landed without
//! routing through the lifecycle gate. Add a gate at the top of the
//! function body (e.g. `let _bi = crate::runtime::default_bridge_instance()?;`)
//! or resolve the manager via `context_manager()?` /
//! `context_manager_expect()?`. See `.docs/audits/uniffi-check-ready-audit-1646.md`
//! for the full audit table.
//!
//! The full audit table is committed to
//! `.docs/audits/uniffi-check-ready-audit-1646.md`. CI runs this test on
//! every PR.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::format_push_string,
    clippy::trim_split_whitespace
)]

use std::fs;
use std::path::PathBuf;

/// Patterns that indicate a function body contains a lifecycle gate.
/// At least ONE must match for a Category A or Category B function.
/// The bare `bridge_instance()` string match is intentional: every call
/// site — whether `?`-propagating, `.ok()`-downgrading, or chained —
/// invokes the same lifecycle check inside `bridge_instance()` itself.
const GATE_PATTERNS: &[&str] = &[
    "default_bridge_instance()",
    "bridge_instance()",
    "context_manager()?",
    "context_manager().ok_or_else",
    "context_manager_expect()?",
    "= crate::runtime::context_manager_expect()",
    "check_ready",
    "ensure_bridge_instance",
];

/// Patterns that indicate a function body touches `ContextManager` state
/// (Category A). The presence of any of these marks the function as
/// stateful and therefore requires a gate.
const CM_PATTERNS: &[&str] = &["context_manager()", "context_manager_expect()"];

/// Patterns that indicate a function body touches `CoreFields` state
/// (Category B). Category A takes precedence over B when both patterns
/// are present (the CM path implicitly carries `CoreFields` state).
const CORE_PATTERNS: &[&str] = &[
    "default_bridge_instance()",
    "bridge_instance()",
    ".known_contexts",
    ".rate_limiters",
    ".economy_budgets",
    ".with_transport",
    ".set_transport",
    ".clear_transport",
    ".did_resolver",
    ".petname_registry",
    ".handle_registry",
    ".scope_registry",
    ".identity_registry",
    ".ucan_registry",
    "core.instance_id",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    A,
    B,
    C,
}

#[derive(Debug)]
struct Export {
    line: usize,
    name: String,
    category: Category,
    has_gate: bool,
}

fn bridge_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bridge.rs");
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read bridge.rs at {}: {e}", path.display());
    })
}

/// Locates every `#[uniffi::export]` attribute, skips over any subsequent
/// `#[...]` attributes, and returns the 0-indexed line where the actual
/// declaration (fn / impl) begins.
fn collect_export_decl_lines(lines: &[&str]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "#[uniffi::export]" {
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
            if j < lines.len() {
                out.push(j);
            }
        }
        i += 1;
    }
    out
}

/// Strips `pub`/`pub(..)`/`async`/`unsafe` modifiers from the start of a
/// line so the declaration token (`fn` / `impl`) is flush with the start.
fn strip_modifiers(line: &str) -> String {
    let mut s = line.trim_start().to_owned();
    // pub / pub(...)
    if let Some(rest) = s.strip_prefix("pub") {
        let after_pub = rest.trim_start();
        if let Some(after_paren) = after_pub.strip_prefix('(') {
            if let Some(close_idx) = after_paren.find(')') {
                s = after_paren[close_idx + 1..].trim_start().to_owned();
            } else {
                s = after_pub.to_owned();
            }
        } else {
            s = after_pub.to_owned();
        }
    }
    for prefix in ["async ", "unsafe "] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_owned();
        }
    }
    s
}

/// Returns the 0-indexed line of the closing `}` that ends the block
/// opening at or after `start_line`. Counts braces across the file and
/// returns once the matched open is closed.
fn find_block_end(lines: &[&str], start_line: usize) -> Option<usize> {
    let mut depth: i64 = 0;
    let mut in_body = false;
    for (offset, line) in lines.iter().enumerate().skip(start_line) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                in_body = true;
            } else if ch == '}' {
                depth -= 1;
                if in_body && depth == 0 {
                    return Some(offset);
                }
            }
        }
    }
    None
}

/// Returns `true` if any pattern in `patterns` occurs in `body`.
fn body_contains_any(body: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| body.contains(*p))
}

fn classify_body(body: &str) -> (Category, bool) {
    let has_cm = body_contains_any(body, CM_PATTERNS);
    let has_core = body_contains_any(body, CORE_PATTERNS);
    let has_gate = body_contains_any(body, GATE_PATTERNS);
    let category = if has_cm {
        Category::A
    } else if has_core {
        Category::B
    } else {
        Category::C
    };
    (category, has_gate)
}

/// Collects all `#[uniffi::export]` functions — both free functions and
/// methods inside `#[uniffi::export] impl` blocks — along with their
/// category + gate presence.
fn enumerate_exports(source: &str) -> Vec<Export> {
    let lines: Vec<&str> = source.lines().collect();
    let decls = collect_export_decl_lines(&lines);

    let mut exports = Vec::new();

    for decl_line in decls {
        let line = lines[decl_line];
        let stripped = strip_modifiers(line);

        if let Some(after_impl) = stripped.trim_start().strip_prefix("impl") {
            // impl-block export: walk the block and pick up each fn.
            let Some(block_end) = find_block_end(&lines, decl_line) else {
                continue;
            };
            let impl_name = after_impl
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("?")
                .to_owned();
            for i in (decl_line + 1)..=block_end {
                let method_line = lines[i];
                let ms = strip_modifiers(method_line);
                if let Some(rest) = ms.trim_start().strip_prefix("fn ") {
                    let name = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect::<String>();
                    if name.is_empty() {
                        continue;
                    }
                    let Some(body_end) = find_block_end(&lines, i) else {
                        continue;
                    };
                    let body = lines[i..=body_end].join("\n");
                    let (category, has_gate) = classify_body(&body);
                    exports.push(Export {
                        line: i + 1,
                        name: format!("{impl_name}::{name}"),
                        category,
                        has_gate,
                    });
                }
            }
        } else if let Some(rest) = stripped.trim_start().strip_prefix("fn ") {
            let name = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>();
            if name.is_empty() {
                continue;
            }
            let Some(body_end) = find_block_end(&lines, decl_line) else {
                continue;
            };
            let body = lines[decl_line..=body_end].join("\n");
            let (category, has_gate) = classify_body(&body);
            exports.push(Export {
                line: decl_line + 1,
                name,
                category,
                has_gate,
            });
        }
    }

    exports
}

#[test]
fn uniffi_check_ready_coverage() {
    let source = bridge_source();
    let exports = enumerate_exports(&source);

    assert!(
        exports.len() >= 190,
        "expected at least 190 exports in bridge.rs (165 free fns + 27 impl methods), got {}",
        exports.len()
    );

    let missing: Vec<&Export> = exports
        .iter()
        .filter(|e| !matches!(e.category, Category::C) && !e.has_gate)
        .collect();

    if !missing.is_empty() {
        let mut msg = format!(
            "{} UniFFI export(s) touching CoreFields/ContextManager state are missing a \
             lifecycle gate (#1646). Every Category A/B export must invoke one of: \
             `default_bridge_instance()?`, `bridge_instance()`, `context_manager()?`, \
             `context_manager_expect()?`, or `check_ready()`.\n\n",
            missing.len()
        );
        for e in &missing {
            msg.push_str(&format!(
                "  - line {} `{}` (category {:?})\n",
                e.line, e.name, e.category
            ));
        }
        msg.push_str(
            "\nFix: add `let _bi = crate::runtime::default_bridge_instance()?;` at the \
             top of each offender's body, or resolve the manager via \
             `context_manager()?` / `context_manager_expect()?`.\n\
             See .docs/audits/uniffi-check-ready-audit-1646.md for the full audit table.",
        );
        panic!("{msg}");
    }
}

/// Sanity check on the classifier itself — at least one A, one B, and
/// one C must exist (otherwise the patterns are wrong and the above test
/// becomes vacuously true).
#[test]
fn classifier_identifies_all_three_categories() {
    let source = bridge_source();
    let exports = enumerate_exports(&source);
    assert!(
        exports.iter().any(|e| matches!(e.category, Category::A)),
        "classifier must identify at least one Category A export"
    );
    assert!(
        exports.iter().any(|e| matches!(e.category, Category::B)),
        "classifier must identify at least one Category B export"
    );
    assert!(
        exports.iter().any(|e| matches!(e.category, Category::C)),
        "classifier must identify at least one Category C export"
    );
}
