//! Structural audit: every `#[uniffi::export]` function that touches
//! `ContextManager` or `CoreFields` state MUST route through the
//! lifecycle gate (`default_bridge_instance()?`, `context_manager()?`,
//! `context_manager_expect()?`, `bridge_instance()`, or `check_ready()`).
//!
//! This test is the mechanical enforcement for #1646 (ADR-048 PR 2
//! commit 14). It parses `bridge.rs` with `syn` into a real Rust AST,
//! enumerates every `#[uniffi::export]`ed function and impl-block
//! method, classifies each into Category A (touches `ContextManager`),
//! Category B (touches `CoreFields`), or Category C (pure / getter),
//! and asserts every A/B export contains at least one gate call in its
//! body.
//!
//! If this test fails, it means a new stateful export landed without
//! routing through the lifecycle gate. Add a gate at the top of the
//! function body (e.g. `let _bi = crate::runtime::default_bridge_instance()?;`)
//! or resolve the manager via `context_manager()?` /
//! `context_manager_expect()?`. See `.docs/audits/uniffi-check-ready-audit-1646.md`
//! for the full audit table.
//!
//! ## Why syn and not substring matching (#1694)
//!
//! The original implementation walked bridge.rs as text and matched
//! substrings on function names and attributes. Known failure modes:
//!
//! - Attribute nesting (`#[cfg_attr(not(...), uniffi::export)]`) caused
//!   the inner attribute to match while hiding the outer gate.
//! - Comments and doc strings mentioning `#[uniffi::export]` or method
//!   names tripped the scanner.
//! - Symbol renames left stale substring references in docstrings that
//!   still matched.
//!
//! The syn-based scanner visits the AST directly — attribute paths are
//! resolved segment-by-segment, method calls are distinguished from
//! field accesses, and doc / comment text never enters the match set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::format_push_string,
    clippy::redundant_pub_crate,
    clippy::doc_markdown,
    // The syn visitor intentionally checks `i.base` in both `Expr::Path`
    // and `Expr::Field` arms — clippy wants to rewrite as a `match` but
    // the arms have subtly different recv-ident extraction logic.
    clippy::collapsible_match,
    clippy::collapsible_if
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use syn::visit::Visit;

/// Method names whose invocation inside a function body counts as a
/// lifecycle gate. At least ONE of these calls must appear in every
/// Category A / Category B export.
const GATE_METHODS: &[&str] = &[
    "default_bridge_instance",
    "bridge_instance",
    "context_manager",
    "context_manager_expect",
    "check_ready",
    "ensure_bridge_instance",
];

/// Method names whose invocation identifies the body as touching the
/// authoritative `ContextManager` (Category A).
const CATEGORY_A_METHODS: &[&str] = &["context_manager", "context_manager_expect"];

/// Method names whose invocation identifies the body as touching
/// `CoreFields`-owned state (Category B). A body containing a Category A
/// call is classified as A regardless — A implicitly carries B.
const CATEGORY_B_METHODS: &[&str] = &["default_bridge_instance", "bridge_instance"];

/// Field names (`.known_contexts`, `.rate_limiters`, …) whose access
/// identifies the body as touching `CoreFields`-owned state (Category B).
/// Field accesses are distinct from method calls in the AST — syn's
/// `ExprField` vs `ExprMethodCall` — so we track them separately to
/// keep the pattern surface minimal.
///
/// Plain field names match anywhere in the AST. For qualified matches
/// tied to a specific receiver (e.g. `core.instance_id` on a
/// `CoreFields` binding), see [`QUALIFIED_CATEGORY_B_FIELDS`]. The
/// `instance_id` field is intentionally NOT in this list because every
/// opaque handle (`Identity`, `ContextHandle`, `UcanToken`,
/// `TransportManager`) also carries one and handle getters are pure.
const CATEGORY_B_FIELDS: &[&str] = &[
    "known_contexts",
    "rate_limiters",
    "economy_budgets",
    "with_transport",
    "set_transport",
    "clear_transport",
    "did_resolver",
    "petname_registry",
    "handle_registry",
    "scope_registry",
    "identity_registry",
    "ucan_registry",
];

/// Field-name pairs that count as Category B **only** when the receiver
/// identifier matches. This is the AST equivalent of the legacy
/// `core.instance_id` substring — match `.instance_id` specifically
/// when the receiver is named `core`. The general `.instance_id` case
/// (every opaque handle exposes one) does not imply `CoreFields` access.
///
/// Each entry is `(receiver_ident, field_ident)`.
const QUALIFIED_CATEGORY_B_FIELDS: &[(&str, &str)] = &[("core", "instance_id")];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Category {
    A,
    B,
    C,
}

#[derive(Debug, Clone)]
struct Export {
    line: usize,
    name: String,
    category: Category,
    has_gate: bool,
}

fn bridge_source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bridge.rs")
}

fn bridge_source() -> String {
    let path = bridge_source_path();
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read bridge.rs at {}: {e}", path.display());
    })
}

/// Returns `true` if `attrs` contains `#[uniffi::export]` or a
/// `#[cfg_attr(<pred>, uniffi::export)]` that expands to it.
fn has_uniffi_export_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(is_uniffi_export_attr)
}

fn is_uniffi_export_attr(attr: &syn::Attribute) -> bool {
    // Direct form: `#[uniffi::export]` or `#[uniffi::export(...)]`.
    if path_matches(attr.path(), &["uniffi", "export"]) {
        return true;
    }
    // Nested form: `#[cfg_attr(<pred>, uniffi::export)]`. We don't care
    // about the predicate — the export is either unconditional or
    // feature-gated; either way, if it reaches uniffi it needs a gate.
    if path_matches(attr.path(), &["cfg_attr"]) {
        // Parse the cfg_attr body manually — syn models cfg_attr as a
        // nested meta list. Walk every meta arm and look for
        // `uniffi::export` as one of the attributes.
        let parsed = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        );
        if let Ok(metas) = parsed {
            // Skip the first arm (that's the predicate) and look at the rest.
            for meta in metas.iter().skip(1) {
                if let syn::Meta::Path(path) = meta
                    && path_matches(path, &["uniffi", "export"])
                {
                    return true;
                }
                if let syn::Meta::List(list) = meta
                    && path_matches(&list.path, &["uniffi", "export"])
                {
                    return true;
                }
            }
        }
    }
    false
}

fn path_matches(path: &syn::Path, segments: &[&str]) -> bool {
    if path.segments.len() != segments.len() {
        return false;
    }
    path.segments
        .iter()
        .zip(segments.iter())
        .all(|(seg, expected)| seg.ident == *expected)
}

/// Walks a function body (`syn::Block`) and records every method-call
/// name (`.foo()` → `"foo"`), every field-access name (`.foo` →
/// `"foo"`), and every qualified field access on a named receiver
/// (`core.instance_id` → `("core", "instance_id")`). These sets are
/// later classified into Category A / B / C and gate-presence.
#[derive(Default)]
struct BodyScan {
    method_calls: Vec<String>,
    field_accesses: Vec<String>,
    qualified_field_accesses: Vec<(String, String)>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        self.method_calls.push(i.method.to_string());
        // Recurse so nested calls / args are scanned too.
        syn::visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        // Free-function calls like `context_manager()` or path-qualified
        // `crate::runtime::context_manager_expect()` land here. Extract
        // the last path segment so the gate patterns (which are short
        // names like "bridge_instance") match regardless of the import
        // style used at the call site.
        if let syn::Expr::Path(path_expr) = &*i.func
            && let Some(last) = path_expr.path.segments.last()
        {
            self.method_calls.push(last.ident.to_string());
        }
        syn::visit::visit_expr_call(self, i);
    }

    fn visit_expr_field(&mut self, i: &'ast syn::ExprField) {
        if let syn::Member::Named(ident) = &i.member {
            let field_name = ident.to_string();
            self.field_accesses.push(field_name.clone());
            // Also record the (receiver, field) pair when the receiver
            // is a bare identifier, e.g. `core.instance_id`. Chained
            // receivers like `self.inner.core.instance_id` end up with
            // their *innermost* ident captured during recursion since
            // each step is its own `ExprField`.
            if let syn::Expr::Path(p) = &*i.base
                && let Some(recv) = p.path.segments.last()
            {
                self.qualified_field_accesses
                    .push((recv.ident.to_string(), field_name));
            } else if let syn::Expr::Field(inner) = &*i.base
                && let syn::Member::Named(recv_ident) = &inner.member
            {
                self.qualified_field_accesses
                    .push((recv_ident.to_string(), field_name));
            }
        }
        syn::visit::visit_expr_field(self, i);
    }
}

fn classify(scan: &BodyScan) -> (Category, bool) {
    let has_cm = scan
        .method_calls
        .iter()
        .any(|m| CATEGORY_A_METHODS.contains(&m.as_str()));
    let has_core_method = scan
        .method_calls
        .iter()
        .any(|m| CATEGORY_B_METHODS.contains(&m.as_str()));
    let has_core_field = scan
        .field_accesses
        .iter()
        .any(|f| CATEGORY_B_FIELDS.contains(&f.as_str()));
    let has_qualified_core_field = scan.qualified_field_accesses.iter().any(|(recv, field)| {
        QUALIFIED_CATEGORY_B_FIELDS
            .iter()
            .any(|(qr, qf)| recv == qr && field == qf)
    });
    let has_core = has_core_method || has_core_field || has_qualified_core_field;
    let has_gate = scan
        .method_calls
        .iter()
        .any(|m| GATE_METHODS.contains(&m.as_str()));
    let category = if has_cm {
        Category::A
    } else if has_core {
        Category::B
    } else {
        Category::C
    };
    (category, has_gate)
}

/// Line number (1-indexed) of an item — useful for the audit message.
/// syn stores spans, but stable Rust only exposes `Span::start()` via
/// `proc-macro2`'s nightly-only feature. As a portable substitute we
/// look up the item's identifier byte-offset in the original source by
/// scanning for the token's name on the line it resides on — sufficient
/// for error messaging without shelling out to proc-macro2 nightly.
///
/// Called rarely (only when the test is about to panic or when
/// formatting the audit), so the linear scan cost is acceptable.
fn locate_line(source: &str, needle: &str) -> usize {
    source
        .lines()
        .enumerate()
        .find_map(|(idx, line)| line.contains(needle).then_some(idx + 1))
        .unwrap_or(0)
}

fn collect_exports(source: &str) -> Vec<Export> {
    let file = syn::parse_file(source).expect("failed to parse bridge.rs as a syn::File");

    let mut out = Vec::new();

    for item in &file.items {
        match item {
            syn::Item::Fn(func) => {
                if has_uniffi_export_attr(&func.attrs) {
                    let name = func.sig.ident.to_string();
                    let mut scan = BodyScan::default();
                    scan.visit_block(&func.block);
                    let (category, has_gate) = classify(&scan);
                    let needle = format!("fn {name}");
                    out.push(Export {
                        line: locate_line(source, &needle),
                        name,
                        category,
                        has_gate,
                    });
                }
            }
            syn::Item::Impl(impl_block) => {
                if !has_uniffi_export_attr(&impl_block.attrs) {
                    continue;
                }
                let impl_ty_name = impl_type_short_name(&impl_block.self_ty);
                for impl_item in &impl_block.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        let method_name = method.sig.ident.to_string();
                        let mut scan = BodyScan::default();
                        scan.visit_block(&method.block);
                        let (category, has_gate) = classify(&scan);
                        let full_name = format!("{impl_ty_name}::{method_name}");
                        let needle = format!("fn {method_name}");
                        out.push(Export {
                            line: locate_line(source, &needle),
                            name: full_name,
                            category,
                            has_gate,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    out
}

fn impl_type_short_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map_or_else(|| "?".to_owned(), |seg| seg.ident.to_string()),
        _ => "?".to_owned(),
    }
}

#[test]
fn uniffi_check_ready_coverage() {
    let source = bridge_source();
    let exports = collect_exports(&source);

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
    let exports = collect_exports(&source);
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

/// #1694 regression: the syn-based scanner's export set must be a
/// **superset** of the legacy substring scanner's set. Exact equality
/// is not required — and in fact is known to fail — because the
/// substring scanner missed every `#[uniffi::export(...)]` with a
/// parenthesized arg list (e.g. `#[uniffi::export(async_runtime =
/// "tokio")]` on `impl Scp { … }`). The syn scanner picks those up
/// correctly. Any export the legacy scanner found but syn missed
/// would be a true regression.
///
/// The legacy scanner lives on as a private helper in this file — it's
/// the comparison anchor, not a production path. It can be deleted
/// once confidence in the syn scanner is baked.
#[test]
fn syn_export_set_is_superset_of_substring_baseline() {
    let source = bridge_source();
    let exports = collect_exports(&source);

    let legacy_names: std::collections::BTreeSet<String> =
        legacy_substring_scanner::enumerate_exports(&source)
            .into_iter()
            .map(|e| e.name)
            .collect();
    let syn_names: std::collections::BTreeSet<String> =
        exports.iter().map(|e| e.name.clone()).collect();

    let only_in_legacy: Vec<_> = legacy_names.difference(&syn_names).collect();
    assert!(
        only_in_legacy.is_empty(),
        "syn scanner dropped {} export(s) the legacy scanner found: {only_in_legacy:?}",
        only_in_legacy.len()
    );
}

/// #1694 regression: the syn-based scanner must never *weaken* the
/// enforcement guarantee provided by the legacy scanner. Concretely:
/// for every export the legacy scanner flagged as A/B + gated, the
/// syn scanner MUST also observe a gate call — regardless of its
/// category verdict. The category label is an implementation detail;
/// what matters is that the lifecycle gate is present.
///
/// Allowed improvements (these are the whole point of #1694):
///   - Legacy B → syn C: the substring scanner matched a doc-comment
///     or a nested substring (e.g. `bridge_instance` inside
///     `ensure_bridge_instance`). Syn correctly sees there's no
///     CoreFields access. The function is genuinely pure — so long as
///     it still calls a gate, the enforcement goal is met.
///   - Legacy B no gate → syn B no gate: both scanners agree a gate
///     is missing; the main `uniffi_check_ready_coverage` test already
///     fails loudly on those.
#[test]
fn syn_gate_coverage_is_superset_of_substring_baseline() {
    let source = bridge_source();
    let syn_exports: BTreeMap<String, Export> = collect_exports(&source)
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();
    let legacy_exports = legacy_substring_scanner::enumerate_exports(&source);

    let mut regressed = Vec::new();
    for legacy in &legacy_exports {
        // Only assert on exports the legacy scanner marked as A or B
        // AND gated. If legacy missed the gate, we don't expect syn to
        // see it either — the main enforcement test `uniffi_check_ready_coverage`
        // already covers those.
        if matches!(legacy.category, legacy_substring_scanner::Category::C) || !legacy.has_gate {
            continue;
        }
        match syn_exports.get(&legacy.name) {
            None => regressed.push(format!(
                "{}: present in legacy, missing in syn",
                legacy.name
            )),
            Some(s) => {
                // Category drift is allowed (legacy's substring match
                // was too coarse). Gate loss is not: if legacy saw a
                // gate, syn must too. Syn's method-call AST visits
                // strictly more calls than the legacy substring scan,
                // so gate loss here would indicate a visitor bug.
                if !s.has_gate {
                    regressed.push(format!(
                        "{}: legacy gated, syn ungated — regression",
                        legacy.name
                    ));
                }
            }
        }
    }

    assert!(
        regressed.is_empty(),
        "syn-based classifier regressed on {} exports:\n  - {}",
        regressed.len(),
        regressed.join("\n  - ")
    );
}

/// Legacy substring scanner, preserved here as a baseline for the
/// #1694 migration. Not used by the enforcement test — see
/// `uniffi_check_ready_coverage` above.
mod legacy_substring_scanner {
    #![allow(clippy::format_push_string, clippy::trim_split_whitespace)]

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

    const CM_PATTERNS: &[&str] = &["context_manager()", "context_manager_expect()"];

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
    pub(super) enum Category {
        A,
        B,
        C,
    }

    #[derive(Debug, Clone)]
    pub(super) struct Export {
        pub name: String,
        pub category: Category,
        pub has_gate: bool,
    }

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

    fn strip_modifiers(line: &str) -> String {
        let mut s = line.trim_start().to_owned();
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

    pub(super) fn enumerate_exports(source: &str) -> Vec<Export> {
        let lines: Vec<&str> = source.lines().collect();
        let decls = collect_export_decl_lines(&lines);

        let mut exports = Vec::new();

        for decl_line in decls {
            let line = lines[decl_line];
            let stripped = strip_modifiers(line);

            if let Some(after_impl) = stripped.trim_start().strip_prefix("impl") {
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
                    name,
                    category,
                    has_gate,
                });
            }
        }

        exports
    }
}
