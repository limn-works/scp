//! Structural audit: every `impl Scp` method exported via
//! `#[uniffi::export]` that accepts a handle carrying an `instance_id`
//! MUST call `self.inner.core.check_handle(handle.instance_id())`
//! before touching the handle's state.
//!
//! Phase D (#1695) replaced the old process-wide lifecycle gate
//! (`default_bridge_instance()?`, `bridge_instance_for_affinity()?`,
//! etc. on a shared `DEFAULT_BRIDGE_INSTANCE`) with per-instance
//! handle-affinity enforcement: the caller-owned `Scp` mints handles
//! stamped with its own `instance_id`, and every method that accepts
//! such a handle rejects cross-instance use through the inline
//! `CoreFields::check_handle` call.
//!
//! If this test fails, it means a new `Scp` method that takes a
//! handle argument (`Arc<Identity>`, `Arc<ContextHandle>`,
//! `Arc<UcanToken>`, `Arc<TransportManager>`, `Arc<RelayHandle>`,
//! `Arc<NodeHandle>`) landed without the inline handle-affinity check.
//! Add `self.inner.core.check_handle(handle.instance_id()).map_err(ScpError::from)?;`
//! at the top of the method body.
//!
//! The justification for modifying this enforcement file in Phase D:
//! the old helpers this test scanned for (`default_bridge_instance`,
//! `bridge_instance`, `ensure_bridge_instance`,
//! `bridge_instance_for_affinity`, `check_handle_affinity`) no longer
//! exist in `crate::runtime` — the coverage list must be pruned to
//! reflect the new per-instance invariant. The enforcement *guarantee*
//! is strengthened, not weakened: the process-wide-default check could
//! only compare against the shared default, whereas the inline
//! `check_handle` rejects handles minted by any other `Scp`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::format_push_string,
    clippy::redundant_pub_crate,
    clippy::doc_markdown,
    clippy::collapsible_match,
    clippy::collapsible_if
)]

use std::fs;
use std::path::PathBuf;

use syn::visit::Visit;

/// Argument type-name patterns that indicate a handle carrying an
/// `instance_id`. Any `Scp::method` that accepts one of these MUST call
/// `check_handle` on the handle's `instance_id()` before using it.
const HANDLE_ARG_TYPES: &[&str] = &[
    "Identity",
    "ContextHandle",
    "UcanToken",
    "TransportManager",
    "RelayHandle",
    "NodeHandle",
];

fn bridge_source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bridge.rs")
}

fn bridge_source() -> String {
    let path = bridge_source_path();
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read bridge.rs at {}: {e}", path.display());
    })
}

/// Returns `true` if `attrs` contains `#[uniffi::export]` (with or
/// without parenthesized args), possibly nested inside
/// `#[cfg_attr(..., uniffi::export)]`.
fn has_uniffi_export_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(is_uniffi_export_attr)
}

fn is_uniffi_export_attr(attr: &syn::Attribute) -> bool {
    if path_matches(attr.path(), &["uniffi", "export"]) {
        return true;
    }
    if path_matches(attr.path(), &["cfg_attr"]) {
        let parsed = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        );
        if let Ok(metas) = parsed {
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

/// Extracts the short (last-segment) type name from a signature input
/// type, peeling through `Arc<...>`, `Option<Arc<...>>`, and references.
fn handle_arg_type(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => {
            let last = p.path.segments.last()?;
            let ident = last.ident.to_string();
            // Unwrap Arc<...>, Option<Arc<...>>, Box<...>.
            if matches!(ident.as_str(), "Arc" | "Option" | "Box")
                && let syn::PathArguments::AngleBracketed(args) = &last.arguments
                && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
            {
                return handle_arg_type(inner);
            }
            Some(ident)
        }
        syn::Type::Reference(r) => handle_arg_type(&r.elem),
        _ => None,
    }
}

/// Extracts the parameter names whose declared type matches one of the
/// handle patterns.
fn collect_handle_params(sig: &syn::Signature) -> Vec<String> {
    let mut out = Vec::new();
    for input in &sig.inputs {
        if let syn::FnArg::Typed(pat) = input
            && let syn::Pat::Ident(ident) = &*pat.pat
            && let Some(tname) = handle_arg_type(&pat.ty)
            && HANDLE_ARG_TYPES.contains(&tname.as_str())
        {
            out.push(ident.ident.to_string());
        }
    }
    out
}

/// Walks a function body and counts the number of
/// `<expr>.check_handle(<expr>.instance_id())` calls.
///
/// A method with N distinct handle parameters must contain at least N
/// such calls — the scanner pairs them positionally (first call = first
/// param, etc.) rather than matching on identifier names because
/// `Option<Arc<T>>` parameters are usually destructured into a locally
/// renamed binding (e.g. `if let Some(ref id) = identity`).
#[derive(Default)]
struct CheckHandleScan {
    call_count: usize,
}

impl<'ast> Visit<'ast> for CheckHandleScan {
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        if i.method == "check_handle"
            && let Some(arg0) = i.args.first()
            && let syn::Expr::MethodCall(inner) = arg0
            && inner.method == "instance_id"
            && inner.args.is_empty()
        {
            self.call_count += 1;
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

/// Line number (1-indexed) of a function name in the source, for audit
/// messages. Matches the first line containing `fn <name>`.
fn locate_line(source: &str, needle: &str) -> usize {
    source
        .lines()
        .enumerate()
        .find_map(|(idx, line)| line.contains(needle).then_some(idx + 1))
        .unwrap_or(0)
}

#[derive(Debug)]
struct Export {
    name: String,
    line: usize,
    handle_params: Vec<String>,
    check_call_count: usize,
}

fn collect_scp_method_exports(source: &str) -> Vec<Export> {
    let file = syn::parse_file(source).expect("failed to parse bridge.rs as a syn::File");

    let mut out = Vec::new();

    for item in &file.items {
        // Only `impl Scp` blocks with `#[uniffi::export]` matter for the
        // handle-affinity invariant.
        if let syn::Item::Impl(impl_block) = item {
            if !has_uniffi_export_attr(&impl_block.attrs) {
                continue;
            }
            if impl_type_short_name(&impl_block.self_ty) != "Scp" {
                continue;
            }
            for impl_item in &impl_block.items {
                if let syn::ImplItem::Fn(method) = impl_item {
                    let method_name = method.sig.ident.to_string();
                    let handle_params = collect_handle_params(&method.sig);
                    if handle_params.is_empty() {
                        continue;
                    }
                    let mut scan = CheckHandleScan::default();
                    scan.visit_block(&method.block);
                    let needle = format!("fn {method_name}");
                    out.push(Export {
                        name: format!("Scp::{method_name}"),
                        line: locate_line(source, &needle),
                        handle_params,
                        check_call_count: scan.call_count,
                    });
                }
            }
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

/// Asserts that every `impl Scp` `#[uniffi::export]` method whose signature
/// accepts a handle argument (Identity/ContextHandle/UcanToken/TransportManager/
/// RelayHandle/NodeHandle) calls `check_handle` against that argument's
/// `instance_id()` inside its body.
#[test]
fn uniffi_scp_handle_affinity_coverage() {
    let source = bridge_source();
    let exports = collect_scp_method_exports(&source);

    assert!(
        !exports.is_empty(),
        "expected at least one Scp method with handle arg — got 0 (audit scanner broken?)"
    );

    let mut missing: Vec<String> = Vec::new();
    for e in &exports {
        if e.check_call_count < e.handle_params.len() {
            missing.push(format!(
                "  - line {} `{}`: method accepts {} handle param(s) ({}) \
                 but body contains only {} `check_handle(...instance_id())` call(s)",
                e.line,
                e.name,
                e.handle_params.len(),
                e.handle_params.join(", "),
                e.check_call_count,
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "{} Scp method(s) are missing the Phase D (#1695) per-instance \
         handle-affinity check. Add `self.inner.core.check_handle(\
         <param>.instance_id()).map_err(ScpError::from)?;` at the top of \
         each offender's body.\n\n{}",
        missing.len(),
        missing.join("\n")
    );
}

/// Sanity check: the scanner must pick up at least one positive case
/// (a method that does call check_handle) and at least one
/// unambiguous handle param, otherwise the above assertion is vacuously
/// true.
#[test]
fn scanner_finds_positive_cases() {
    let source = bridge_source();
    let exports = collect_scp_method_exports(&source);

    let any_with_handle = exports.iter().any(|e| !e.handle_params.is_empty());
    assert!(
        any_with_handle,
        "scanner must identify at least one Scp method with a handle parameter"
    );

    let any_checked = exports.iter().any(|e| e.check_call_count > 0);
    assert!(
        any_checked,
        "scanner must identify at least one check_handle call — \
         otherwise the positive path of the scanner is broken"
    );
}
