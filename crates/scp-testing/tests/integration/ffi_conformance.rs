#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::single_match,
    clippy::cast_precision_loss
)]

//! B15: FFI Bridge API Surface Conformance
//!
//! Verifies that the 4 FFI bridges (PyO3, UniFFI, NAPI, WASM) export
//! consistent operation sets. PyO3 is the reference bridge (100% coverage
//! target). Other bridges should match except where architecture constraints
//! apply (e.g. WASM cannot depend on scp-core per ADR-034).
//!
//! Implementation: reads bridge source files at compile time via `include_str!`
//! and searches for exported function name patterns. The per-bridge alias
//! tables live in `scripts/bridge-aliases.json` — the SAME file consumed by
//! `scripts/check-bridge-symmetry.sh`, so the Rust test and the shell
//! enforcement cannot silently drift apart. The test
//! `aliases_json_is_in_sync_with_parity_operations` asserts the JSON matches
//! the local ratchet constants (total op count and WASM-required named set).

use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Source files embedded at compile time
// ---------------------------------------------------------------------------

// PyO3 bridge sources
const PYO3_IDENTITY: &str = include_str!("../../../../crates/scp-ffi/src/identity.rs");
const PYO3_CONTEXT: &str = include_str!("../../../../crates/scp-ffi/src/context.rs");
const PYO3_TOOLS: &str = include_str!("../../../../crates/scp-ffi/src/tools.rs");
const PYO3_UCAN: &str = include_str!("../../../../crates/scp-ffi/src/ucan.rs");
const PYO3_EVENT_LOG: &str = include_str!("../../../../crates/scp-ffi/src/event_log.rs");
const PYO3_TRANSPORT: &str = include_str!("../../../../crates/scp-ffi/src/transport.rs");
const PYO3_BRIDGE_CONNECTOR: &str =
    include_str!("../../../../crates/scp-ffi/src/bridge_connector.rs");
const PYO3_SYNC: &str = include_str!("../../../../crates/scp-ffi/src/sync.rs");
const PYO3_PROVENANCE: &str = include_str!("../../../../crates/scp-ffi/src/provenance.rs");
const PYO3_DISCOVERY: &str = include_str!("../../../../crates/scp-ffi/src/discovery.rs");
const PYO3_TRUST: &str = include_str!("../../../../crates/scp-ffi/src/trust.rs");
const PYO3_MCP: &str = include_str!("../../../../crates/scp-ffi/src/mcp.rs");
const PYO3_ECONOMY: &str = include_str!("../../../../crates/scp-ffi/src/economy.rs");
const PYO3_MEDIA: &str = include_str!("../../../../crates/scp-ffi/src/media.rs");
// Phase 4 PR 4 migrated `fn py_foo(...)` free functions to
// `#[pymethods] impl PyScp { pub fn foo(&self, ...) }` methods. The per-category
// files above still contain these methods on PyScp; `scp.rs` holds the
// lifecycle surface (new / with_storage / suspend / resume / shutdown).
const PYO3_SCP: &str = include_str!("../../../../crates/scp-ffi/src/scp.rs");
// PyO3 surface for `scpid_*` (challenge/sign/verify) and the server lifecycle
// (start_in_memory / start_local / enable_site_projection / disable_site_projection).
// Both files were not previously embedded — Batch 2 (#1543) folds them in so
// SCPID and site-projection canonicals can resolve.
const PYO3_SCPID: &str = include_str!("../../../../crates/scp-ffi/src/scpid.rs");
const PYO3_SERVER: &str = include_str!("../../../../crates/scp-ffi/src/server.rs");

// UniFFI bridge spans three files: the central `bridge.rs` (most ops),
// `server.rs` (site-projection methods on the `Server` type), and `scp.rs`
// which hosts the construction-time lifecycle surface on the `Scp` type
// (`new` / `with_storage` / `with_persistence` / `suspend` / `resume` /
// `shutdown`). All three must be embedded so the conformance test sees the
// full UniFFI surface — without `scp.rs` the alias resolver flags
// constructors like `with_storage` as phantom even though they are
// wired and exposed to Swift/Kotlin.
const UNIFFI_BRIDGE: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs");
const UNIFFI_SERVER: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/server.rs");
const UNIFFI_SCP: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/scp.rs");

// NAPI bridge sources
const NAPI_IDENTITY: &str = include_str!("../../../../crates/scp-ffi/napi/src/identity.rs");
const NAPI_CONTEXT: &str = include_str!("../../../../crates/scp-ffi/napi/src/context.rs");
const NAPI_TOOLS: &str = include_str!("../../../../crates/scp-ffi/napi/src/tools.rs");
const NAPI_UCAN: &str = include_str!("../../../../crates/scp-ffi/napi/src/ucan.rs");
const NAPI_EVENT_LOG: &str = include_str!("../../../../crates/scp-ffi/napi/src/event_log.rs");
const NAPI_TRANSPORT: &str = include_str!("../../../../crates/scp-ffi/napi/src/transport.rs");
const NAPI_BRIDGE_CONNECTOR: &str =
    include_str!("../../../../crates/scp-ffi/napi/src/bridge_connector.rs");
const NAPI_SYNC: &str = include_str!("../../../../crates/scp-ffi/napi/src/sync.rs");
const NAPI_PROVENANCE: &str = include_str!("../../../../crates/scp-ffi/napi/src/provenance.rs");
const NAPI_DISCOVERY: &str = include_str!("../../../../crates/scp-ffi/napi/src/discovery.rs");
const NAPI_TRUST: &str = include_str!("../../../../crates/scp-ffi/napi/src/trust.rs");
const NAPI_MCP: &str = include_str!("../../../../crates/scp-ffi/napi/src/mcp.rs");
const NAPI_ECONOMY: &str = include_str!("../../../../crates/scp-ffi/napi/src/economy.rs");
const NAPI_MEDIA: &str = include_str!("../../../../crates/scp-ffi/napi/src/media.rs");
// Phase 4 PR 4 migrated `fn napi_foo(...)` free functions to `impl Scp { pub async fn foo(&self, ...) }`
// methods in `scp.rs`. The per-category source files retain helpers and types,
// but the canonical bridge surface now lives on the `Scp` struct.
const NAPI_SCP: &str = include_str!("../../../../crates/scp-ffi/napi/src/scp.rs");
// NAPI server module hosts `enable_site_projection` / `disable_site_projection`
// methods on the `Server` type — added in Batch 2 (#1543).
const NAPI_SERVER: &str = include_str!("../../../../crates/scp-ffi/napi/src/server.rs");

// WASM bridge sources
const WASM_IDENTITY: &str = include_str!("../../../../crates/scp-ffi/wasm/src/identity.rs");
const WASM_CONTEXT: &str = include_str!("../../../../crates/scp-ffi/wasm/src/context.rs");
const WASM_TOOLS: &str = include_str!("../../../../crates/scp-ffi/wasm/src/tools.rs");
const WASM_UCAN: &str = include_str!("../../../../crates/scp-ffi/wasm/src/ucan.rs");
const WASM_EVENT_LOG: &str = include_str!("../../../../crates/scp-ffi/wasm/src/event_log.rs");
const WASM_TRANSPORT: &str = include_str!("../../../../crates/scp-ffi/wasm/src/transport.rs");
const WASM_SYNC: &str = include_str!("../../../../crates/scp-ffi/wasm/src/sync.rs");
const WASM_PROVENANCE: &str = include_str!("../../../../crates/scp-ffi/wasm/src/provenance.rs");
const WASM_DISCOVERY: &str = include_str!("../../../../crates/scp-ffi/wasm/src/discovery.rs");
const WASM_TRUST: &str = include_str!("../../../../crates/scp-ffi/wasm/src/trust.rs");
const WASM_ECONOMY: &str = include_str!("../../../../crates/scp-ffi/wasm/src/economy.rs");
// WASM SCPID module hosts `scpid_challenge` / `scpid_sign` (verify is exempt
// per ADR-034 — see crates/scp-ffi/wasm/src/scpid.rs:11). Added in Batch 2 (#1543).
const WASM_SCPID: &str = include_str!("../../../../crates/scp-ffi/wasm/src/scpid.rs");

// ---------------------------------------------------------------------------
// Shared alias table — compiled in at build time from scripts/bridge-aliases.json
// ---------------------------------------------------------------------------

/// Raw JSON bytes of the shared alias table. Both this test and the shell
/// script `scripts/check-bridge-symmetry.sh` read the same file, so drift is
/// impossible — the test `aliases_json_is_in_sync_with_parity_operations`
/// asserts the JSON matches the ratchet constants below.
const BRIDGE_ALIASES_JSON: &str = include_str!("../../../../scripts/bridge-aliases.json");

#[derive(Debug, Deserialize)]
struct BridgeAliasesFile {
    operations: Vec<AliasOp>,
    #[serde(default)]
    exemptions: BridgeExemptions,
}

#[derive(Debug, Default, Deserialize)]
struct BridgeExemptions {
    #[serde(default)]
    pyo3: Vec<ExemptionEntry>,
    #[serde(default)]
    uniffi: Vec<ExemptionEntry>,
    #[serde(default)]
    napi: Vec<ExemptionEntry>,
    #[serde(default)]
    wasm: Vec<ExemptionEntry>,
}

#[derive(Debug, Deserialize)]
struct ExemptionEntry {
    canonical: String,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct AliasOp {
    canonical: String,
    category: String,
    wasm_required: bool,
    pyo3: Vec<String>,
    uniffi: Vec<String>,
    napi: Vec<String>,
    wasm: Vec<String>,
}

fn aliases() -> &'static BridgeAliasesFile {
    static CELL: OnceLock<BridgeAliasesFile> = OnceLock::new();
    CELL.get_or_init(|| {
        serde_json::from_str(BRIDGE_ALIASES_JSON).expect("bridge-aliases.json is valid JSON")
    })
}

/// Returns the list of (category, canonical, wasm_required) tuples, built
/// dynamically from the alias JSON. Replaces the old hand-maintained
/// `PARITY_OPERATIONS` constant. Each &'static str is a borrow into the
/// process-lifetime `OnceLock<BridgeAliasesFile>` backing the alias data.
fn parity_operations() -> Vec<(&'static str, &'static str, bool)> {
    let file: &'static BridgeAliasesFile = aliases();
    file.operations
        .iter()
        .map(|op| {
            (
                op.category.as_str(),
                op.canonical.as_str(),
                op.wasm_required,
            )
        })
        .collect()
}

fn lookup_op(canonical: &str) -> &'static AliasOp {
    // aliases() returns &'static BridgeAliasesFile, so every inner reference
    // already has 'static lifetime — the compiler just needs us to name it.
    let file: &'static BridgeAliasesFile = aliases();
    for op in &file.operations {
        if op.canonical == canonical {
            return op;
        }
    }
    panic!("canonical operation not found in bridge-aliases.json: {canonical}");
}

fn pyo3_names(canonical: &str) -> &'static [String] {
    lookup_op(canonical).pyo3.as_slice()
}

fn uniffi_names(canonical: &str) -> &'static [String] {
    lookup_op(canonical).uniffi.as_slice()
}

fn napi_names(canonical: &str) -> &'static [String] {
    lookup_op(canonical).napi.as_slice()
}

fn wasm_names(canonical: &str) -> &'static [String] {
    lookup_op(canonical).wasm.as_slice()
}

/// Returns the set of canonical operations explicitly exempted for the given
/// bridge in `bridge-aliases.json`. The sole source of truth: no hand-rolled
/// `known_exclusions` arrays anywhere in this file.
fn exemptions_for(bridge: &str) -> BTreeSet<&'static str> {
    let file: &'static BridgeAliasesFile = aliases();
    let entries: &'static [ExemptionEntry] = match bridge {
        "pyo3" => &file.exemptions.pyo3,
        "uniffi" => &file.exemptions.uniffi,
        "napi" => &file.exemptions.napi,
        "wasm" => &file.exemptions.wasm,
        other => panic!("exemptions_for: unknown bridge '{other}'"),
    };
    entries.iter().map(|e| e.canonical.as_str()).collect()
}

// ---------------------------------------------------------------------------
// Detection: parse source with `syn` and collect every function/method
// DEFINITION at module or impl-block scope. This matches the semantics of
// `scripts/check-bridge-symmetry.sh`'s awk-based `collect_fn_names_from_file`:
//
//   • Functions inside `#[cfg(test)] mod <name> { ... }` are EXCLUDED. An
//     adversary can otherwise hide a fake alias behind a test module to
//     satisfy a naive substring check.
//   • Trait method DECLARATIONS (`trait Foo { fn bar(&self); }`) are EXCLUDED
//     — they are signatures, not definitions. Implementations in impl blocks
//     ARE included.
//   • Doc-comments containing `/// fn name(` are EXCLUDED — `syn` only sees
//     items.
//   • Whitespace, generics, and line-break variants are handled uniformly.
//
// Parity with the shell collector matters: the Rust test and the shell script
// read the same `bridge-aliases.json`, so if either side is weaker an attacker
// can thread a phantom alias through the gap.
//
// Parsing uses `syn::parse_file` + a `syn::visit::Visit` walk that skips the
// subtree rooted at any `#[cfg(test)]`-annotated module. We cache the per-
// source set via `OnceLock` keyed by the pointer identity of the `&'static
// str` — every bridge source is `include_str!`-interned, so the pointer is
// stable and unique per file.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Mutex;

use syn::visit::Visit;

/// Collects every function/method name DEFINED in `source` at module or
/// impl-block scope, skipping items under `#[cfg(test)]` modules and trait
/// method signatures. Returns a `HashSet<String>` of unique names.
///
/// Fail-loud policy: if `syn::parse_file` fails, we PANIC. All bridge sources
/// must be valid Rust (they compile with rustc upstream); a parse failure here
/// means either (a) we embedded a file that is not a Rust source, or (b) the
/// source contains a real lex/parse error the compiler would reject. Silently
/// falling back to a weaker substring scanner lets an attacker smuggle a
/// phantom alias past the test by crafting input the substring path accepts
/// but `syn` rejects — degraded enforcement is worse than no enforcement
/// because it looks like it is working. Mirror Layer B, which hard-fails on
/// tree-sitter parse errors.
fn collect_defined_fns(source: &str) -> HashSet<String> {
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(err) => panic!(
            "ffi_conformance: syn failed to parse bridge source: {err}. \
             Refusing to enforce with a degraded scanner. Fix the Rust source \
             or, if this file is known to be unparseable, add it to a Layer-A \
             parse-error allowlist (mirror Layer B's KNOWN_PARSE_ERROR_FILES)."
        ),
    };
    let mut v = FnCollector {
        names: HashSet::new(),
    };
    v.visit_file(&file);
    v.names
}

struct FnCollector {
    names: HashSet<String>,
}

/// Returns true if `attrs` contains a `#[cfg(...)]` predicate that evaluates
/// to test-only code — i.e. the cfg expression is satisfied ONLY when the
/// `test` predicate is true.
///
/// Semantics (matches rustc cfg evaluation for the `test` predicate):
///   • `#[cfg(test)]` → test-only.
///   • `#[cfg(all(test, ...))]` → test-only (all must hold, so test must hold).
///   • `#[cfg(any(test, ...))]` → test-only (it becomes active when test is on;
///     for our scanner purposes, any item gated this way is test-only code).
///   • `#[cfg(not(test))]` → NOT test-only (this is the inverse — active only
///     when test is DISABLED; production code must be kept).
///   • `#[cfg(all(not(test), ...))]` → NOT test-only (contains `not(test)` at
///     top-level within `all`, so the predicate holds only outside tests).
///   • Anything with `test` under a `not(...)` → NOT test-only for our purposes
///     (the item is included when test is off).
///
/// We parse the cfg predicate as a `syn::Meta` tree and walk it, tracking
/// whether we are currently under a `not(...)` context. A bare `test` ident
/// encountered OUTSIDE a `not(...)` marks the item as test-only.
fn attrs_contain_cfg_test(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if !attr.path().is_ident("cfg") {
            continue;
        }
        // parse_args::<Meta>() gives us the single Meta expression inside the
        // `cfg(...)` — e.g. `test`, `any(test, feature = "x")`, or `not(test)`.
        let Ok(inner) = attr.parse_args::<syn::Meta>() else {
            continue;
        };
        if meta_is_test_gated(&inner, false) {
            return true;
        }
    }
    false
}

/// Walks a `syn::Meta` cfg sub-expression. Returns true iff this sub-expression
/// evaluates to test-only code (i.e. is active only when `test` is enabled).
///
/// `under_not` tracks whether we are currently inside a `not(...)` wrapper.
/// Every pass through a `not(...)` flips the sign.
fn meta_is_test_gated(meta: &syn::Meta, under_not: bool) -> bool {
    use syn::Meta;
    match meta {
        // Bare `test`. Test-only iff not negated.
        Meta::Path(p) if p.is_ident("test") => !under_not,
        // `any(...)`, `all(...)`, `not(...)` are list metas with nested items.
        Meta::List(list) => {
            let ident = list.path.get_ident().map(syn::Ident::to_string);
            match ident.as_deref() {
                Some("not") => {
                    // Each nested meta inside `not(...)` has its under_not flipped.
                    let Ok(nested) = list.parse_args_with(
                        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                    ) else {
                        return false;
                    };
                    nested.iter().any(|m| meta_is_test_gated(m, !under_not))
                }
                Some(op @ ("all" | "any")) => {
                    let Ok(nested) = list.parse_args_with(
                        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                    ) else {
                        return false;
                    };
                    // "test-gated" here means "the item is compiled ONLY when
                    // test is on" — i.e., the cfg predicate implies `test`.
                    //
                    // * `all(A, B)` compiles iff `A && B`. The item is
                    //   test-only iff ANY child implies test — because a
                    //   single test-gated predicate forces the whole
                    //   conjunction to require test.
                    // * `any(A, B)` compiles iff `A || B`. The item is
                    //   test-only iff EVERY child implies test — because
                    //   any non-test predicate could activate the item in
                    //   production via the disjunction.
                    //
                    // Counter-example the wrong choice misclassifies:
                    //   `#[cfg(all(any(feature = "x", test), not(test)))]`
                    // is production-only, but with `.any()` on `any(...)`
                    // the inner disjunction reports test-gated, which then
                    // propagates through the outer `all`. Splitting by op
                    // makes the walker rustc-equivalent for these layered
                    // patterns.
                    if op == "all" {
                        nested.iter().any(|m| meta_is_test_gated(m, under_not))
                    } else {
                        nested.iter().all(|m| meta_is_test_gated(m, under_not))
                    }
                }
                _ => false,
            }
        }
        // Any other Meta (NameValue, a Path that is not `test`, etc.) is not
        // a test gate by itself.
        _ => false,
    }
}

impl<'ast> Visit<'ast> for FnCollector {
    // Free-standing `fn`. Always a definition — UNLESS the fn itself carries a
    // `#[cfg(test)]` (or equivalent) attribute. A non-test module may still
    // contain a test-only fn: `mod foo { #[cfg(test)] fn bar() {} }`. Without
    // this guard, `bar` would be collected and could satisfy a phantom alias.
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        self.names.insert(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
    }

    // Methods inside `impl` blocks are definitions. Same fn-level cfg(test)
    // guard as free-standing fns.
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        self.names.insert(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
    }

    // Trait method SIGNATURES are declarations, not definitions — skip.
    // A default body (`fn foo(&self) { ... }`) inside a trait is still a
    // declaration in terms of the exported surface: callers don't call the
    // trait method through that name, they call the impl. Not descending into
    // trait items keeps us aligned with the shell script, which never matches
    // inside `trait { ... }` blocks either (no impl body is required there).
    fn visit_item_trait(&mut self, _node: &'ast syn::ItemTrait) {
        // Intentionally do not recurse.
    }

    // Descend into modules UNLESS they are `#[cfg(test)]`.
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    // Descend into `impl` blocks UNLESS they are `#[cfg(test)]`. Without this
    // guard, a non-test module could still host a test-only impl block whose
    // methods would be collected — a real instance exists at
    // `crates/scp-ffi/napi/src/context.rs:296` and `runtime.rs:347`. An
    // adversary can otherwise declare a canonical alias as a method inside
    // `#[cfg(test)] impl Foo { fn alias() {} }` and satisfy the scanner with
    // code that never ships. Mirrors `visit_item_mod`'s cfg(test) guard.
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_impl(self, node);
    }
}

// ---------------------------------------------------------------------------
// FFI-EXPORTED scanner (strict): collects only `pub fn` definitions decorated
// with a per-bridge FFI export macro on the fn itself OR on its enclosing
// impl block. This is the scanner the alias-resolution path uses: an alias
// only "resolves" if the named fn is actually exported through the bridge's
// binding tooling, not merely defined in source.
//
// The looser `FnCollector` above stays in place for the cfg(test) drift
// fixtures (which test the cfg-gate semantics in isolation). Two scanners
// with two purposes — do not collapse.
//
// The macros recognized are the ones each bridge's binding tool consumes:
//
//   • PyO3:  free `pub fn` decorated `#[pyfunction]`,
//            method inside `#[pymethods] impl <T> { ... }`.
//   • NAPI:  free `pub fn` decorated `#[napi]` / `#[napi(...)]`,
//            method inside `#[napi] impl <T> { ... }` (or `#[napi(...)]`).
//   • UniFFI: free `pub fn` decorated `#[uniffi::export]` / `#[uniffi::export(...)]`,
//             method inside `#[uniffi::export] impl <T> { ... }` (or `#[uniffi::export(...)]`).
//   • WASM:   free `pub fn` decorated `#[wasm_bindgen]` / `#[wasm_bindgen(...)]`,
//             method inside `#[wasm_bindgen] impl <T> { ... }` (or `#[wasm_bindgen(...)]`).
//
// Visibility rule: NOT enforced. The FFI macro is the export marker — every
// SCP bridge tool (PyO3, NAPI, UniFFI, wasm-bindgen) accepts the macro on
// any visibility (pub, pub(crate), naked fn). PyO3 even has many real
// examples of `#[pyfunction] fn name(...)` without `pub` — see
// `runtime_is_initialized` / `version` / `shutdown_runtime` in
// `crates/scp-ffi/src/lib.rs`. Visibility controls Rust-internal access; the
// macro generates a separate language-callable wrapper that exports
// regardless. The phantom-alias attack surface this PR closes is "alias
// resolves to a fn the binding tooling does NOT process" — i.e. a fn missing
// the macro entirely. Adding a `pub` requirement on top would create false
// positives without adding security.
// ---------------------------------------------------------------------------

/// Returns true if `attrs` carries a free-fn-level FFI export macro
/// (`#[pyfunction]`, `#[napi]`, `#[wasm_bindgen]`, `#[uniffi::export]`,
/// or any of those with parenthesized arguments).
fn attrs_have_free_fn_ffi_export(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        let path = attr.path();
        if let Some(ident) = path.get_ident()
            && matches!(
                ident.to_string().as_str(),
                "pyfunction" | "napi" | "wasm_bindgen"
            )
        {
            return true;
        }
        if path.segments.len() == 2
            && path.segments[0].ident == "uniffi"
            && path.segments[1].ident == "export"
        {
            return true;
        }
    }
    false
}

/// Returns true if `attrs` carries an impl-block-level FFI export macro
/// (`#[pymethods]`, `#[napi]`, `#[wasm_bindgen]`, `#[uniffi::export]`).
/// Matches `#[napi]`, `#[napi(...)]`, etc. uniformly.
fn attrs_have_impl_block_ffi_export(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        let path = attr.path();
        if let Some(ident) = path.get_ident()
            && matches!(
                ident.to_string().as_str(),
                "pymethods" | "napi" | "wasm_bindgen"
            )
        {
            return true;
        }
        if path.segments.len() == 2
            && path.segments[0].ident == "uniffi"
            && path.segments[1].ident == "export"
        {
            return true;
        }
    }
    false
}

/// Strict scanner: collects every fn name a bridge's binding tool would
/// actually export. See module-level docs above for the export rules.
fn collect_ffi_exported_fns(source: &str) -> HashSet<String> {
    let file = match syn::parse_file(source) {
        Ok(f) => f,
        Err(err) => panic!(
            "ffi_conformance: syn failed to parse bridge source: {err}. \
             Refusing to enforce with a degraded scanner."
        ),
    };
    let mut v = FfiFnCollector {
        names: HashSet::new(),
        impl_decorated_stack: Vec::new(),
    };
    v.visit_file(&file);
    v.names
}

struct FfiFnCollector {
    names: HashSet<String>,
    /// Stack of "is enclosing `impl` block FFI-decorated?" flags. Pushed in
    /// `visit_item_impl`, popped after recursion. Nested impls are not a
    /// real Rust pattern but the stack costs nothing and keeps the scanner
    /// composable.
    impl_decorated_stack: Vec<bool>,
}

impl<'ast> Visit<'ast> for FfiFnCollector {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        if !attrs_have_free_fn_ffi_export(&node.attrs) {
            return;
        }
        self.names.insert(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        let impl_decorated = self.impl_decorated_stack.last().copied().unwrap_or(false);
        // Either the impl carries the FFI macro (the common case for
        // `#[pymethods] impl ...` / `#[napi] impl ...`) OR the method itself
        // does (rare but legal — e.g. an individual `#[uniffi::export]`
        // method inside an undecorated impl block).
        let fn_decorated = attrs_have_free_fn_ffi_export(&node.attrs);
        if !impl_decorated && !fn_decorated {
            return;
        }
        self.names.insert(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_trait(&mut self, _node: &'ast syn::ItemTrait) {
        // Trait method signatures are not exports.
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if attrs_contain_cfg_test(&node.attrs) {
            return;
        }
        let decorated = attrs_have_impl_block_ffi_export(&node.attrs);
        self.impl_decorated_stack.push(decorated);
        syn::visit::visit_item_impl(self, node);
        self.impl_decorated_stack.pop();
    }
}

/// Cache key for `FnSetCache`. `(ptr, len)` keys the parsed set against the
/// identity of a `&'static str` — see `fns_of_source` for rationale.
type FnSetCacheKey = (usize, usize);

/// Process-wide cache of parsed fn-name sets, keyed by `FnSetCacheKey`.
type FnSetCache = Mutex<HashMap<FnSetCacheKey, &'static HashSet<String>>>;

/// Returns a cached `HashSet<String>` of FFI-exported function names for the
/// given source — the names a bridge's binding tool would actually expose.
/// Keyed by `(ptr, len)` of the `&'static str` so each `include_str!`-ed
/// bridge file is parsed exactly once per test process.
///
/// Invariant note: every `include_str!(...)` produces a distinct static byte
/// slice with a unique pointer — but in theory a rustc string-constant-merging
/// pass could fold two byte-identical `include_str!` results to the same
/// pointer. That is unlikely to happen in practice (bridge source files are
/// many KB and include surrounding context that makes them textually unique),
/// but keying on `(ptr, len)` rather than `ptr` alone is robust even in the
/// degenerate case: two distinct sources with identical bytes share a cache
/// entry (correct: they parse to the same fn set), and the rare case of two
/// DIFFERENT sources sharing a pointer is impossible when lengths differ.
///
/// Backed by the STRICT scanner (`collect_ffi_exported_fns`) — see its
/// module-level docs above for the export-detection rules. The looser
/// `collect_defined_fns` continues to exist for the cfg(test)-gate fixtures.
fn fns_of_source(source: &'static str) -> &'static HashSet<String> {
    static CACHE: OnceLock<FnSetCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key: FnSetCacheKey = (source.as_ptr() as usize, source.len());
    // Fast path: already cached.
    {
        let guard = cache.lock().expect("fns_of_source cache mutex");
        if let Some(set) = guard.get(&key) {
            return set;
        }
    }
    // Slow path: parse, leak to get a 'static reference, insert.
    let parsed: &'static HashSet<String> = Box::leak(Box::new(collect_ffi_exported_fns(source)));
    let mut guard = cache.lock().expect("fns_of_source cache mutex");
    // Another thread may have inserted between the two lock acquisitions.
    guard.entry(key).or_insert(parsed)
}

/// Resolves an alias name against a single bridge source — STRICT semantics.
/// Returns true iff `source` defines `name` AS AN FFI-EXPORTED FUNCTION:
/// `pub fn` decorated with the bridge's export macro (free-fn form), OR a
/// method inside a `#[pymethods]` / `#[napi]` / `#[uniffi::export]` /
/// `#[wasm_bindgen]` impl block.
fn source_has_fn(source: &'static str, name: &str) -> bool {
    fns_of_source(source).contains(name)
}

fn any_source_has_fn(sources: &[&'static str], name: &str) -> bool {
    sources.iter().any(|s| source_has_fn(s, name))
}

// ---------------------------------------------------------------------------
// Per-bridge detection
// ---------------------------------------------------------------------------

fn pyo3_has_operation(sources: &[&'static str], canonical: &str) -> bool {
    pyo3_names(canonical)
        .iter()
        .any(|name| any_source_has_fn(sources, name))
}

fn uniffi_has_operation(canonical: &str) -> bool {
    // UniFFI's surface spans `bridge.rs` (most ops), `server.rs` (site
    // projection on the Server type), and `scp.rs` (lifecycle methods on
    // the Scp type — `new` / `with_storage` / `suspend` / `resume` /
    // `shutdown`). Search all three. Adding `scp.rs` was a #1543 follow-up
    // when `with_storage` parity exposed the gap — Batch 2 had only
    // included bridge.rs + server.rs.
    uniffi_names(canonical).iter().any(|name| {
        source_has_fn(UNIFFI_BRIDGE, name)
            || source_has_fn(UNIFFI_SERVER, name)
            || source_has_fn(UNIFFI_SCP, name)
    })
}

fn napi_has_operation(sources: &[&'static str], canonical: &str) -> bool {
    napi_names(canonical)
        .iter()
        .any(|name| any_source_has_fn(sources, name))
}

fn wasm_has_operation(sources: &[&'static str], canonical: &str) -> bool {
    wasm_names(canonical)
        .iter()
        .any(|name| any_source_has_fn(sources, name))
}

// ---------------------------------------------------------------------------
// Collected sources per bridge
// ---------------------------------------------------------------------------

fn pyo3_sources() -> Vec<&'static str> {
    vec![
        PYO3_IDENTITY,
        PYO3_CONTEXT,
        PYO3_TOOLS,
        PYO3_UCAN,
        PYO3_EVENT_LOG,
        PYO3_TRANSPORT,
        PYO3_BRIDGE_CONNECTOR,
        PYO3_SYNC,
        PYO3_PROVENANCE,
        PYO3_DISCOVERY,
        PYO3_TRUST,
        PYO3_MCP,
        PYO3_ECONOMY,
        PYO3_MEDIA,
        PYO3_SCP,
        PYO3_SCPID,
        PYO3_SERVER,
    ]
}

fn napi_sources() -> Vec<&'static str> {
    vec![
        NAPI_IDENTITY,
        NAPI_CONTEXT,
        NAPI_TOOLS,
        NAPI_UCAN,
        NAPI_EVENT_LOG,
        NAPI_TRANSPORT,
        NAPI_BRIDGE_CONNECTOR,
        NAPI_SYNC,
        NAPI_PROVENANCE,
        NAPI_DISCOVERY,
        NAPI_TRUST,
        NAPI_MCP,
        NAPI_ECONOMY,
        NAPI_MEDIA,
        NAPI_SCP,
        NAPI_SERVER,
    ]
}

fn wasm_sources() -> Vec<&'static str> {
    vec![
        WASM_IDENTITY,
        WASM_CONTEXT,
        WASM_TOOLS,
        WASM_UCAN,
        WASM_EVENT_LOG,
        WASM_TRANSPORT,
        WASM_SYNC,
        WASM_PROVENANCE,
        WASM_DISCOVERY,
        WASM_TRUST,
        WASM_ECONOMY,
        WASM_SCPID,
    ]
}

// ---------------------------------------------------------------------------
// Category coverage helper
// ---------------------------------------------------------------------------

/// Asserts that every op in `ops` (a slice of `(category, canonical, wasm_required)`
/// tuples — typically produced by filtering `parity_operations()` to a single
/// category) is present in all four bridges, modulo `bridge-aliases.json`
/// exemptions. The `label` parameter controls the category name printed in
/// failure messages — this is decoupled from the category in the tuple so
/// callers can preserve historical wording (e.g. "UCAN" rather than "ucan",
/// "tool" rather than "tools").
fn assert_category_coverage(label: &str, ops: &[&(&'static str, &'static str, bool)]) {
    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    let pyo3_exempt = exemptions_for("pyo3");
    let uniffi_exempt = exemptions_for("uniffi");
    let napi_exempt = exemptions_for("napi");
    let wasm_exempt = exemptions_for("wasm");

    for (_, op, _) in ops {
        if !pyo3_exempt.contains(*op) {
            assert!(
                pyo3_has_operation(&pyo3_srcs, op),
                "PyO3 missing {label} op: {op}"
            );
        }
        if !uniffi_exempt.contains(*op) {
            assert!(uniffi_has_operation(op), "UniFFI missing {label} op: {op}");
        }
        if !napi_exempt.contains(*op) {
            assert!(
                napi_has_operation(&napi_srcs, op),
                "NAPI missing {label} op: {op}"
            );
        }
        if !wasm_exempt.contains(*op) {
            assert!(
                wasm_has_operation(&wasm_srcs, op),
                "WASM missing {label} op: {op}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Coverage result
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BridgeCoverage {
    name: &'static str,
    present: Vec<(&'static str, &'static str)>,
    missing: Vec<(&'static str, &'static str)>,
    total: usize,
}

impl BridgeCoverage {
    fn coverage_pct(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        (self.present.len() as f64 / self.total as f64) * 100.0
    }
}

fn compute_coverage<F>(name: &'static str, detect: F) -> BridgeCoverage
where
    F: Fn(&str) -> bool,
{
    let mut present = Vec::new();
    let mut missing = Vec::new();

    for (category, op, _) in parity_operations() {
        if detect(op) {
            present.push((category, op));
        } else {
            missing.push((category, op));
        }
    }

    let total = parity_operations().len();
    BridgeCoverage {
        name,
        present,
        missing,
        total,
    }
}

fn compute_pyo3_coverage() -> BridgeCoverage {
    let sources = pyo3_sources();
    compute_coverage("PyO3", |op| pyo3_has_operation(&sources, op))
}

fn compute_uniffi_coverage() -> BridgeCoverage {
    compute_coverage("UniFFI", uniffi_has_operation)
}

fn compute_napi_coverage() -> BridgeCoverage {
    let sources = napi_sources();
    compute_coverage("NAPI", |op| napi_has_operation(&sources, op))
}

fn compute_wasm_coverage() -> BridgeCoverage {
    let sources = wasm_sources();
    compute_coverage("WASM", |op| wasm_has_operation(&sources, op))
}

// ---------------------------------------------------------------------------
// Helper: print missing operations
// ---------------------------------------------------------------------------

fn print_coverage(cov: &BridgeCoverage) {
    eprintln!(
        "{} coverage: {:.1}% ({}/{})",
        cov.name,
        cov.coverage_pct(),
        cov.present.len(),
        cov.total
    );
    if !cov.missing.is_empty() {
        eprintln!("{} missing operations:", cov.name);
        for (cat, op) in &cov.missing {
            eprintln!("  {cat}/{op}");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// PyO3 is the reference bridge -- it must cover ALL operations.
#[test]
fn pyo3_bridge_covers_all_operations() {
    let coverage = compute_pyo3_coverage();
    print_coverage(&coverage);

    if !coverage.missing.is_empty() {
        let missing_list: Vec<String> = coverage
            .missing
            .iter()
            .map(|(cat, op)| format!("  {cat}/{op}"))
            .collect();
        panic!(
            "PyO3 (reference bridge) is missing {} operations:\n{}",
            coverage.missing.len(),
            missing_list.join("\n")
        );
    }
}

/// UniFFI bridge should cover all core operations except those explicitly
/// exempted in `scripts/bridge-aliases.json`. The JSON is the single source
/// of truth for exemptions — no hand-maintained lists in this file.
#[test]
fn uniffi_bridge_covers_core_operations() {
    let coverage = compute_uniffi_coverage();
    print_coverage(&coverage);

    let exempt = exemptions_for("uniffi");

    let unexpected_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(_, op)| !exempt.contains(*op))
        .collect();

    assert!(
        unexpected_missing.is_empty(),
        "UniFFI has {} unexpected missing operations: {:?}. \
         If any of these are intentional, add them to \
         scripts/bridge-aliases.json:exemptions.uniffi with a reason.",
        unexpected_missing.len(),
        unexpected_missing
    );

    // Also assert the exempt entries actually correspond to missing ops —
    // an exemption for an operation that IS implemented is stale and should
    // be removed from the JSON.
    let missing_ops: BTreeSet<&str> = coverage.missing.iter().map(|(_, op)| *op).collect();
    let stale_exemptions: Vec<&str> = exempt
        .iter()
        .copied()
        .filter(|e| !missing_ops.contains(e))
        .collect();
    assert!(
        stale_exemptions.is_empty(),
        "UniFFI has stale exemption(s) in bridge-aliases.json (operation is \
         implemented but still listed as exempt): {stale_exemptions:?}. \
         Remove them from exemptions.uniffi."
    );
}

/// NAPI bridge should cover all core operations except those explicitly
/// exempted in `scripts/bridge-aliases.json`. The JSON is the single source
/// of truth for exemptions.
#[test]
fn napi_bridge_covers_core_operations() {
    let coverage = compute_napi_coverage();
    print_coverage(&coverage);

    let exempt = exemptions_for("napi");

    let unexpected_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(_, op)| !exempt.contains(*op))
        .collect();

    assert!(
        unexpected_missing.is_empty(),
        "NAPI has {} unexpected missing operations: {:?}. \
         If any of these are intentional, add them to \
         scripts/bridge-aliases.json:exemptions.napi with a reason.",
        unexpected_missing.len(),
        unexpected_missing
    );

    let missing_ops: BTreeSet<&str> = coverage.missing.iter().map(|(_, op)| *op).collect();
    let stale_exemptions: Vec<&str> = exempt
        .iter()
        .copied()
        .filter(|e| !missing_ops.contains(e))
        .collect();
    assert!(
        stale_exemptions.is_empty(),
        "NAPI has stale exemption(s) in bridge-aliases.json (operation is \
         implemented but still listed as exempt): {stale_exemptions:?}. \
         Remove them from exemptions.napi."
    );
}

/// Returns true iff `reason` cites a DURABLE provenance artifact: an ADR
/// (`ADR-NNN`), a spec section (`§N…`), or a PRD story (`SCP-NNN`). Issue /
/// PR numbers are deliberately NOT accepted — they are ephemeral and project
/// policy forbids issue references in tracked source/data. An exemption is a
/// permanent statement that an operation is intentionally absent from a
/// bridge; it must point at the artifact that justifies the absence, not at a
/// mutable ticket or a hand-wave like "known gap".
fn cites_durable_provenance(reason: &str) -> bool {
    // `prefix` immediately followed by an ASCII digit (e.g. `ADR-0`, `SCP-2`,
    // `§9`). `§` is a 2-byte UTF-8 char, so `i + prefix.len()` lands on a char
    // boundary and the slice is safe.
    let has_numbered = |prefix: &str| {
        reason.match_indices(prefix).any(|(i, _)| {
            reason[i + prefix.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
    };
    has_numbered("ADR-") || has_numbered("SCP-") || has_numbered("§")
}

/// Extracts every `{prefix}NNN` token cited in `text` (maximal digit run after
/// each `prefix`). `cited_tokens("per ADR-034", "ADR-")` yields `["ADR-034"]`,
/// never the prefix `ADR-03` — the maximal run is what makes the existence
/// check reject a fabricated `ADR-3` that happens to be a prefix of a real
/// `ADR-34`. `prefix` is ASCII here (`ADR-` / `SCP-`), so `i + prefix.len()`
/// lands on a char boundary and the slice is safe.
fn cited_tokens(text: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in text.match_indices(prefix) {
        let digits: String = text[i + prefix.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if !digits.is_empty() {
            out.push(format!("{prefix}{digits}"));
        }
    }
    out
}

/// The set of `{prefix}NNN` tokens that actually EXIST under `rel_dir`, read
/// once. ADRs are filed both as standalone `ADR-NNN-*.md` and as headings
/// inside `phase-N.md`; PRD stories are scattered across `.docs/prds/*.json` —
/// in both cases the reliable existence signal is the set of tokens appearing
/// anywhere in the corpus. This turns the exemption gate from "cites something
/// ADR-/SCP-shaped" into "cites a REAL artifact": a fabricated `ADR-999` /
/// `SCP-9999` no longer satisfies the gate.
fn prefixed_tokens_under(rel_dir: &str, prefix: &str) -> BTreeSet<String> {
    let dir = workspace_root().join(rel_dir);
    let entries =
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    let mut set = BTreeSet::new();
    for entry in entries {
        let path = entry.expect("doc dir entry").path();
        if path.is_file() {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            set.extend(cited_tokens(&text, prefix));
        }
    }
    assert!(
        !set.is_empty(),
        "no {prefix}NNN tokens found under {} — the provenance existence \
         check cannot function; has the directory moved?",
        dir.display()
    );
    set
}

/// `ADR-NNN` tokens that exist under `.docs/adrs/`.
fn adrs_in_repo() -> &'static BTreeSet<String> {
    static CELL: OnceLock<BTreeSet<String>> = OnceLock::new();
    CELL.get_or_init(|| prefixed_tokens_under(".docs/adrs", "ADR-"))
}

/// `SCP-NNN` PRD-story tokens that exist under `.docs/prds/`.
fn scp_stories_in_repo() -> &'static BTreeSet<String> {
    static CELL: OnceLock<BTreeSet<String>> = OnceLock::new();
    CELL.get_or_init(|| prefixed_tokens_under(".docs/prds", "SCP-"))
}

/// Every per-bridge exemption MUST justify itself by citing a durable
/// provenance artifact (ADR / spec section / PRD story). This closes the
/// hole where an exemption could be added with an unsubstantiated reason
/// ("not yet implemented", "known gap") that silently suppresses a real
/// parity finding forever. The exemption is the override for the
/// coverage gate — so the override itself must trace to an artifact, per the
/// project's provenance-everywhere tenet.
#[test]
fn every_exemption_reason_cites_durable_provenance() {
    let file = aliases();
    let mut offenders: Vec<String> = Vec::new();
    for (bridge, entries) in [
        ("pyo3", &file.exemptions.pyo3),
        ("uniffi", &file.exemptions.uniffi),
        ("napi", &file.exemptions.napi),
        ("wasm", &file.exemptions.wasm),
    ] {
        for entry in entries {
            if !cites_durable_provenance(&entry.reason) {
                offenders.push(format!(
                    "{bridge}/{}: reason {:?} cites no ADR-/§/SCP- artifact",
                    entry.canonical, entry.reason
                ));
                continue;
            }
            // Shape is necessary but not sufficient: a cited ADR or SCP story
            // must EXIST. This rejects a fabricated `ADR-999` / `SCP-9999`
            // reason that would otherwise pass the shape check and silently
            // substantiate a bogus exemption forever. Both `.docs/adrs/` and
            // `.docs/prds/` are token-greppable, so both synonyms are closed.
            // Spec `§` sections remain shape-only — section numbers like
            // `§9.16` are not a single greppable token against the multi-file
            // spec — but a reason citing only a bare `§` cannot lean on the
            // ADR/SCP synonyms to dodge existence verification.
            let fabricated_adrs: Vec<String> = cited_tokens(&entry.reason, "ADR-")
                .into_iter()
                .filter(|t| !adrs_in_repo().contains(t))
                .collect();
            let fabricated_stories: Vec<String> = cited_tokens(&entry.reason, "SCP-")
                .into_iter()
                .filter(|t| !scp_stories_in_repo().contains(t))
                .collect();
            if !fabricated_adrs.is_empty() {
                offenders.push(format!(
                    "{bridge}/{}: reason {:?} cites non-existent ADR(s) {:?} \
                     (no matching file/heading under .docs/adrs/)",
                    entry.canonical, entry.reason, fabricated_adrs
                ));
            }
            if !fabricated_stories.is_empty() {
                offenders.push(format!(
                    "{bridge}/{}: reason {:?} cites non-existent PRD story(s) \
                     {:?} (no matching SCP-NNN under .docs/prds/)",
                    entry.canonical, entry.reason, fabricated_stories
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "bridge-aliases.json exemption(s) lack durable provenance \
         (cite a REAL ADR-NNN, spec §section, or SCP-NNN story — not an issue \
         number, not a hand-wave, not a fabricated ADR/story): {offenders:#?}"
    );
}

#[test]
fn provenance_detector_accepts_durable_artifacts() {
    assert!(cites_durable_provenance(
        "WASM lacks the tokio runtime per ADR-034"
    ));
    assert!(cites_durable_provenance(
        "Sender-side key layer, separate from MLS (spec §9.16)"
    ));
    assert!(cites_durable_provenance(
        "Tracked by PRD story SCP-214 criterion 10"
    ));
}

#[test]
fn provenance_detector_rejects_hand_waves_and_issue_refs() {
    // Hand-wave with no artifact.
    assert!(!cites_durable_provenance("not yet exported (known gap)"));
    // Issue / PR numbers are ephemeral and policy-forbidden — not provenance.
    assert!(!cites_durable_provenance("see issue #1543 and PR #1735"));
    // Bare prefix with no number must not pass.
    assert!(!cites_durable_provenance("documented in an ADR- somewhere"));
    assert!(!cites_durable_provenance("see § for details"));
    assert!(!cites_durable_provenance(""));
}

#[test]
fn cited_tokens_extracts_maximal_digit_runs() {
    assert_eq!(
        cited_tokens("per ADR-034 and ADR-3", "ADR-"),
        ["ADR-034", "ADR-3"]
    );
    assert_eq!(cited_tokens("tracked by SCP-214", "SCP-"), ["SCP-214"]);
    assert_eq!(cited_tokens("no token here", "ADR-"), Vec::<String>::new());
    // Prefix with no trailing digit yields nothing.
    assert_eq!(
        cited_tokens("an ADR- without a number", "ADR-"),
        Vec::<String>::new()
    );
}

/// The existence check backing the exemption gate: a real artifact is present
/// in its corpus; a fabricated one is not. This is what makes the gate reject
/// shape-valid-but-bogus reasons like "WASM gap, see ADR-999" / "see SCP-9999".
#[test]
fn provenance_existence_distinguishes_real_from_fabricated() {
    let adrs = adrs_in_repo();
    // ADR-048 is this very document; ADR-034 governs WASM constraints and is
    // cited by every current wasm exemption — both must be present.
    assert!(adrs.contains("ADR-048"), "ADR-048 should exist in corpus");
    assert!(adrs.contains("ADR-034"), "ADR-034 should exist in corpus");
    // A fabricated ADR must NOT be present (the prefix `ADR-9` of a real ADR
    // must not produce a false positive either — maximal-run extraction).
    assert!(!adrs.contains("ADR-999"), "ADR-999 must not exist");

    let stories = scp_stories_in_repo();
    assert!(
        stories.contains("SCP-214"),
        "SCP-214 should exist in corpus"
    );
    assert!(!stories.contains("SCP-9999"), "SCP-9999 must not exist");
}

/// WASM bridge has intentionally fewer operations per ADR-034.
/// This test verifies all wasm_required operations are present and reports
/// optional gaps without failing.
#[test]
fn wasm_bridge_covers_core_operations() {
    let coverage = compute_wasm_coverage();
    print_coverage(&coverage);

    let ops = parity_operations();

    // Separate required vs optional gaps
    let required_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(cat, op)| ops.iter().any(|(c, o, req)| c == cat && o == op && *req))
        .collect();

    let optional_missing: Vec<_> = coverage
        .missing
        .iter()
        .filter(|(cat, op)| ops.iter().any(|(c, o, req)| c == cat && o == op && !*req))
        .collect();

    if !optional_missing.is_empty() {
        eprintln!("WASM intentionally omitted operations (ADR-034, not failures):");
        for (cat, op) in &optional_missing {
            eprintln!("  {cat}/{op}");
        }
    }

    assert!(
        required_missing.is_empty(),
        "WASM is missing {} required operations: {:?}",
        required_missing.len(),
        required_missing
    );

    // Stale-exemptions guard (parity with uniffi/napi covers-core tests):
    // an exemption for an operation that IS implemented is stale and should
    // be removed from the JSON. WASM lacked this check, so a WASM op could be
    // wired up while its exemption silently lingered, masking future drift.
    let exempt = exemptions_for("wasm");
    let missing_ops: BTreeSet<&str> = coverage.missing.iter().map(|(_, op)| *op).collect();
    let stale_exemptions: Vec<&str> = exempt
        .iter()
        .copied()
        .filter(|e| !missing_ops.contains(e))
        .collect();
    assert!(
        stale_exemptions.is_empty(),
        "WASM has stale exemption(s) in bridge-aliases.json (operation is \
         implemented but still listed as exempt): {stale_exemptions:?}. \
         Remove them from exemptions.wasm."
    );
}

/// Cross-bridge parity matrix: builds and prints a matrix of all operations
/// across all 4 bridges. Documents the current state of parity.
///
/// Assertions:
/// 1. PyO3 (reference) must be 100%.
/// 2. Every bridge must cover all operations marked wasm_required=true
///    (with documented exclusions per bridge).
#[test]
fn cross_bridge_parity_matrix() {
    let pyo3 = compute_pyo3_coverage();
    let uniffi = compute_uniffi_coverage();
    let napi = compute_napi_coverage();
    let wasm = compute_wasm_coverage();

    // Print matrix header
    eprintln!();
    eprintln!(
        "{:<15} {:<40} {:>5} {:>6} {:>5} {:>5}",
        "Category", "Operation", "PyO3", "UniFFI", "NAPI", "WASM"
    );
    eprintln!("{}", "-".repeat(82));

    for (category, op, _wasm_required) in parity_operations() {
        let p = pyo3.present.iter().any(|(_, o)| *o == op);
        let u = uniffi.present.iter().any(|(_, o)| *o == op);
        let n = napi.present.iter().any(|(_, o)| *o == op);
        let w = wasm.present.iter().any(|(_, o)| *o == op);

        let mark = |present: bool| if present { "Y" } else { "-" };

        eprintln!(
            "{:<15} {:<40} {:>5} {:>6} {:>5} {:>5}",
            category,
            op,
            mark(p),
            mark(u),
            mark(n),
            mark(w)
        );
    }

    // Summary
    eprintln!("{}", "-".repeat(82));
    eprintln!(
        "{:<15} {:<40} {:>5} {:>6} {:>5} {:>5}",
        "TOTAL",
        "",
        pyo3.present.len(),
        uniffi.present.len(),
        napi.present.len(),
        wasm.present.len()
    );
    eprintln!(
        "{:<15} {:<40} {:>4.1}% {:>5.1}% {:>4.1}% {:>4.1}%",
        "COVERAGE",
        "",
        pyo3.coverage_pct(),
        uniffi.coverage_pct(),
        napi.coverage_pct(),
        wasm.coverage_pct()
    );
    eprintln!();

    // PyO3 is the reference -- must be 100%
    assert_eq!(
        pyo3.present.len(),
        pyo3.total,
        "PyO3 (reference bridge) must have 100% coverage"
    );

    // Count total unique operations across all non-reference bridges
    let all_gaps: usize = uniffi.missing.len() + napi.missing.len() + wasm.missing.len();
    eprintln!("Total parity gaps across non-reference bridges: {all_gaps}");

    // Verify minimum coverage thresholds
    assert!(
        uniffi.coverage_pct() >= 85.0,
        "UniFFI coverage {:.1}% below 85% threshold",
        uniffi.coverage_pct()
    );
    assert!(
        napi.coverage_pct() >= 95.0,
        "NAPI coverage {:.1}% below 95% threshold",
        napi.coverage_pct()
    );
    // WASM legitimately omits ADR-034-exempt operations (it cannot depend on
    // scp-runtime). Measuring coverage over the FULL parity set would
    // mechanically drift this floor down every time an exempt op is added —
    // the metric would punish WASM for ops it is correctly NOT expected to
    // implement. So coverage is computed over the NON-EXEMPT operations WASM
    // is actually expected to cover (present / (total - wasm-exempt)). This is
    // drift-immune: adding an exempt op increases both the exempt count and
    // the total by one, leaving the non-exempt denominator unchanged. The hard
    // requirement (every `wasm_required` op present) is enforced separately by
    // `wasm_bridge_covers_core_operations`, and exemption legitimacy by
    // `every_exemption_reason_cites_durable_provenance`.
    let wasm_exempt = exemptions_for("wasm").len();
    let wasm_non_exempt_total = wasm.total.saturating_sub(wasm_exempt);
    let wasm_non_exempt_pct = if wasm_non_exempt_total == 0 {
        100.0
    } else {
        (wasm.present.len() as f64 / wasm_non_exempt_total as f64) * 100.0
    };
    assert!(
        wasm_non_exempt_pct >= 70.0,
        "WASM coverage of non-exempt operations {:.1}% below 70% threshold \
         ({} present / {} non-exempt total; {} exempt)",
        wasm_non_exempt_pct,
        wasm.present.len(),
        wasm_non_exempt_total,
        wasm_exempt
    );
}

// ---------------------------------------------------------------------------
// Marker attribute presence tests
// ---------------------------------------------------------------------------

/// Verifies PyO3 source files actually contain `#[pyfunction]` markers.
#[test]
fn pyo3_sources_contain_pyfunction_markers() {
    let sources = pyo3_sources();
    let marker_count: usize = sources
        .iter()
        .map(|s| s.matches("#[pyfunction]").count())
        .sum();

    eprintln!("PyO3 #[pyfunction] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[pyfunction] markers, found {marker_count}"
    );
}

/// Verifies UniFFI bridge source contains `#[uniffi::export]` markers.
#[test]
fn uniffi_source_contains_export_markers() {
    let marker_count = UNIFFI_BRIDGE.matches("#[uniffi::export]").count();

    eprintln!("UniFFI #[uniffi::export] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[uniffi::export] markers, found {marker_count}"
    );
}

/// Verifies NAPI source files actually contain napi-rs export markers.
///
/// Phase 4 PR 4 migrated free-function napi exports into `impl Scp { ... }`
/// methods; most of those methods carry `#[napi(js_name = "...")]` instead
/// of the bare `#[napi]` attribute. Accept both forms by counting the
/// shared `#[napi` prefix (which covers `#[napi]`, `#[napi(...)]`,
/// `#[napi(object)]`, etc.).
#[test]
fn napi_sources_contain_napi_markers() {
    let sources = napi_sources();
    let marker_count: usize = sources.iter().map(|s| s.matches("#[napi").count()).sum();

    eprintln!("NAPI #[napi...] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[napi...] markers, found {marker_count}"
    );
}

/// Verifies WASM source files actually contain `#[wasm_bindgen]` markers.
#[test]
fn wasm_sources_contain_wasm_bindgen_markers() {
    let sources = wasm_sources();
    let marker_count: usize = sources
        .iter()
        .map(|s| s.matches("#[wasm_bindgen]").count())
        .sum();

    eprintln!("WASM #[wasm_bindgen] count: {marker_count}");
    assert!(
        marker_count >= 30,
        "Expected at least 30 #[wasm_bindgen] markers, found {marker_count}"
    );
}

// ---------------------------------------------------------------------------
// Per-category coverage depth tests
// ---------------------------------------------------------------------------

/// Verifies identity operations are present across all bridges. Per-bridge
/// exemptions are sourced from `scripts/bridge-aliases.json` — the same
/// single source of truth used by the per-bridge coverage tests and the
/// shell symmetry script. No hand-maintained skip lists here.
#[test]
fn identity_category_coverage() {
    let ops = parity_operations();
    let identity_ops: Vec<_> = ops
        .iter()
        .filter(|(cat, _, _)| *cat == "identity")
        .collect();
    assert_category_coverage("identity", &identity_ops);
}

/// Verifies context lifecycle operations are present across all bridges.
/// Handles naming variance: PyO3 uses `context_receive` for `context_subscribe`.
/// Per-bridge exemptions are sourced from `scripts/bridge-aliases.json`.
#[test]
fn context_category_coverage() {
    let ops = parity_operations();
    let context_ops: Vec<_> = ops.iter().filter(|(cat, _, _)| *cat == "context").collect();
    assert_category_coverage("context", &context_ops);
}

/// Verifies UCAN operations are present across all bridges. Per-bridge
/// exemptions are sourced from `scripts/bridge-aliases.json`.
#[test]
fn ucan_category_coverage() {
    let ops = parity_operations();
    let ucan_ops: Vec<_> = ops.iter().filter(|(cat, _, _)| *cat == "ucan").collect();
    assert_category_coverage("UCAN", &ucan_ops);
}

/// Verifies tool operations are present across all bridges. Per-bridge
/// exemptions are sourced from `scripts/bridge-aliases.json`.
#[test]
fn tools_category_coverage() {
    let ops = parity_operations();
    let tool_ops: Vec<_> = ops.iter().filter(|(cat, _, _)| *cat == "tools").collect();
    assert_category_coverage("tool", &tool_ops);
}

/// Verifies broadcast operations are present across all bridges.
/// Accounts for naming variance: `broadcast_block` vs `broadcast_block_subscriber`.
/// Per-bridge exemptions are sourced from `scripts/bridge-aliases.json`.
#[test]
fn broadcast_category_coverage() {
    let ops = parity_operations();
    let broadcast_ops: Vec<_> = ops
        .iter()
        .filter(|(cat, _, _)| *cat == "broadcast")
        .collect();
    assert_category_coverage("broadcast", &broadcast_ops);
}

/// Verifies trust operations are present across all bridges. Per-bridge
/// exemptions are sourced from `scripts/bridge-aliases.json`.
#[test]
fn trust_category_coverage() {
    let ops = parity_operations();
    let trust_ops: Vec<_> = ops.iter().filter(|(cat, _, _)| *cat == "trust").collect();
    assert_category_coverage("trust", &trust_ops);
}

/// Verifies event_log operations are present across all bridges. Per-bridge
/// exemptions are sourced from `scripts/bridge-aliases.json`.
#[test]
fn event_log_category_coverage() {
    let ops = parity_operations();
    let event_log_ops: Vec<_> = ops
        .iter()
        .filter(|(cat, _, _)| *cat == "event_log")
        .collect();
    assert_category_coverage("event_log", &event_log_ops);
}

/// Verifies discovery and provenance operations are present across all bridges.
/// Per-bridge exemptions are sourced from `scripts/bridge-aliases.json`.
#[test]
fn discovery_and_provenance_coverage() {
    let ops = parity_operations();
    let discovery_ops: Vec<_> = ops
        .iter()
        .filter(|(cat, _, _)| *cat == "discovery")
        .collect();
    let provenance_ops: Vec<_> = ops
        .iter()
        .filter(|(cat, _, _)| *cat == "provenance")
        .collect();
    assert_category_coverage("discovery", &discovery_ops);
    assert_category_coverage("provenance", &provenance_ops);
}

// =========================================================================
// RATCHET CONSTANTS — may only increase
// Any decrease requires human approval
// =========================================================================

// Ratchet lowered from 98 -> 97 by the spec §19.7 anti-spam wiring plan:
// the non-spec EIP-1559-style relay base-price adjustment operation
// (`economy_adjust_relay_price` / `py_economy_adjust_relay_price` /
// `napi_economy_adjust_relay_price` / `economy_adjust_relay_price` in
// UniFFI / `wasm_economy_adjust_relay_price`) was deleted across all FFI
// bridges + language SDK wrappers. `adjust_relay_price` implemented
// Matrix-style aggregate pricing adjustment; the authoritative per-DID
// escalation mechanism (spec §19.7) replaces it and is wired through
// the existing `context_send_message` and `context_invoke_tool_with_economy`
// paths, so no new parity operation was added in its place. This is a
// legitimate removal; the ratchet is reset to the new floor. See commit
// 2291102.
//
// Subsequently RAISED 97 -> 104 by the reverse-coverage gate: seven operations
// were exported across bridges but absent from the alias table (the
// hide-by-omission class). They are now registered, expanding coverage. The
// seven: `metadata_record_to_json` (spec §5.7.2, the to_json counterpart of
// the already-registered `metadata_record_from_json`); `commit_deploy` /
// `rollback_deploy` (ADR-037; spec §10.14.3 site-projection deploy, wasm-exempt
// server ops); and the four transport relay-management ops
// `transport_add_relay` / `transport_assign_relay_set` /
// `transport_adapter_count` / `transport_reliability` (ADR-013 transport
// adapter set, wasm-exempt — WASM has no scp-platform per ADR-034). This is a
// pure coverage expansion, not a swap for the removed `economy_adjust_relay_price`.
const MIN_PARITY_OPERATIONS: usize = 104;

/// Named set of operations that must have `wasm_required=true`.
/// This is a named set, not a count — swapping one operation for another is
/// caught. Operations can be added but never removed or weakened.
const WASM_REQUIRED_OPERATIONS: &[&str] = &[
    // Identity
    "identity_create",
    "identity_load",
    "identity_resolve",
    "identity_remove",
    "identity_remove_if_present",
    "identity_migrate",
    "identity_attest_device",
    "identity_verify_device_attestation",
    "identity_verify_link_attestation",
    // Context lifecycle
    "context_create",
    "context_join",
    "context_leave",
    "context_close",
    "context_send",
    "context_subscribe",
    "context_export",
    "context_import",
    // Membership
    "context_member_count",
    "context_is_member",
    "context_member_dids",
    "context_member_role",
    // Events
    "context_drain_events",
    // Governance
    "governance_execute",
    // Tools (core only — sessions and cross-context are optional)
    "tool_register",
    "tool_invoke",
    "tool_verify",
    "tool_interface_expose",
    "tool_interface_accept",
    "tool_interface_revoke",
    // UCAN
    "ucan_validate",
    "ucan_mint",
    "ucan_revoke",
    "ucan_delegate",
    // Event Log
    "event_log_query",
    "event_log_verify",
    "event_log_checkpoint",
    "event_log_checkpoint_by_did",
    // Broadcast
    "broadcast_subscribe",
    "broadcast_unsubscribe",
    "broadcast_publish",
    "broadcast_block",
    "broadcast_subscriber_count",
    "broadcast_is_subscriber",
    "broadcast_admission",
    // Trust
    "trust_query_score",
    "trust_verify_attestation",
    "trust_create_challenge",
    "trust_verify_response",
    "verify_participation_requirements",
    // Sync
    "sync_classify_offline",
    "sync_classify_offline_custom",
    "sync_get_policy",
    // Discovery
    "discovery_parse_address",
    "discovery_normalize_address",
    // Provenance
    "provenance_check_chain_depth",
    "evaluate_provenance_quality",
    "provenance_attach",
    // Petname
    "petname_set",
    "petname_remove",
    "petname_set_context",
    "petname_remove_context",
    "petname_resolve_did",
    "petname_resolve_context",
    "petname_get_for_did",
    "petname_get_for_context",
    // Petname event-replay + count queries
    // promoted from WASM-only to cross-bridge parity. Backed by
    // scp_protocol::discovery::petnames::PetnameMap apply_event / did_petname_count
    // / context_petname_count (the same shared type the other petname ops use).
    "petname_apply_event",
    "petname_did_count",
    "petname_context_count",
    // Handle/Scope
    "handle_register",
    "handle_lookup",
    "handle_deregister",
    "scope_register",
    "scope_lookup",
    "scope_deregister",
    // Governance checkpoints
    "context_create_governance_checkpoint",
    "context_add_checkpoint_cosignature",
    // Batch 2 (#1543) — 31 Batch-1 ops promoted from optional to required after
    // matrix hygiene confirmed each is implemented across all four bridges with
    // a real `fn` definition (verified by every_alias_resolves_to_a_real_fn_or_exemption).
    // Governance lifecycle (4)
    "context_governance_propose",
    "context_governance_approve",
    "context_governance_reject",
    "context_governance_withdraw",
    "context_governance_get_proposal",
    "context_governance_list_proposals",
    // Sandbox / capability checking (Batch 3f)
    "sandbox_check_capability",
    "sandbox_validate_declaration",
    // Context lifecycle (6)
    "context_finalize_close",
    "context_apply_pending_ceiling_modification",
    "context_get_economic_policy",
    "context_set_economic_policy",
    "context_restore",
    "context_restore_all",
    // TTL (3)
    "context_handle_ttl_expiry",
    "context_propose_ttl_extension",
    "context_reset_ttl_timer",
    // Broadcast (4)
    "broadcast_publish_asset",
    "broadcast_publish_assets",
    "broadcast_handle_key_request",
    "broadcast_unblock",
    // Identity (7)
    "identity_link_attestations",
    "identity_create_link_attestation",
    "identity_create_with_agent_key",
    "identity_execute_recovery",
    "identity_execute_custody_migration",
    "identity_add_agent_key",
    "identity_remove_agent_key",
    "identity_rotate_agent_key",
    "identity_rotate_key",
    // Stateless utility ops (4)
    "address_resolve",
    "aggregate_trust_input",
    "evaluate_invitation",
    "transport_disconnect",
    // Provenance (3)
    "provenance_redact_counterparties",
    "provenance_pseudonymize_counterparties",
    "provenance_update_source_type",
    // Batch 2 — newly registered SCPID ops promoted alongside the 31 Batch-1
    // ops. `scpid_verify` stays optional (WASM-exempt: needs network DID resolver).
    "scpid_challenge",
    "scpid_sign",
];

// ---------------------------------------------------------------------------
// Ratchet meta-tests — detect weakening of enforcement
// ---------------------------------------------------------------------------

/// The total operation count must never decrease. New operations may be
/// added; existing operations must not be removed without human approval.
#[test]
fn parity_operation_count_never_decreases() {
    let ops = parity_operations();
    assert!(
        ops.len() >= MIN_PARITY_OPERATIONS,
        "parity operations has {} entries, minimum is {}. \
         Operations were removed without updating the ratchet.",
        ops.len(),
        MIN_PARITY_OPERATIONS
    );
}

/// Every operation in `WASM_REQUIRED_OPERATIONS` must remain in
/// parity operations with `wasm_required=true`. Changing an operation
/// from required to optional (or removing it) is caught.
#[test]
fn wasm_required_set_not_weakened() {
    let ops = parity_operations();
    for op_name in WASM_REQUIRED_OPERATIONS {
        let entry = ops.iter().find(|(_, name, _)| name == op_name);
        assert!(entry.is_some(), "{op_name} removed from parity operations");
        assert!(
            entry.unwrap().2,
            "{op_name} changed from wasm_required=true to false"
        );
    }
}

/// Verify that WASM_REQUIRED_OPERATIONS is consistent with the parity table.
/// Every operation marked `wasm_required=true` in the table must
/// appear in the named set.
#[test]
fn wasm_required_set_is_complete() {
    for (_, op, required) in parity_operations() {
        if required {
            assert!(
                WASM_REQUIRED_OPERATIONS.contains(&op),
                "Operation {op} has wasm_required=true but is not in WASM_REQUIRED_OPERATIONS. \
                 Add it to the named set."
            );
        }
    }
}

/// F10 meta-test: ensures the MIN_PARITY_OPERATIONS ratchet comment cites
/// the real deleted operation name (`economy_adjust_relay_price`) rather
/// than any fabricated name. Guards against phantom-provenance regressions
/// in enforcement files.
#[test]
fn min_parity_operations_comment_references_real_deletion() {
    let src = include_str!("ffi_conformance.rs");
    // Locate the MIN_PARITY_OPERATIONS const and walk backwards to its
    // immediately preceding ratchet comment block.
    let idx = src
        .find("const MIN_PARITY_OPERATIONS")
        .expect("MIN_PARITY_OPERATIONS constant present");
    let prelude = &src[..idx];
    let comment_start = prelude
        .rfind("// Ratchet")
        .expect("ratchet comment present above MIN_PARITY_OPERATIONS");
    let comment = &prelude[comment_start..];
    assert!(
        comment.contains("economy_adjust_relay_price"),
        "ratchet comment must cite the real deleted op name, got: {comment}"
    );
    assert!(
        !comment.contains("economy_evaluate_relay_cost"),
        "ratchet comment must not cite the fabricated op name \
         'economy_evaluate_relay_cost'"
    );
}

// ---------------------------------------------------------------------------
// Cross-validation: scripts/bridge-aliases.json must match the ratchet
// ---------------------------------------------------------------------------

/// Ensures the shell-side enforcement source of truth (bridge-aliases.json)
/// and the Rust-side ratchet constants stay in lockstep. Without this test,
/// someone could add a canonical operation to the JSON without surfacing it
/// in the named WASM_REQUIRED_OPERATIONS set (and vice versa).
#[test]
fn aliases_json_is_in_sync_with_parity_operations() {
    let file = aliases();

    // 1. Count: must meet or exceed the ratchet floor.
    assert!(
        file.operations.len() >= MIN_PARITY_OPERATIONS,
        "bridge-aliases.json has {} operations, ratchet requires at least {}",
        file.operations.len(),
        MIN_PARITY_OPERATIONS
    );

    // 2. No duplicate canonical names.
    let mut canon_set: BTreeSet<&str> = BTreeSet::new();
    for op in &file.operations {
        assert!(
            canon_set.insert(op.canonical.as_str()),
            "bridge-aliases.json contains duplicate canonical name: {}",
            op.canonical
        );
    }

    // 3. No empty or duplicate aliases within a bridge's list.
    for op in &file.operations {
        for (bridge_name, aliases) in [
            ("pyo3", &op.pyo3),
            ("uniffi", &op.uniffi),
            ("napi", &op.napi),
            ("wasm", &op.wasm),
        ] {
            let mut seen = HashSet::new();
            for alias in aliases {
                assert!(
                    !alias.is_empty(),
                    "empty alias in {bridge_name} list for canonical {}",
                    op.canonical
                );
                assert!(
                    seen.insert(alias.as_str()),
                    "duplicate alias {alias} in {bridge_name} list for canonical {}",
                    op.canonical
                );
            }
        }
    }

    // 4. wasm_required=true set must equal the named WASM_REQUIRED_OPERATIONS
    //    set (catches drift in either direction).
    let json_wasm_required: BTreeSet<&str> = file
        .operations
        .iter()
        .filter(|op| op.wasm_required)
        .map(|op| op.canonical.as_str())
        .collect();
    let rust_wasm_required: BTreeSet<&str> = WASM_REQUIRED_OPERATIONS.iter().copied().collect();
    assert_eq!(
        json_wasm_required,
        rust_wasm_required,
        "bridge-aliases.json wasm_required set diverges from Rust \
         WASM_REQUIRED_OPERATIONS: json_only={:?} rust_only={:?}",
        json_wasm_required
            .difference(&rust_wasm_required)
            .collect::<Vec<_>>(),
        rust_wasm_required
            .difference(&json_wasm_required)
            .collect::<Vec<_>>()
    );

    // 5. Every canonical op's per-bridge alias array is either non-empty
    //    (the alias the script searches for) OR the canonical is in the
    //    bridge's exemption list with a documented reason. The combined
    //    invariant is enforced by `every_bridge_alias_array_is_non_empty_or_exempt`,
    //    which runs as its own test and gives a complete (op, bridge) report
    //    on violation rather than panicking on the first one. We delegate to
    //    that test here rather than re-running the same loop with a weaker
    //    error message.
}

/// Every alias declared in `bridge-aliases.json` must EITHER resolve to a
/// real `fn <alias>(` definition in the corresponding bridge's source tree,
/// OR the canonical operation must be listed in that bridge's `exemptions`
/// array.
///
/// This blocks the adversarial pattern where an agent adds a fake alias like
/// `"napi": ["fake_symbol"]` to the JSON to pretend an op is implemented.
/// The existing count/duplicate/empty checks do not catch that.
#[test]
fn every_alias_resolves_to_a_real_fn_or_exemption() {
    let file = aliases();
    let pyo3_srcs = pyo3_sources();
    let napi_srcs = napi_sources();
    let wasm_srcs = wasm_sources();

    let pyo3_exempt = exemptions_for("pyo3");
    let uniffi_exempt = exemptions_for("uniffi");
    let napi_exempt = exemptions_for("napi");
    let wasm_exempt = exemptions_for("wasm");

    let mut phantom: Vec<String> = Vec::new();

    for op in &file.operations {
        // --- pyo3 ---
        if !pyo3_exempt.contains(op.canonical.as_str()) {
            let any_resolves = op
                .pyo3
                .iter()
                .any(|name| any_source_has_fn(&pyo3_srcs, name));
            if !any_resolves {
                phantom.push(format!(
                    "pyo3:{} — none of the declared aliases {:?} resolve to `fn <name>(` in crates/scp-ffi/src/",
                    op.canonical, op.pyo3
                ));
            }
        }
        // --- uniffi ---
        if !uniffi_exempt.contains(op.canonical.as_str()) {
            let any_resolves = op.uniffi.iter().any(|name| {
                source_has_fn(UNIFFI_BRIDGE, name)
                    || source_has_fn(UNIFFI_SERVER, name)
                    || source_has_fn(UNIFFI_SCP, name)
            });
            if !any_resolves {
                phantom.push(format!(
                    "uniffi:{} — none of the declared aliases {:?} resolve to `fn <name>(` in crates/scp-ffi/uniffi/src/{{bridge,server,scp}}.rs",
                    op.canonical, op.uniffi
                ));
            }
        }
        // --- napi ---
        if !napi_exempt.contains(op.canonical.as_str()) {
            let any_resolves = op
                .napi
                .iter()
                .any(|name| any_source_has_fn(&napi_srcs, name));
            if !any_resolves {
                phantom.push(format!(
                    "napi:{} — none of the declared aliases {:?} resolve to `fn <name>(` in crates/scp-ffi/napi/src/",
                    op.canonical, op.napi
                ));
            }
        }
        // --- wasm --- (only when required, mirroring CI script behavior)
        if op.wasm_required && !wasm_exempt.contains(op.canonical.as_str()) {
            let any_resolves = op
                .wasm
                .iter()
                .any(|name| any_source_has_fn(&wasm_srcs, name));
            if !any_resolves {
                phantom.push(format!(
                    "wasm:{} — none of the declared aliases {:?} resolve to `fn <name>(` in crates/scp-ffi/wasm/src/",
                    op.canonical, op.wasm
                ));
            }
        }
    }

    assert!(
        phantom.is_empty(),
        "bridge-aliases.json contains {} phantom alias declaration(s) — an alias was \
         listed but no matching `fn <alias>(` exists in the bridge's source tree and \
         the canonical is not exempted:\n  {}",
        phantom.len(),
        phantom.join("\n  ")
    );
}

/// Guards the cleanup pass that emptied placeholder alias arrays for
/// operations a bridge has been excused from implementing. Every per-bridge
/// alias array in `scripts/bridge-aliases.json` must be either:
///
///   • non-empty (real impl is expected to exist in source — verified by
///     `every_alias_resolves_to_a_real_fn_or_exemption`), OR
///   • empty AND the canonical is in `exemptions[bridge]` (intentionally
///     not implemented in that bridge).
///
/// Empty arrays without an exemption are a phantom: they declare "no aliases"
/// for a bridge that nominally must support the op. The opposite (non-empty
/// arrays + exemption) is also redundant — exemption already says the bridge
/// does not need to implement, so a non-empty alias is either a stale
/// placeholder or a stale exemption. Both are flagged.
///
/// Companion to `every_alias_resolves_to_a_real_fn_or_exemption`: that test
/// verifies the *content* of non-empty arrays resolves to real fns; this test
/// verifies the *presence* of every (op, bridge) pair as either non-empty or
/// exempt, with no in-between placeholder state.
#[test]
fn every_bridge_alias_array_is_non_empty_or_exempt() {
    let file = aliases();
    let pyo3_exempt = exemptions_for("pyo3");
    let uniffi_exempt = exemptions_for("uniffi");
    let napi_exempt = exemptions_for("napi");
    let wasm_exempt = exemptions_for("wasm");

    let mut violations: Vec<String> = Vec::new();
    let mut redundant: Vec<String> = Vec::new();

    for op in &file.operations {
        // (bridge, alias_array, exempt_set)
        let cells: [(&str, &[String], &BTreeSet<&'static str>); 4] = [
            ("pyo3", op.pyo3.as_slice(), &pyo3_exempt),
            ("uniffi", op.uniffi.as_slice(), &uniffi_exempt),
            ("napi", op.napi.as_slice(), &napi_exempt),
            ("wasm", op.wasm.as_slice(), &wasm_exempt),
        ];
        for (bridge, aliases, exempt) in cells {
            let is_exempt = exempt.contains(op.canonical.as_str());
            if aliases.is_empty() && !is_exempt {
                violations.push(format!(
                    "{}:{} has empty alias array but is not in exemptions.{}",
                    bridge, op.canonical, bridge
                ));
            } else if !aliases.is_empty() && is_exempt {
                redundant.push(format!(
                    "{}:{} is in exemptions.{} but still declares aliases {:?} \
                     — empty the array (preferred) or remove the exemption",
                    bridge, op.canonical, bridge, aliases
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "bridge-aliases.json has {} (op, bridge) cell(s) with an empty alias \
         array and no matching exemption — either declare an alias or add an \
         exemption with a reason:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
    assert!(
        redundant.is_empty(),
        "bridge-aliases.json has {} (op, bridge) cell(s) listed as exempt \
         but still carrying a non-empty alias placeholder — empty the array \
         (cleanup) or remove the exemption (no longer accurate):\n  {}",
        redundant.len(),
        redundant.join("\n  ")
    );
}

/// Guards against reintroduction of hand-maintained exclusion lists inside
/// this file that duplicate the `exemptions` section of
/// `scripts/bridge-aliases.json`. The JSON is the single source of truth —
/// any drift is a footgun. Fails loudly if a hand-rolled skip-list
/// identifier reappears as an assignment target (a previous regression
/// lived here: `mcp_server` / `identity_migrate` were duplicated in both
/// places).
#[test]
fn no_hardcoded_exclusion_arrays_in_this_file() {
    let src = include_str!("ffi_conformance.rs");
    // Banned tokens are encoded with a string-concat so the test body itself
    // does not trigger the match. The assertion hunts for `let <token>` which
    // is how the old hand-rolled arrays were declared — harmless occurrences
    // of the same substring in comments or messages do not trip it.
    let banned_names: Vec<String> = vec![
        format!("{}_{}", "known", "exclusions"),
        format!("{}_missing_{}", "known", "count"),
    ];
    for name in &banned_names {
        let needle = format!("let {name}");
        assert!(
            !src.contains(&needle),
            "ffi_conformance.rs reintroduced hand-maintained `{name}` list. \
             Exemptions live in scripts/bridge-aliases.json only — read them via \
             exemptions_for(bridge) instead."
        );
    }
}

// ---------------------------------------------------------------------------
// Syn scanner adversarial tests — guard against drift between the shell and
// Rust scanners. The bash fixture under
// `scripts/tests/bridge-symmetry/fixtures/bad-alias-in-test-module-only/`
// exercises the bash path only. These tests exercise the Rust `syn` path over
// the same fixture source, so if either side weakens its cfg(test) exclusion
// the matrix catches it.
// ---------------------------------------------------------------------------

/// Adversarial fn-hidden-in-test-module fixture: asserts the Rust `syn`
/// scanner EXCLUDES a fn defined inside `#[cfg(test)] mod tests { ... }` the
/// same way the bash scanner does. Without this test, the two scanners could
/// silently drift and let a phantom alias through.
#[test]
fn syn_scanner_excludes_cfg_test_module() {
    // Embed the fixture source at compile time so it moves with the file and
    // we do not depend on runtime cwd. The fixture's intent: `widget_create`
    // is defined ONLY inside `#[cfg(test)] mod tests { ... }` — the scanner
    // must not report it.
    const FIXTURE: &str = include_str!(
        "../../../../scripts/tests/bridge-symmetry/fixtures/\
         bad-alias-in-test-module-only/crates/scp-ffi/napi/src/widgets.rs"
    );
    let fns = collect_defined_fns(FIXTURE);
    assert!(
        !fns.contains("widget_create"),
        "syn scanner leaked a fn defined inside #[cfg(test)] mod tests — \
         names collected: {fns:?}"
    );
    // Sanity: the non-test fn is still visible.
    assert!(
        fns.contains("widget_create_not_real"),
        "syn scanner failed to collect the non-test fn widget_create_not_real \
         — names collected: {fns:?}"
    );
}

/// Adversarial fn-hidden-in-test-impl fixture: asserts the Rust `syn` scanner
/// EXCLUDES a method defined inside `#[cfg(test)] impl Foo { ... }`. Real
/// instances of this pattern live at `crates/scp-ffi/napi/src/context.rs:296`
/// and `runtime.rs:347` — an adversary can declare a canonical alias as a
/// method name inside a test-only impl to satisfy a naive scanner. The guard
/// is `visit_item_impl` skipping the subtree when
/// `attrs_contain_cfg_test(&node.attrs)` is true.
///
/// Pair of the `bad-alias-in-test-impl` bash fixture — both scanners must
/// fail on the same source to prevent silent drift.
#[test]
fn syn_scanner_excludes_cfg_test_impl() {
    const FIXTURE: &str = include_str!(
        "../../../../scripts/tests/bridge-symmetry/fixtures/\
         bad-alias-in-test-impl/crates/scp-ffi/napi/src/widgets.rs"
    );
    let fns = collect_defined_fns(FIXTURE);
    assert!(
        !fns.contains("widget_create"),
        "syn scanner leaked a method defined inside #[cfg(test)] impl Context \
         — names collected: {fns:?}"
    );
    // Sanity: the non-test fn OUTSIDE the impl is still visible.
    assert!(
        fns.contains("widget_create_not_real"),
        "syn scanner failed to collect the non-test fn widget_create_not_real \
         — names collected: {fns:?}"
    );
}

/// Guards MAJOR-1 (cfg predicate semantics): a fn marked `#[cfg(not(test))]`
/// is production-only code and MUST be collected. A bare `test` token scan
/// that reported any mention of `test` as test-only would wrongly drop it.
#[test]
fn syn_scanner_keeps_cfg_not_test_fn() {
    const SRC: &str = r#"
        #[cfg(not(test))]
        pub fn should_be_kept() {}

        #[cfg(all(not(test), feature = "x"))]
        pub fn should_also_be_kept() {}
    "#;
    let fns = collect_defined_fns(SRC);
    assert!(
        fns.contains("should_be_kept"),
        "#[cfg(not(test))] fn was incorrectly excluded — collected: {fns:?}"
    );
    assert!(
        fns.contains("should_also_be_kept"),
        "#[cfg(all(not(test), ...))] fn was incorrectly excluded — \
         collected: {fns:?}"
    );
}

/// Guards MAJOR-2 (fn-level cfg(test)): a fn marked `#[cfg(test)]` inside a
/// non-test module must NOT be collected. Both `visit_item_fn` and
/// `visit_impl_item_fn` must consult the fn's own attrs.
#[test]
fn syn_scanner_excludes_cfg_test_fn_inside_non_test_module() {
    const SRC: &str = r"
        mod foo {
            #[cfg(test)]
            fn fake_canonical() {}

            pub fn production_fn() {}
        }

        struct Widget;
        impl Widget {
            #[cfg(test)]
            fn fake_method() {}

            pub fn real_method(&self) {}
        }
    ";
    let fns = collect_defined_fns(SRC);
    assert!(
        !fns.contains("fake_canonical"),
        "fn-level #[cfg(test)] in non-test module was not excluded — \
         collected: {fns:?}"
    );
    assert!(
        !fns.contains("fake_method"),
        "fn-level #[cfg(test)] on impl method was not excluded — \
         collected: {fns:?}"
    );
    assert!(
        fns.contains("production_fn"),
        "production fn was dropped — collected: {fns:?}"
    );
    assert!(
        fns.contains("real_method"),
        "impl method was dropped — collected: {fns:?}"
    );
}

/// Exercise `cfg(test)` and `all(test, ...)` — both are test-ONLY, so
/// the scanner must exclude them. `any(test, ...)` is tested below as a
/// production case (it has a production path via the other disjunct).
#[test]
fn syn_scanner_excludes_test_only_cfgs() {
    const SRC: &str = r#"
        #[cfg(test)]
        fn a() {}

        #[cfg(all(test, feature = "x"))]
        fn c() {}
    "#;
    let fns = collect_defined_fns(SRC);
    for name in ["a", "c"] {
        assert!(
            !fns.contains(name),
            "fn `{name}` gated on test should have been excluded — \
             collected: {fns:?}"
        );
    }
}

/// `#[cfg(any(test, feature = "x"))]` compiles when `test OR feature
/// = "x"`. With `feature = "x"` enabled and `test` off, the item is
/// reachable in production — so the scanner MUST keep it in the
/// collected set (it is a production definition, not a test-only one).
/// The old walker misclassified this as test-gated; ADR-046 MINOR-1
/// rev split `all(...)` and `any(...)` folds to fix it.
#[test]
fn syn_scanner_includes_any_with_test_and_feature() {
    const SRC: &str = r#"
        #[cfg(any(test, feature = "x"))]
        fn b() {}
    "#;
    let fns = collect_defined_fns(SRC);
    assert!(
        fns.contains("b"),
        "fn `b` under `any(test, feature=...)` has a production path \
         and must be collected — collected: {fns:?}"
    );
}

/// `#[cfg_attr(test, …)]` is conditional-attribute propagation, NOT a
/// compile-time gate on the item itself. `cfg_attr(test, deprecated)`
/// expands to `#[deprecated]` when `test` is on and to nothing when
/// it's off — either way, the fn is compiled in production. The
/// walker must treat the fn as production-reachable and keep it in
/// the collected set. Review round 12 flagged this as a coverage gap
/// (the walker handled it correctly per ADR-046, but no fixture
/// proved it). This test locks the behaviour.
#[test]
fn syn_scanner_includes_fn_with_cfg_attr_test() {
    const SRC: &str = r#"
        #[cfg_attr(test, deprecated = "use bar")]
        fn foo() {}

        #[cfg_attr(test, allow(dead_code), deprecated)]
        #[cfg_attr(not(test), inline)]
        fn bar() {}
    "#;
    let fns = collect_defined_fns(SRC);
    for name in ["foo", "bar"] {
        assert!(
            fns.contains(name),
            "fn `{name}` carries `cfg_attr(test, …)` which is attribute \
             propagation, not a gate — the fn is compiled in production \
             and must be collected; collected: {fns:?}"
        );
    }
}

/// Negative case: `#[cfg(test)]` stacked ABOVE `#[cfg_attr(test, …)]`
/// is still a real test-only gate. The `cfg_attr` underneath is irrelevant
/// because the outer `cfg(test)` already excludes the fn from production.
#[test]
fn syn_scanner_excludes_cfg_test_above_cfg_attr() {
    const SRC: &str = "
        #[cfg(test)]
        #[cfg_attr(test, allow(dead_code))]
        fn test_only_fn() {}
    ";
    let fns = collect_defined_fns(SRC);
    assert!(
        !fns.contains("test_only_fn"),
        "fn `test_only_fn` under `cfg(test)` + `cfg_attr(test, …)` is \
         test-only and must be excluded; collected: {fns:?}"
    );
}

// ---------------------------------------------------------------------------
// Strict-scanner adversarial tests — guard against phantom aliases that
// resolve to UNDECORATED fns (no FFI macro on either the fn or its enclosing
// impl). The `every_alias_resolves_to_a_real_fn_or_exemption` test relies on
// `collect_ffi_exported_fns` via the `fns_of_source` cache; these tests
// exercise that scanner directly so a future weakening is caught at the
// fixture level instead of as a coverage anomaly nobody investigates.
// ---------------------------------------------------------------------------

/// Free fn with no FFI macro must NOT be FFI-resolvable, even if `pub`.
/// An attacker could declare `"napi": ["ghost_op"]` in `bridge-aliases.json`
/// and define `pub fn ghost_op() {}` in `crates/scp-ffi/napi/src/` — the
/// looser scanner would happily report the alias as resolved. The strict
/// scanner refuses because the binding tool (napi-rs) never sees an
/// undecorated fn.
#[test]
fn ffi_scanner_excludes_undecorated_pub_fn() {
    const SRC: &str = r"
        pub fn ghost_op() {}
        pub(crate) fn another_ghost() {}
        fn naked_ghost() {}
    ";
    let fns = collect_ffi_exported_fns(SRC);
    for name in ["ghost_op", "another_ghost", "naked_ghost"] {
        assert!(
            !fns.contains(name),
            "fn `{name}` has no FFI macro and must NOT be FFI-resolvable — \
             collected: {fns:?}"
        );
    }
}

/// Method inside an undecorated `impl` block must NOT be FFI-resolvable,
/// even with `pub` visibility. The phantom-alias adversary can otherwise
/// add a method whose name matches the canonical alias, satisfying a naive
/// scanner. The strict scanner requires the impl block to carry one of the
/// FFI binding macros.
#[test]
fn ffi_scanner_excludes_method_in_undecorated_impl() {
    const SRC: &str = r"
        struct PyScp;
        impl PyScp {
            pub fn ghost_method(&self) {}
        }
    ";
    let fns = collect_ffi_exported_fns(SRC);
    assert!(
        !fns.contains("ghost_method"),
        "method inside undecorated impl block must not be FFI-resolvable — \
         collected: {fns:?}"
    );
}

/// Positive cases: the strict scanner MUST recognize every form of FFI
/// decoration the SCP bridges actually use. If this test fails, the
/// `attrs_have_*_ffi_export` allow-lists are too narrow and may have stopped
/// detecting a real export pattern that landed in the codebase.
#[test]
fn ffi_scanner_recognizes_all_bridge_macros() {
    const SRC: &str = r#"
        // PyO3 free fn — no `pub` (real pattern in lib.rs)
        #[pyfunction]
        fn py_free_fn() {}

        // PyO3 free fn — with `pub`
        #[pyfunction]
        pub fn py_free_fn_pub() {}

        // PyO3 impl — pymethods
        struct PyScp;
        #[pymethods]
        impl PyScp {
            pub fn py_method(&self) {}
        }

        // NAPI free fn
        #[napi]
        pub fn napi_free_fn() {}

        // NAPI free fn with args
        #[napi(js_name = "napiNamed")]
        pub fn napi_named_fn() {}

        // NAPI impl
        struct NapiScp;
        #[napi]
        impl NapiScp {
            pub fn napi_method(&self) {}
        }

        // UniFFI free fn
        #[uniffi::export]
        pub fn uniffi_free_fn() {}

        // UniFFI free fn with args
        #[uniffi::export(async_runtime = "tokio")]
        pub async fn uniffi_async_fn() {}

        // UniFFI impl
        struct UniffiScp;
        #[uniffi::export]
        impl UniffiScp {
            pub fn uniffi_method(&self) {}
        }

        // WASM free fn
        #[wasm_bindgen]
        pub fn wasm_free_fn() {}

        // WASM free fn with args
        #[wasm_bindgen(js_name = "wasmNamed")]
        pub fn wasm_named_fn() {}

        // WASM impl
        struct WasmScp;
        #[wasm_bindgen]
        impl WasmScp {
            pub fn wasm_method(&self) {}
        }
    "#;
    let fns = collect_ffi_exported_fns(SRC);
    let expected = [
        "py_free_fn",
        "py_free_fn_pub",
        "py_method",
        "napi_free_fn",
        "napi_named_fn",
        "napi_method",
        "uniffi_free_fn",
        "uniffi_async_fn",
        "uniffi_method",
        "wasm_free_fn",
        "wasm_named_fn",
        "wasm_method",
    ];
    for name in expected {
        assert!(
            fns.contains(name),
            "FFI scanner failed to detect `{name}` — at least one bridge \
             macro form is no longer recognized. Collected: {fns:?}"
        );
    }
}

/// Reads the fixture file added in this PR which deliberately defines a
/// `pub(crate) fn ghost_op` (no FFI macro) AND a regular `pub fn` named
/// `widget_create_not_real` (also no macro). Neither must be FFI-resolvable.
/// Pair of the `bad-alias-undecorated-fn` bash fixture — both scanners must
/// fail on the same source to keep them in lockstep.
#[test]
fn ffi_scanner_rejects_undecorated_fixture() {
    const FIXTURE: &str = include_str!(
        "../../../../scripts/tests/bridge-symmetry/fixtures/\
         bad-alias-undecorated-fn/crates/scp-ffi/napi/src/widgets.rs"
    );
    let fns = collect_ffi_exported_fns(FIXTURE);
    assert!(
        !fns.contains("ghost_op"),
        "`pub(crate) fn ghost_op` (no FFI macro) was accepted by the strict \
         scanner — this is the phantom-alias hole the strict scanner closes. \
         Collected: {fns:?}"
    );
    assert!(
        !fns.contains("widget_create_not_real"),
        "undecorated `pub fn widget_create_not_real` was accepted by the \
         strict scanner. Collected: {fns:?}"
    );
}

// ---------------------------------------------------------------------------
// PR-E #28: Mechanize ADR-048 §1 — pure protocol helpers stay free fns at the
// FFI Rust layer.
//
// Background. ADR-048 §1 says: "pure protocol helpers stay free fns at FFI
// Rust layer". The rule exists because a helper that takes `&self` but never
// reads from the receiver is structurally bound to an instance for no reason:
// it forces a `SCP` constructor call to invoke a pure validator, and it
// inflates the FFI binding surface for every language wrapper that has to
// generate per-instance method bindings instead of free-function bindings.
//
// Before PR-E this rule lived only in review. This test mechanizes it: scan
// every `crates/scp-ffi/{src,napi/src,uniffi/src,wasm/src}/**/*.rs` impl
// block; for each `&self` (or `&mut self` / `self`) method, walk the body
// and the non-receiver signature parts. If the method body, its non-receiver
// args, return type, generics, and where-clause never reference `self` or
// `Self` (as an `Expr::Path`, `Type::Path`, `Pat::Path`, or `Pat::Struct`),
// it is a pure helper bound to a receiver — flag.
//
// False-positive escape hatch. `scripts/pure-helpers-allowlist.txt` lists
// (file-relative, fn-name) exemptions one per line, `#`-prefixed comments
// allowed. Empty by default; exemptions are rare and require a documented
// reason. The list is path-qualified to prevent a fn name in one bridge
// from accidentally exempting a same-named fn in another bridge.
//
// Tests:
//   * `pure_helpers_stay_free_fns_at_ffi_layer` — the production gate, scans
//     all four bridges. Default policy: fail on any flagged method.
//   * `pure_helpers_detector_recognizes_genuinely_bound_method` — positive
//     test against a `self.field` example. Locks the detector.
//   * `pure_helpers_detector_flags_genuinely_pure_method` — negative test
//     against a `&self` method that never reads the receiver. Locks the
//     detector against false negatives.
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};

/// Walks a directory recursively and yields every `.rs` file. No filtering
/// of test files or generated code at this layer — the caller decides via
/// the `#[cfg(test)]` skip inside the impl visitor.
fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Returns the workspace root computed from `CARGO_MANIFEST_DIR`.
/// `scp-testing`'s manifest lives at `<workspace>/crates/scp-testing`, so the
/// workspace root is two parents up. This is the same convention used by the
/// other crate-root path computations in the SCP codebase.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Returns the absolute paths of the four FFI bridge source roots that
/// ADR-048 §1 governs. `crates/scp-ffi/common/src/` is intentionally not
/// included: it hosts shared bridge plumbing (BridgeInstance, validators),
/// not bridge-exported surface, and its impl methods serve a different role
/// (trait impls for cross-bridge composability) where the §1 rule does not
/// straightforwardly apply.
fn ffi_bridge_roots() -> Vec<PathBuf> {
    let root = workspace_root();
    vec![
        root.join("crates/scp-ffi/src"),
        root.join("crates/scp-ffi/napi/src"),
        root.join("crates/scp-ffi/uniffi/src"),
        root.join("crates/scp-ffi/wasm/src"),
    ]
}

/// Loads `scripts/pure-helpers-allowlist.txt`. Each non-empty, non-`#` line
/// is a workspace-relative path followed by `::` followed by the fn name —
/// e.g. `crates/scp-ffi/src/runtime.rs::with_state`. The path qualifier is
/// required: a fn name alone could match across bridges and exempt code the
/// authors did not intend.
fn load_pure_helpers_allowlist() -> HashSet<String> {
    let path = workspace_root().join("scripts/pure-helpers-allowlist.txt");
    let mut out = HashSet::new();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return out;
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.insert(line.to_owned());
    }
    out
}

/// Returns true if the receiver is `&self`, `&mut self`, `self`, or
/// `self: Self`. All forms bind the method to an instance, all are subject
/// to the §1 rule.
fn impl_method_has_self_receiver(method: &syn::ImplItemFn) -> bool {
    method
        .sig
        .inputs
        .first()
        .is_some_and(|arg| matches!(arg, syn::FnArg::Receiver(_)))
}

/// Returns true if any part of `method`'s body, non-receiver signature,
/// return type, generics, or where-clause references the identifier `self`
/// or `Self`. Receiver-only references (e.g. `&self` in the signature
/// itself) do NOT count — every &self method has those by definition. Only
/// USES of the receiver count as binding.
fn method_uses_self_outside_receiver(method: &syn::ImplItemFn) -> bool {
    let mut scanner = SelfRefScanner { found: false };

    syn::visit::Visit::visit_block(&mut scanner, &method.block);
    if scanner.found {
        return true;
    }

    for arg in method.sig.inputs.iter().skip(1) {
        if let syn::FnArg::Typed(pt) = arg {
            syn::visit::Visit::visit_type(&mut scanner, &pt.ty);
            if scanner.found {
                return true;
            }
        }
    }
    if let syn::ReturnType::Type(_, ty) = &method.sig.output {
        syn::visit::Visit::visit_type(&mut scanner, ty);
        if scanner.found {
            return true;
        }
    }
    syn::visit::Visit::visit_generics(&mut scanner, &method.sig.generics);
    scanner.found
}

struct SelfRefScanner {
    found: bool,
}

fn path_starts_with_self_or_self_kw(path: &syn::Path) -> bool {
    path.segments
        .first()
        .is_some_and(|seg| seg.ident == "self" || seg.ident == "Self")
}

impl<'ast> syn::visit::Visit<'ast> for SelfRefScanner {
    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if path_starts_with_self_or_self_kw(&p.path) {
            self.found = true;
        }
        syn::visit::visit_expr_path(self, p);
    }
    fn visit_type_path(&mut self, t: &'ast syn::TypePath) {
        if path_starts_with_self_or_self_kw(&t.path) {
            self.found = true;
        }
        syn::visit::visit_type_path(self, t);
    }
    /// Catches `Pat::Path(PatPath { path: Self, ... })` and
    /// `Pat::Struct(PatStruct { path: Self, ... })` uniformly. `syn::visit`
    /// has dedicated `visit_pat_struct` / `visit_pat_tuple_struct` overrides
    /// but not a separate `visit_pat_path`, so we match on the enum here and
    /// fall through to the default visitor so nested patterns still recurse.
    fn visit_pat(&mut self, p: &'ast syn::Pat) {
        match p {
            syn::Pat::Path(pp) if path_starts_with_self_or_self_kw(&pp.path) => {
                self.found = true;
            }
            syn::Pat::Struct(ps) if path_starts_with_self_or_self_kw(&ps.path) => {
                self.found = true;
            }
            syn::Pat::TupleStruct(pts) if path_starts_with_self_or_self_kw(&pts.path) => {
                self.found = true;
            }
            _ => {}
        }
        syn::visit::visit_pat(self, p);
    }
    /// Macros (`format!`, `println!`, `bail!`, `tracing::error!`, `vec!`,
    /// …) carry an unparsed `TokenStream`. `syn::visit` does NOT descend into
    /// macro tokens — they were not parsed as expressions, so the AST has
    /// no expression nodes to visit. Without this override, a method like
    /// `fn __repr__(&self) -> String { format!("X({})", self.field) }` would
    /// look bound-free to the scanner because `self.field` lives inside the
    /// macro's opaque tokens. Walk the token stream byte-by-byte looking
    /// for the `self` / `Self` identifier — sufficient because both are
    /// keywords and cannot appear as unrelated substrings.
    ///
    /// **Known limitation — identifier-splitting macros.** Macros that
    /// CONSTRUCT the `self` / `Self` ident from sub-tokens evade this
    /// walker: `paste::paste!([<se lf>])`, `concat_idents!(se, lf)` (nightly),
    /// custom proc-macros that emit `Ident::new("self", ...)` programmatically.
    /// Any such macro inside the body would let an undecorated method pass
    /// even though it never reads from the receiver. SCP bridge code does
    /// not currently use these macros; if you reach for one in a `&self`
    /// method, prefer making the method a free fn (per ADR-048 §1) over
    /// rebinding the scanner's blindspot. Strengthening this scanner to
    /// expand recognised expression macros and reject everything else is
    /// tracked as a future hardening if the codebase ever adopts a macro
    /// in this shape.
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if tokens_have_self_or_self_kw(m.tokens.clone()) {
            self.found = true;
        }
        syn::visit::visit_macro(self, m);
    }
}

/// Walks a `proc_macro2::TokenStream` recursively looking for the identifier
/// `self` or `Self`. Used by the macro-body fallback in `SelfRefScanner`.
/// proc_macro2 is a transitive dep of syn so no extra Cargo entry is needed.
fn tokens_have_self_or_self_kw(stream: proc_macro2::TokenStream) -> bool {
    for tree in stream {
        match tree {
            proc_macro2::TokenTree::Ident(ident) => {
                let s = ident.to_string();
                if s == "self" || s == "Self" {
                    return true;
                }
            }
            proc_macro2::TokenTree::Group(group) if tokens_have_self_or_self_kw(group.stream()) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

#[derive(Debug)]
struct PureHelperViolation {
    file_rel: String,
    method_name: String,
}

/// Walks all FFI bridge sources and collects every impl method that has
/// a `self` receiver but never references `self` / `Self` in its body,
/// non-receiver signature parts, or generics. These are pure helpers
/// wrongly bound to an instance — ADR-048 §1 mandates they be free fns.
fn scan_pure_helpers() -> Vec<PureHelperViolation> {
    let workspace = workspace_root();
    let allowlist = load_pure_helpers_allowlist();
    let mut violations = Vec::new();

    for bridge_root in ffi_bridge_roots() {
        let mut files = Vec::new();
        collect_rs_files(&bridge_root, &mut files);
        for file_path in files {
            let Ok(src) = std::fs::read_to_string(&file_path) else {
                continue;
            };
            let parsed = match syn::parse_file(&src) {
                Ok(f) => f,
                Err(err) => panic!(
                    "pure-helpers scanner: syn parse failed for \
                     {} — {err}",
                    file_path.display()
                ),
            };
            let rel = file_path
                .strip_prefix(&workspace)
                .unwrap_or(&file_path)
                .to_string_lossy()
                .replace('\\', "/");
            scan_items_for_pure_helpers(&parsed.items, &rel, &allowlist, &mut violations);
        }
    }
    violations
}

/// Recursive worker for [`scan_pure_helpers`]. Flags pure-helper §1 violations
/// in FFI-exported inherent impls and DESCENDS INTO inline `mod { … }` blocks,
/// so a decorated impl nested in a module is not missed. The module recursion
/// matches the strict alias scanner's `visit_item_mod`, keeping the two
/// scanners' reachability identical.
fn scan_items_for_pure_helpers(
    items: &[syn::Item],
    rel: &str,
    allowlist: &HashSet<String>,
    out: &mut Vec<PureHelperViolation>,
) {
    for item in items {
        match item {
            // Recurse into inline modules (skipping `#[cfg(test)] mod`). The
            // alias scanner descends here too; not doing so would let a
            // decorated impl inside `mod foo { … }` evade the §1 gate.
            syn::Item::Mod(item_mod) => {
                if attrs_contain_cfg_test(&item_mod.attrs) {
                    continue;
                }
                if let Some((_, inner)) = &item_mod.content {
                    scan_items_for_pure_helpers(inner, rel, allowlist, out);
                }
            }
            syn::Item::Impl(item_impl) => {
                if attrs_contain_cfg_test(&item_impl.attrs) {
                    continue;
                }
                // Trait impls (`impl Trait for Type`) are out of scope: the
                // trait dictates the signature, not the FFI author.
                // `Drop::drop(&mut self)`, `Display::fmt(&self, …)`, and the
                // bridge-adapter traits (`BridgeDidResolver`,
                // `BridgeNonceTracker`, `ContextProvider`, …) all require
                // `self`-shaped methods even when the impl body delegates to a
                // free fn. ADR-048 §1 is about INHERENT impls that the binding
                // tooling actually exports as methods on the language-level SCP
                // class — those are what the test catches when an author binds
                // a pure validator to the receiver.
                if item_impl.trait_.is_some() {
                    continue;
                }
                // §1 applies to methods the FFI binding tooling actually
                // EXPORTS. A method is exported when the impl block carries the
                // macro (`#[pymethods]` / `#[napi]` / `#[uniffi::export]` /
                // `#[wasm_bindgen]` — the dominant pattern) OR the method itself
                // carries it (rare but legal — e.g. an individual
                // `#[uniffi::export]` / `#[napi]` method inside an
                // otherwise-undecorated impl). A method in a FULLY undecorated
                // impl produces no export, so "should this be a free fn?" is
                // internal coding style, not an enforcement matter — real
                // instance: `impl WasmContextManager { ... }` hosts internal
                // helpers called from `#[wasm_bindgen] pub fn context_*` free
                // fns, not exposed as JS methods. This mirrors the strict alias
                // scanner's `visit_impl_item_fn` exactly (block-decorated OR
                // fn-decorated), closing the gap where a pure `&self` helper
                // decorated per-method in an undecorated impl would evade the
                // gate while still counting as an export.
                let impl_decorated = attrs_have_impl_block_ffi_export(&item_impl.attrs);
                for impl_item in &item_impl.items {
                    let syn::ImplItem::Fn(method) = impl_item else {
                        continue;
                    };
                    if attrs_contain_cfg_test(&method.attrs) {
                        continue;
                    }
                    let fn_decorated = attrs_have_free_fn_ffi_export(&method.attrs);
                    if !impl_decorated && !fn_decorated {
                        continue;
                    }
                    if !impl_method_has_self_receiver(method) {
                        continue;
                    }
                    if method_uses_self_outside_receiver(method) {
                        continue;
                    }
                    let name = method.sig.ident.to_string();
                    let key = format!("{rel}::{name}");
                    if allowlist.contains(&key) {
                        continue;
                    }
                    out.push(PureHelperViolation {
                        file_rel: rel.to_owned(),
                        method_name: name,
                    });
                }
            }
            _ => {}
        }
    }
}

#[test]
fn pure_helpers_stay_free_fns_at_ffi_layer() {
    let violations = scan_pure_helpers();
    assert!(
        violations.is_empty(),
        "ADR-048 §1 violation: {} impl method(s) take `self` but never use \
         it. Move them to free fns, or add an exemption to \
         scripts/pure-helpers-allowlist.txt with a documented reason:\n{}",
        violations.len(),
        violations
            .iter()
            .map(|v| format!("  {}::{}", v.file_rel, v.method_name))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Positive case: a method that reads `self.inner` IS a genuinely bound
/// method and the detector must NOT flag it. Locks the detector against
/// false positives that would force real methods to be moved to free fns.
#[test]
fn pure_helpers_detector_recognizes_genuinely_bound_method() {
    let src = "
        struct PyScp { inner: Inner }
        impl PyScp {
            pub fn helper(&self, x: u32) -> u32 {
                self.inner.value + x
            }
        }
    ";
    let parsed = syn::parse_file(src).unwrap();
    let item_impl = parsed
        .items
        .iter()
        .find_map(|it| match it {
            syn::Item::Impl(ii) => Some(ii),
            _ => None,
        })
        .unwrap();
    let method = item_impl
        .items
        .iter()
        .find_map(|ii| match ii {
            syn::ImplItem::Fn(f) => Some(f),
            _ => None,
        })
        .unwrap();
    assert!(impl_method_has_self_receiver(method));
    assert!(
        method_uses_self_outside_receiver(method),
        "detector failed to recognize `self.inner.value` as a self reference"
    );
}

/// Negative case: a `&self` method whose body never touches `self` IS a
/// pure helper and the detector MUST flag it. Locks the detector against
/// false negatives that would let new violations slip in.
#[test]
fn pure_helpers_detector_flags_genuinely_pure_method() {
    let src = "
        struct PyScp;
        impl PyScp {
            pub fn pure_validator(&self, input: &str) -> bool {
                !input.is_empty() && input.len() < 1024
            }
        }
    ";
    let parsed = syn::parse_file(src).unwrap();
    let item_impl = parsed
        .items
        .iter()
        .find_map(|it| match it {
            syn::Item::Impl(ii) => Some(ii),
            _ => None,
        })
        .unwrap();
    let method = item_impl
        .items
        .iter()
        .find_map(|ii| match ii {
            syn::ImplItem::Fn(f) => Some(f),
            _ => None,
        })
        .unwrap();
    assert!(impl_method_has_self_receiver(method));
    assert!(
        !method_uses_self_outside_receiver(method),
        "detector wrongly flagged a method that never uses `self` as bound"
    );
}

/// F4 escape-hatch closure: a pure `&self` method individually decorated with
/// an FFI macro inside an OTHERWISE-UNDECORATED impl is still an export, so it
/// must be subject to §1. The scanner's gate is `impl_decorated || fn_decorated`
/// (mirroring the strict alias scanner) — this test locks that an undecorated
/// impl block does NOT short-circuit when the method itself carries the macro.
#[test]
fn pure_helpers_scanner_descends_into_per_method_decorated_undecorated_impl() {
    let src = "
        struct Scp;
        impl Scp {
            #[uniffi::export]
            pub fn pure_validator(&self, input: &str) -> bool {
                !input.is_empty()
            }
        }
    ";
    let parsed = syn::parse_file(src).unwrap();
    let item_impl = parsed
        .items
        .iter()
        .find_map(|it| match it {
            syn::Item::Impl(ii) => Some(ii),
            _ => None,
        })
        .unwrap();
    let method = item_impl
        .items
        .iter()
        .find_map(|ii| match ii {
            syn::ImplItem::Fn(f) => Some(f),
            _ => None,
        })
        .unwrap();
    // The scanner's in-scope gate is `impl_decorated || fn_decorated`. Here the
    // block is UNDECORATED, so the `fn_decorated` operand is the one that must
    // carry the method into §1 scope — that is the gap this closes.
    assert!(
        !attrs_have_impl_block_ffi_export(&item_impl.attrs),
        "impl block must be undecorated for this test to exercise the gap"
    );
    assert!(
        attrs_have_free_fn_ffi_export(&method.attrs),
        "per-method FFI decoration must bring the method into §1 scope even \
         when the impl block is undecorated"
    );
    // And it is a genuine pure-helper violation that must be flagged.
    assert!(impl_method_has_self_receiver(method));
    assert!(!method_uses_self_outside_receiver(method));
}

/// The pure-helpers scanner must DESCEND into inline `mod { … }` blocks, just
/// like the strict alias scanner's `visit_item_mod`. A pure `&self` helper in a
/// decorated impl nested in a module would otherwise evade §1 while still being
/// an export. Drives `scan_items_for_pure_helpers` directly on parsed source.
#[test]
fn pure_helpers_scanner_recurses_into_inline_modules() {
    let src = "
        mod inner {
            struct Scp;
            #[uniffi::export]
            impl Scp {
                pub fn pure_validator(&self, input: &str) -> bool {
                    !input.is_empty()
                }
            }
        }
    ";
    let parsed = syn::parse_file(src).unwrap();
    let allowlist: HashSet<String> = HashSet::new();
    let mut out: Vec<PureHelperViolation> = Vec::new();
    scan_items_for_pure_helpers(&parsed.items, "test.rs", &allowlist, &mut out);
    assert_eq!(
        out.len(),
        1,
        "a decorated impl nested in `mod` must be scanned (module recursion)"
    );
    assert_eq!(out[0].method_name, "pure_validator");
}

/// Locks the false-positive guards from ADR-048 §1: methods that use
/// `Self::CONST`, `let Self { ... } = ...`, `<Self ...>` (turbofish),
/// `: Self` (type position), or `-> Self` (return type) are valid even
/// without explicit `self.<field>` reads. Each is a genuine binding to
/// the impl block's `Self` type. The detector must accept all of them.
#[test]
fn pure_helpers_detector_accepts_self_type_references() {
    let cases = [
        // Self:: in body
        "struct S; impl S { fn f(&self) -> u32 { Self::CONST } }",
        // let Self { .. } in body
        "struct S { x: u32 } impl S { fn f(&self) { let Self { x } = self; let _ = x; } }",
        // : Self in arg position
        "struct S; impl S { fn f(&self, _other: &Self) {} }",
        // -> Self in return position
        "struct S; impl S { fn f(&self) -> Self { Self } }",
        // <Self ...> turbofish
        "struct S; impl S { fn f(&self) -> Vec<Self> { Vec::<Self>::new() } }",
    ];
    for src in cases {
        let parsed = syn::parse_file(src).unwrap();
        let item_impl = parsed
            .items
            .iter()
            .find_map(|it| match it {
                syn::Item::Impl(ii) => Some(ii),
                _ => None,
            })
            .unwrap();
        let method = item_impl
            .items
            .iter()
            .find_map(|ii| match ii {
                syn::ImplItem::Fn(f) => Some(f),
                _ => None,
            })
            .unwrap();
        assert!(
            method_uses_self_outside_receiver(method),
            "detector failed to recognize Self-type reference in: {src}"
        );
    }
}

// ===========================================================================
// F2: Reverse-coverage — every exported FFI fn is registered or allowlisted
//
// The forward tests (`*_bridge_covers_core_operations`) ask: "is every
// canonical operation in bridge-aliases.json backed by a real exported fn?"
// They are blind in the OTHER direction: a bridge can export a function that
// no canonical operation references at all. If that function is genuinely a
// cross-bridge parity op (it exists in the other bridges too) but simply
// never got an alias entry, the forward tests stay green while the operation
// silently lacks parity tracking. That is exactly how an unregistered op can
// hide — e.g. an op exported in all four bridges but absent from the alias
// table is invisible to every forward gate.
//
// This reverse gate enumerates EVERY exported fn under each bridge crate's
// `src/` (via a real filesystem walk + the strict `syn` scanner — NOT the
// curated `*_sources()` include lists, which are themselves incomplete) and
// requires each name to be either:
//   • registered  — appears as a Rust name for some canonical op in
//     bridge-aliases.json under that bridge, OR
//   • allowed      — listed in scripts/ffi-export-allowlist.json as a
//     legitimately-non-parity export (getter, lifecycle, dunder, etc.), OR
//   • pending      — listed in the allowlist's pending_registration block as
//     a known-unregistered cross-bridge parity op awaiting an alias entry.
//
// `leaked = exported − registered − allowed − pending`. A non-empty `leaked`
// set is a finding: a brand-new export that is neither tracked for parity nor
// justified as non-parity.
// ===========================================================================

const FFI_EXPORT_ALLOWLIST_JSON: &str =
    include_str!("../../../../scripts/ffi-export-allowlist.json");

#[derive(Debug, Deserialize)]
struct FfiExportAllowlistFile {
    #[serde(default)]
    pyo3: Vec<AllowlistEntry>,
    #[serde(default)]
    uniffi: Vec<AllowlistEntry>,
    #[serde(default)]
    napi: Vec<AllowlistEntry>,
    #[serde(default)]
    wasm: Vec<AllowlistEntry>,
    #[serde(default)]
    pending_registration: PendingRegistration,
}

#[derive(Debug, Default, Deserialize)]
struct PendingRegistration {
    #[serde(default)]
    pyo3: Vec<AllowlistEntry>,
    #[serde(default)]
    uniffi: Vec<AllowlistEntry>,
    #[serde(default)]
    napi: Vec<AllowlistEntry>,
    #[serde(default)]
    wasm: Vec<AllowlistEntry>,
}

#[derive(Debug, Deserialize)]
struct AllowlistEntry {
    name: String,
    /// Workspace-relative path of the source file that defines this exported
    /// fn, e.g. `crates/scp-ffi/src/identity.rs`. The qualified key
    /// `<path>::<name>` is what the reverse gate matches on — mirroring the
    /// `path::fn` discipline of `scripts/pure-helpers-allowlist.txt`. A bare
    /// `name` match would silently exempt ANY future export sharing the name
    /// (e.g. a genuine op named `tools`, which collides with the `tools`
    /// getter), recreating the hide-by-omission class this gate exists to kill.
    path: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    reason: String,
}

impl AllowlistEntry {
    /// The `<workspace-relative-path>::<name>` qualified key, matching the
    /// convention in `scripts/pure-helpers-allowlist.txt`.
    fn qualified_key(&self) -> String {
        format!("{}::{}", self.path, self.name)
    }
}

fn ffi_export_allowlist() -> &'static FfiExportAllowlistFile {
    static CELL: OnceLock<FfiExportAllowlistFile> = OnceLock::new();
    CELL.get_or_init(|| {
        serde_json::from_str(FFI_EXPORT_ALLOWLIST_JSON)
            .expect("scripts/ffi-export-allowlist.json is valid JSON")
    })
}

/// The four bridges, paired with the `src/` root each one's exports live under
/// and the closure that selects that bridge's Rust names from an alias op.
/// Order mirrors `ffi_bridge_roots()`.
fn bridge_export_targets() -> Vec<(&'static str, PathBuf)> {
    let root = workspace_root();
    vec![
        ("pyo3", root.join("crates/scp-ffi/src")),
        ("uniffi", root.join("crates/scp-ffi/uniffi/src")),
        ("napi", root.join("crates/scp-ffi/napi/src")),
        ("wasm", root.join("crates/scp-ffi/wasm/src")),
    ]
}

/// The set of Rust fn names a given bridge is expected to export because a
/// canonical operation in `bridge-aliases.json` names them. This is the
/// "registered" set the reverse gate measures exported fns against.
fn registered_names_for(bridge: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, canonical, _) in parity_operations() {
        let names: &[String] = match bridge {
            "pyo3" => pyo3_names(canonical),
            "uniffi" => uniffi_names(canonical),
            "napi" => napi_names(canonical),
            "wasm" => wasm_names(canonical),
            other => panic!("registered_names_for: unknown bridge '{other}'"),
        };
        for n in names {
            out.insert(n.clone());
        }
    }
    out
}

/// Per-bridge entries from the allowlist's per-bridge arrays.
fn per_bridge_entries(bridge: &str) -> &'static [AllowlistEntry] {
    let file = ffi_export_allowlist();
    match bridge {
        "pyo3" => &file.pyo3,
        "uniffi" => &file.uniffi,
        "napi" => &file.napi,
        "wasm" => &file.wasm,
        other => panic!("per_bridge_entries: unknown bridge '{other}'"),
    }
}

/// Per-bridge entries from the allowlist's `pending_registration` block.
fn pending_entries(bridge: &str) -> &'static [AllowlistEntry] {
    let file = ffi_export_allowlist();
    match bridge {
        "pyo3" => &file.pending_registration.pyo3,
        "uniffi" => &file.pending_registration.uniffi,
        "napi" => &file.pending_registration.napi,
        "wasm" => &file.pending_registration.wasm,
        other => panic!("pending_entries: unknown bridge '{other}'"),
    }
}

/// Allowlist QUALIFIED keys (`<path>::<name>`, the legitimately-non-parity
/// exports) for a bridge. Path-qualified per Finding 1: an entry exempts only
/// the specific fn in the specific file it was written for.
fn allowed_keys_for(bridge: &str) -> BTreeSet<String> {
    per_bridge_entries(bridge)
        .iter()
        .map(AllowlistEntry::qualified_key)
        .collect()
}

/// Pending-registration QUALIFIED keys (known-unregistered cross-bridge parity
/// ops awaiting an alias entry) for a bridge.
fn pending_keys_for(bridge: &str) -> BTreeSet<String> {
    pending_entries(bridge)
        .iter()
        .map(AllowlistEntry::qualified_key)
        .collect()
}

/// Every exported fn under a bridge crate's `src/`, as `<path>::<name>`
/// qualified keys, via a filesystem walk and the strict `syn` scanner. `path`
/// is workspace-relative (e.g. `crates/scp-ffi/src/identity.rs`) so the key
/// matches the `path::fn` discipline of `scripts/pure-helpers-allowlist.txt`
/// and the `path`+`name` pair an allowlist entry carries. Reads each `*.rs`
/// file fresh (these are NOT the `include_str!`-interned `*_sources()` lists,
/// which are incomplete — the walk is authoritative).
///
/// Qualification is what closes the bypass a reviewer proved: a bare-name
/// allowlist (`tools` as a getter) would silently swallow a genuinely-new op
/// that happens to share the name but lives in a different file. Keyed on the
/// full path, an entry exempts ONLY the specific fn it was written for.
fn exported_qualified_under(root: &Path) -> BTreeSet<String> {
    let ws = workspace_root();
    let mut files = Vec::new();
    collect_rs_files(root, &mut files);
    let mut out = BTreeSet::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(&ws)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for name in collect_ffi_exported_fns(&text) {
            out.insert(format!("{rel}::{name}"));
        }
    }
    out
}

/// Reverse-coverage gate. See the section header above for the full rationale.
#[test]
fn every_exported_ffi_fn_is_registered_or_allowlisted() {
    let mut all_leaks: Vec<String> = Vec::new();
    for (bridge, root) in bridge_export_targets() {
        let exported = exported_qualified_under(&root);
        // `registered` is keyed on the BARE Rust name a canonical op resolves
        // to (alias entries are path-agnostic): an op registered in
        // bridge-aliases.json is covered wherever the bridge defines it.
        let registered = registered_names_for(bridge);
        // `allowed` / `pending` are keyed on the QUALIFIED `<path>::<name>` key
        // so an allowlist entry exempts ONLY the specific fn in its file.
        let allowed = allowed_keys_for(bridge);
        let pending = pending_keys_for(bridge);

        let leaked: Vec<&String> = exported
            .iter()
            .filter(|qualified| {
                let name = qualified
                    .rsplit_once("::")
                    .map_or(qualified.as_str(), |(_, n)| n);
                !registered.contains(name)
                    && !allowed.contains(*qualified)
                    && !pending.contains(*qualified)
            })
            .collect();

        if !leaked.is_empty() {
            eprintln!("{bridge}: {} leaked export(s): {leaked:?}", leaked.len());
            for q in leaked {
                all_leaks.push(format!("{bridge}::{q}"));
            }
        }
    }

    assert!(
        all_leaks.is_empty(),
        "{} FFI export(s) are neither registered as a parity operation in \
         scripts/bridge-aliases.json nor justified in \
         scripts/ffi-export-allowlist.json:\n  {}\n\
         Each leaked name is either (a) a legitimately-non-parity export — add \
         it to the bridge's array in ffi-export-allowlist.json with the right \
         `kind` + `reason`; or (b) a genuine cross-bridge parity operation that \
         lacks an alias entry — add it to the pending_registration block (with \
         cross-bridge evidence) and register it in bridge-aliases.json.",
        all_leaks.len(),
        all_leaks.join("\n  ")
    );
}

/// Guard (a): no dead allowlist entries. Every name listed in
/// ffi-export-allowlist.json (both the per-bridge arrays AND the
/// pending_registration block) must correspond to an actually-exported fn in
/// that bridge — otherwise the allowlist accumulates stale entries that hide
/// nothing and rot silently.
#[test]
fn ffi_export_allowlist_has_no_stale_entries() {
    let mut stale: Vec<String> = Vec::new();
    for (bridge, root) in bridge_export_targets() {
        // QUALIFIED keys: an entry is stale unless its EXACT `<path>::<name>`
        // is an actual export. This also catches a `path` that drifted (file
        // renamed/moved) — the bare name might still exist elsewhere, but the
        // entry no longer describes a real export and must be corrected.
        let exported = exported_qualified_under(&root);
        let entries = per_bridge_entries(bridge)
            .iter()
            .chain(pending_entries(bridge));
        for entry in entries {
            if !exported.contains(&entry.qualified_key()) {
                stale.push(format!("{bridge}::{}", entry.qualified_key()));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "ffi-export-allowlist.json has {} stale entry(ies) (the qualified \
         <path>::<name> is not an exported fn in that bridge): {stale:?}. \
         Remove them or correct the `path`.",
        stale.len()
    );
}

/// The capability-matrix artifact a `bridge-specific` allowlist reason must
/// reference: it asserts an export is one-bridge BY DESIGN, so the matrix that
/// records which bridges implement which op is the auditable justification.
const CAPABILITY_MATRIX_REF: &str = "sdk-capability-matrix.json";

/// Records any ADR-/SCP- token in `reason` that does NOT exist in its
/// corpus. Shape (`cites_durable_provenance`) is necessary but not sufficient:
/// this is the SAME existence check `every_exemption_reason_cites_durable_provenance`
/// runs, so a fabricated `ADR-999` / `SCP-9999` cannot substantiate an
/// allowlist entry. Spec `§` sections stay shape-only (section numbers are not
/// single greppable tokens against the multi-file spec).
fn fabricated_provenance_in(reason: &str) -> Vec<String> {
    let mut bad: Vec<String> = cited_tokens(reason, "ADR-")
        .into_iter()
        .filter(|t| !adrs_in_repo().contains(t))
        .collect();
    bad.extend(
        cited_tokens(reason, "SCP-")
            .into_iter()
            .filter(|t| !scp_stories_in_repo().contains(t)),
    );
    bad
}

/// Guard (b): every allowlist entry's `kind` is valid and its `reason` is
/// non-empty.
///
/// Per Finding 2 the reason is EXISTENCE-checked, not merely shape-checked:
///   • `wasm-only` and `pending-registration` must cite a durable artifact
///     (ADR / §spec / SCP story) AND every cited ADR/SCP token must actually
///     EXIST in the repo corpus — a fabricated `ADR-999` no longer passes.
///   • `bridge-specific` must reference the capability-matrix justification
///     (`sdk-capability-matrix.json`) OR an existing ADR/§/SCP that explains
///     the one-bridge status — its prose justification is now ENFORCED, not
///     optional. This is the artifact that records which bridges implement an
///     op; a `bridge-specific` claim ("one-bridge by design, not a gap") is
///     only auditable against it.
///   • getter / lifecycle / dunder / constructor / test-fixture /
///     introspection remain kind-tag-only (a non-empty reason suffices): the
///     kind tag itself is the justification.
#[test]
fn ffi_export_allowlist_reasons_are_justified() {
    const VALID_KINDS: &[&str] = &[
        "getter",
        "lifecycle",
        "dunder",
        "wasm-only",
        "test-fixture",
        "introspection",
        "constructor",
        "bridge-specific",
        "pending-registration",
    ];
    let file = ffi_export_allowlist();
    let mut offenders: Vec<String> = Vec::new();

    let mut check = |bridge: &str, entry: &AllowlistEntry, force_provenance: bool| {
        if !VALID_KINDS.contains(&entry.kind.as_str()) {
            offenders.push(format!(
                "{bridge}::{} has invalid kind '{}' (valid: {VALID_KINDS:?})",
                entry.name, entry.kind
            ));
            return;
        }
        if entry.reason.trim().is_empty() {
            offenders.push(format!("{bridge}::{} has an empty reason", entry.name));
            return;
        }
        // `bridge-specific` requires the capability-matrix justification OR a
        // durable ADR/§/SCP artifact explaining the one-bridge status.
        if entry.kind == "bridge-specific" {
            let cites_matrix = entry.reason.contains(CAPABILITY_MATRIX_REF);
            if !cites_matrix && !cites_durable_provenance(&entry.reason) {
                offenders.push(format!(
                    "{bridge}::{} (kind 'bridge-specific') must reference the \
                     capability-matrix justification ('{CAPABILITY_MATRIX_REF}') \
                     or an existing ADR-NNN / §N / SCP-NNN explaining the \
                     one-bridge status; got: {:?}",
                    entry.name, entry.reason
                ));
            }
            // Whatever ADR/SCP it DOES cite must exist.
            let fabricated = fabricated_provenance_in(&entry.reason);
            if !fabricated.is_empty() {
                offenders.push(format!(
                    "{bridge}::{} (kind 'bridge-specific') cites non-existent \
                     artifact(s) {fabricated:?}",
                    entry.name
                ));
            }
            return;
        }
        let needs_provenance =
            force_provenance || entry.kind == "wasm-only" || entry.kind == "pending-registration";
        if needs_provenance {
            if !cites_durable_provenance(&entry.reason) {
                offenders.push(format!(
                    "{bridge}::{} (kind '{}') must cite a durable artifact \
                     (ADR-NNN / §N / SCP-NNN) in its reason; got: {:?}",
                    entry.name, entry.kind, entry.reason
                ));
                return;
            }
            // Shape is not enough: the cited ADR/SCP must EXIST in the corpus.
            let fabricated = fabricated_provenance_in(&entry.reason);
            if !fabricated.is_empty() {
                offenders.push(format!(
                    "{bridge}::{} (kind '{}') cites non-existent artifact(s) \
                     {fabricated:?} (no matching file/heading under .docs/)",
                    entry.name, entry.kind
                ));
            }
        }
    };

    for (bridge, entries) in [
        ("pyo3", &file.pyo3),
        ("uniffi", &file.uniffi),
        ("napi", &file.napi),
        ("wasm", &file.wasm),
    ] {
        for entry in entries {
            check(bridge, entry, false);
        }
    }
    // pending_registration entries always require durable provenance: they are
    // assertions that a real parity op exists across bridges but is not yet
    // registered, so the evidence must be auditable.
    for (bridge, entries) in [
        ("pyo3", &file.pending_registration.pyo3),
        ("uniffi", &file.pending_registration.uniffi),
        ("napi", &file.pending_registration.napi),
        ("wasm", &file.pending_registration.wasm),
    ] {
        for entry in entries {
            check(bridge, entry, true);
        }
    }

    assert!(
        offenders.is_empty(),
        "ffi-export-allowlist.json has {} unjustified entry(ies):\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}
