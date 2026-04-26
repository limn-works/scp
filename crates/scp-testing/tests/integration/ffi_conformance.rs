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

// UniFFI bridge (single file) plus the server module that hosts UniFFI's
// site-projection methods (enable/disable_site_projection on the Server type).
const UNIFFI_BRIDGE: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/bridge.rs");
const UNIFFI_SERVER: &str = include_str!("../../../../crates/scp-ffi/uniffi/src/server.rs");

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
    #[allow(dead_code)]
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

/// Cache key for `FnSetCache`. `(ptr, len)` keys the parsed set against the
/// identity of a `&'static str` — see `fns_of_source` for rationale.
type FnSetCacheKey = (usize, usize);

/// Process-wide cache of parsed fn-name sets, keyed by `FnSetCacheKey`.
type FnSetCache = Mutex<HashMap<FnSetCacheKey, &'static HashSet<String>>>;

/// Returns a cached `HashSet<String>` of function-definition names for the
/// given source. Keyed by `(ptr, len)` of the `&'static str` so each
/// `include_str!`-ed bridge file is parsed exactly once per test process.
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
    let parsed: &'static HashSet<String> = Box::leak(Box::new(collect_defined_fns(source)));
    let mut guard = cache.lock().expect("fns_of_source cache mutex");
    // Another thread may have inserted between the two lock acquisitions.
    guard.entry(key).or_insert(parsed)
}

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
    // UniFFI's surface spans both the central bridge.rs (most ops) and a
    // smaller server.rs module that hosts site-projection methods on the
    // `Server` type. Search both — Batch 2 (#1543).
    uniffi_names(canonical)
        .iter()
        .any(|name| source_has_fn(UNIFFI_BRIDGE, name) || source_has_fn(UNIFFI_SERVER, name))
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
    assert!(
        wasm.coverage_pct() >= 70.0,
        "WASM coverage {:.1}% below 70% threshold",
        wasm.coverage_pct()
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
const MIN_PARITY_OPERATIONS: usize = 97;

/// Named set of operations that must have `wasm_required=true`.
/// This is a named set, not a count — swapping one operation for another is
/// caught. Operations can be added but never removed or weakened.
const WASM_REQUIRED_OPERATIONS: &[&str] = &[
    // Identity
    "identity_create",
    "identity_load",
    "identity_resolve",
    "identity_migrate",
    "identity_attest_device",
    "identity_verify_device_attestation",
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
    // UCAN
    "ucan_validate",
    "ucan_mint",
    "ucan_revoke",
    "ucan_delegate",
    // Event Log
    "event_log_query",
    "event_log_verify",
    "event_log_checkpoint",
    // Broadcast
    "broadcast_subscribe",
    "broadcast_unsubscribe",
    "broadcast_publish",
    "broadcast_block",
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
    // Identity (8)
    "identity_link_attestations",
    "identity_rotate_key",
    "identity_create_with_agent_key",
    "identity_execute_recovery",
    "identity_execute_custody_migration",
    "identity_add_agent_key",
    "identity_remove_agent_key",
    "identity_rotate_agent_key",
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

    // 5. Every canonical op must have at least one alias per bridge
    //    (even if the bridge is exempt in the JSON's exemption list — the
    //    alias the script would search for must still be documented).
    for op in &file.operations {
        for (bridge_name, aliases) in [
            ("pyo3", &op.pyo3),
            ("uniffi", &op.uniffi),
            ("napi", &op.napi),
            ("wasm", &op.wasm),
        ] {
            assert!(
                !aliases.is_empty(),
                "canonical {} has no aliases for bridge {bridge_name}",
                op.canonical
            );
        }
    }
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
                source_has_fn(UNIFFI_BRIDGE, name) || source_has_fn(UNIFFI_SERVER, name)
            });
            if !any_resolves {
                phantom.push(format!(
                    "uniffi:{} — none of the declared aliases {:?} resolve to `fn <name>(` in crates/scp-ffi/uniffi/src/{{bridge,server}}.rs",
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
