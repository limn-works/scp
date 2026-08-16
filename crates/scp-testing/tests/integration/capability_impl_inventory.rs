// A test binary asserts by panicking, and a scanner that cannot parse a source
// file has no honest verdict to report, so `expect`/`panic` are the right
// failure mode here. This mirrors the header on `capability_nullifiers.rs`.
#![allow(clippy::expect_used, clippy::panic, clippy::doc_markdown)]

//! Identity ratchet over every `impl` of the §17.17.2 production-capability
//! traits, over the trait registry those capabilities resolve to, and over the
//! three lists `scripts/check-shipped-feature-graph.sh` evaluates.
//!
//! # The hole this closes
//!
//! Three mechanisms guard spec §17.17.2 SCP-CAPSEL-8012, and each keys on a
//! different property.
//!
//! `capability_nullifiers.rs` keys on the **shape of a method body**: it flags a
//! method that reads neither `self` nor any parameter and still reports success.
//! An author who wants a fake that survives it writes a body that reads a
//! parameter and discards the value.
//!
//! The failure-path tests key on **behaviour**: they demand a typed error from a
//! production arm, which a fake cannot return. They catch a production arm
//! rewritten in place from real to fake.
//!
//! Neither one notices a new, plausible-looking fake **added** alongside the
//! real implementations. This file keys on **an implementation existing**. It
//! enumerates every impl of a registered capability trait, records what that
//! impl is, and compares the enumeration against a frozen baseline. A convincing
//! fake still moves the enumeration, because the predicate is not "does this
//! body look fake" but "is this impl one a human already reviewed".
//!
//! # The criterion
//!
//! The scan of the workspace and the baseline in
//! `ratchet/capability-impl-inventory.json` must hold **the same records**. Any
//! difference fails: an added impl, a removed impl, or a gating that flipped
//! between production and `testing`-gated.
//!
//! Which records exist, not how many impls exist, is the point. A ratchet that
//! records a total count is defeated by deleting one implementation and adding
//! another in the same commit, which is precisely the swap this file exists to
//! catch. Each record does carry an `impl_count`, because two impls that agree
//! in every recorded field are two impls; that multiplicity counts copies of one
//! identity and is not the cardinality the ratchet refuses to key on.
//!
//! # The registry, and the gate's four lists
//!
//! The trait names in the detector's `CAPABILITY_TRAITS` are frozen here, so
//! replacing one registered trait with another that also resolves — which holds
//! both the capability count and the trait count constant — fails rather than
//! quietly narrowing both gates' scope.
//!
//! The four lists `scripts/check-shipped-feature-graph.sh` evaluates are frozen
//! here too, read from that gate's own `--dump-lists` output:
//!
//! - `PERMITTED_ALLOWLIST` is where an author who wants a nullifier feature
//!   shipped would put it, so growth there fails this ratchet.
//! - `PERMITTED_CRATES` is where an author who wants a nullifier-carrying CRATE
//!   shipped would put it. That list exists because a crate declaring no
//!   `[features]` table emits no feature edge, so `PERMITTED_ALLOWLIST` never
//!   sees it and the gate's feature comparison has nothing to reject it with.
//! - `NULLIFIER_CONTROL_FEATURES` holds the positive controls the gate's
//!   `assert_allowlist_has_no_nullifier` check runs, so deleting an entry
//!   retires one of those controls. The gate's own
//!   `assert_control_features_resolve` fails on an entry that names nothing;
//!   this ratchet covers the other direction, where an entry that names
//!   something real quietly disappears.
//! - `ARTIFACTS` names each shipped artifact and the feature configuration the
//!   gate resolves it in. Deleting an entry stops gating that artifact, and
//!   editing a feature string gates it in a configuration it does not ship —
//!   both leave the gate printing `OK` for a narrower claim than it appears to
//!   make.
//!
//! Reading those lists from the gate's evaluated output, rather than from its
//! source text, is what makes the freeze hold. See `read_gate_lists`.
//!
//! # What each recorded field states, and what it does not
//!
//! Every recorded field is a fact about a **definition**: an `impl` item, its
//! trait, its type, the file that holds it, and the `cfg` predicates that decide
//! whether a production build compiles it.
//!
//! - `capability`, `trait`, `type`, `file` name the impl. The scanner reads them
//!   off the `impl Trait for Type` item and the file that holds it.
//! - `gating` is `production` or `testing-gated`. `testing-gated` means no build
//!   with `test` off and the `testing` feature off can compile this impl, which
//!   `cfg_predicate_holds_in_production` decides by asking whether *any*
//!   assignment of the predicate's other atoms makes it true.
//!
//! # Why no field records whether production code constructs the type
//!
//! `gating` already answers, for the impl, whether a build with `test` off and
//! the `testing` feature off compiles it at all, and the compiler decides that.
//! The narrower question — does production code reach a constructor of the
//! implementing type — has no sound source-side answer, and
//! `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` forbids
//! approximating it. That lesson draws the line at a definition: a source-text
//! gate "may only assert structural facts about a type's *definition*", and "the
//! moment a gate tries to verify a *use-site* property … it is reimplementing
//! the compiler's name resolution in an AST walker, which is an **unbounded arms
//! race** and must not be attempted."
//!
//! An earlier draft of this file recorded a `constructed_in_production` boolean,
//! scanning production-scoped source for a struct literal, a call, or an
//! associated-function call naming the implementing type. Three defects followed
//! from the missing name resolution, and each one is what the lesson predicts.
//! The scan keyed on the type's head identifier, so the two impls for
//! `InMemoryRelayQuerier` — one in `crates/scp-identity/src/resolution.rs`, a
//! different type in `crates/scp-identity/src/resolver.rs` — shared one flag,
//! as did the two for `InMemoryCredentialStore`. The blanket impls over
//! `std::sync::Arc<T>` recorded `true` because some file in the workspace calls
//! `Arc::new`, which no edit can ever change. And pruning the `cfg`-excluded
//! subtrees took four syn node kinds before the count came out right, with more
//! spellings left unhandled.
//!
//! The lesson blesses the rest of this file in the same breath: "Bounded,
//! definition-SIDE source-text checks are legitimately sound and SHOULD be kept
//! — including a frozen-shape positive whitelist." A frozen set of `impl`
//! definitions is exactly that.
//!
//! # How this file consumes the detector's trait registry
//!
//! `capability_nullifiers.rs` resolved §17.17.2's seven provider capabilities to
//! trait names in its `CAPABILITY_TRAITS` const, and its
//! `registry_scope_still_resolves` test fails when a registered name stops
//! resolving. That registry is authoritative, so this file parses it out of that
//! source file rather than restating it. One definition exists in the repository,
//! which is why the two mechanisms cannot disagree about which traits are in
//! scope.
//!
//! # Why the module walk here is not the detector's walk
//!
//! The detector drops a `testing`-gated impl before it records anything, because
//! the shipped-feature-graph gate owns those arms. This inventory must record
//! the gated impls too — a gated impl losing its gate is exactly the change the
//! ratchet has to see — so its walk carries a gating flag down the module tree
//! instead of pruning at it. The two walks answer different questions about the
//! same tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// The workspace root, derived from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("scp-testing manifest dir has a crates/ parent and a workspace root")
        .to_path_buf()
}

/// The detector whose `CAPABILITY_TRAITS` const this file consumes.
const DETECTOR_SOURCE: &str = "crates/scp-testing/tests/integration/capability_nullifiers.rs";

/// The prove-absence gate whose permitted-production allowlist this file freezes.
const FEATURE_GRAPH_GATE: &str = "scripts/check-shipped-feature-graph.sh";

/// The frozen inventory.
const BASELINE: &str = "ratchet/capability-impl-inventory.json";

// ---------------------------------------------------------------------------
// Consuming the detector's capability-trait registry
// ---------------------------------------------------------------------------

/// One registered capability and the trait names that express it, read from
/// `capability_nullifiers.rs`.
#[derive(Debug, Clone)]
struct RegisteredCapability {
    capability: String,
    traits: Vec<String>,
}

/// Parses the `CAPABILITY_TRAITS` const out of the detector's source.
///
/// The detector's registry is the single definition of which traits §17.17.2's
/// seven provider capabilities resolve to. Reading it here, instead of copying
/// it, is what keeps the two mechanisms from disagreeing about scope: a trait
/// added there widens this ratchet in the same commit, with no edit to this file.
///
/// Every failure below panics rather than returning an empty registry, because
/// an empty registry would make every assertion in this file vacuous — the scan
/// would match no impl, find no difference from a baseline it also could not
/// populate, and pass while covering nothing.
fn parse_detector_registry(workspace: &Path) -> Vec<RegisteredCapability> {
    let path = workspace.join(DETECTOR_SOURCE);
    let src = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "cannot read the capability-trait registry from {} — {err}. This \
             ratchet reads `CAPABILITY_TRAITS` out of that file so the two \
             gates share one scope definition.",
            path.display()
        )
    });
    let parsed = syn::parse_file(&src)
        .unwrap_or_else(|err| panic!("syn parse failed for {} — {err}", path.display()));

    let item = parsed
        .items
        .iter()
        .find_map(|it| match it {
            syn::Item::Const(c) if c.ident == "CAPABILITY_TRAITS" => Some(c),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "{DETECTOR_SOURCE} no longer defines `CAPABILITY_TRAITS`. That \
                 const is this ratchet's scope selector; a rename must update \
                 this reader in the same commit."
            )
        });

    let entries = array_elements(&item.expr).unwrap_or_else(|| {
        panic!(
            "`CAPABILITY_TRAITS` in {DETECTOR_SOURCE} is no longer a slice \
             literal, so this ratchet cannot read its scope."
        )
    });

    let registry: Vec<RegisteredCapability> = entries
        .iter()
        .map(|entry| {
            let syn::Expr::Struct(s) = strip_wrappers(entry) else {
                panic!("`CAPABILITY_TRAITS` holds a non-struct element");
            };
            let mut capability = None;
            let mut traits = None;
            for field in &s.fields {
                let syn::Member::Named(name) = &field.member else {
                    continue;
                };
                if name == "capability" {
                    capability = string_literal(&field.expr);
                } else if name == "traits" {
                    traits = array_elements(&field.expr)
                        .map(|elems| elems.iter().filter_map(string_literal).collect::<Vec<_>>());
                }
            }
            RegisteredCapability {
                capability: capability
                    .expect("each CAPABILITY_TRAITS entry names its capability with a string"),
                traits: traits.expect("each CAPABILITY_TRAITS entry lists its trait names"),
            }
        })
        .collect();

    assert!(
        !registry.is_empty(),
        "read zero capabilities out of `CAPABILITY_TRAITS` in {DETECTOR_SOURCE}"
    );
    assert!(
        registry.iter().all(|c| !c.traits.is_empty()),
        "a capability in `CAPABILITY_TRAITS` lists no trait names, so this \
         ratchet would cover nothing for it"
    );
    registry
}

/// Looks through the reference, paren, and group wrappers a const literal can
/// carry.
fn strip_wrappers(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Reference(r) => strip_wrappers(&r.expr),
        syn::Expr::Paren(p) => strip_wrappers(&p.expr),
        syn::Expr::Group(g) => strip_wrappers(&g.expr),
        other => other,
    }
}

/// The elements of an array literal, looking through wrappers.
fn array_elements(expr: &syn::Expr) -> Option<Vec<syn::Expr>> {
    match strip_wrappers(expr) {
        syn::Expr::Array(a) => Some(a.elems.iter().cloned().collect()),
        _ => None,
    }
}

/// The value of a string literal, looking through wrappers.
fn string_literal(expr: &syn::Expr) -> Option<String> {
    match strip_wrappers(expr) {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => Some(s.value()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// cfg evaluation: can this item exist in a production build?
// ---------------------------------------------------------------------------

/// Reports whether some build with `test` off and the `testing` feature off can
/// contain an item carrying this `cfg` predicate.
///
/// **The criterion is satisfiability, not one sample assignment.** `test` is
/// bound to false and `feature = "testing"` to false, because that is the build
/// this file asks about. Every other atom — `unix`, `target_arch = "wasm32"`,
/// `feature = "sqlite"` — is a **free variable**, because a production build can
/// set it either way. The predicate holds in production when *some* assignment
/// of the free variables makes it true, and the answer is computed by trying
/// every assignment.
///
/// Sampling one assignment instead is wrong under negation, and wrong in a way
/// that mislabels a shipped impl as absent. Binding every unknown atom to true
/// reads `#[cfg(not(target_arch = "wasm32"))]` as false and labels the impl
/// `testing-gated`, yet cargo compiles it into every build that is not wasm.
/// Binding every unknown atom to false has the mirror defect. Even trying both
/// extremes is not enough: `all(unix, not(windows))` is false at both and true
/// at the assignment cargo actually uses on Linux.
///
/// An impl this function reports `false` for cannot appear in any production
/// build, which is the claim the `testing-gated` label makes, and which
/// `scripts/check-shipped-feature-graph.sh` then backs for the `testing` feature
/// specifically.
fn cfg_predicate_holds_in_production(tokens: proc_macro2::TokenStream) -> bool {
    // A predicate with many free atoms is reported as production without
    // enumerating, which is the direction that keeps the item in scope. No `cfg`
    // in this workspace comes close to the limit.
    const MAX_FREE_ATOMS: usize = 16;

    let Ok(meta) = syn::parse2::<syn::Meta>(tokens) else {
        // An unparseable predicate is treated as possibly-production, which is
        // the direction that keeps the item in scope.
        return true;
    };

    let mut free_atoms = Vec::new();
    collect_free_atoms(&meta, &mut free_atoms);

    if free_atoms.len() > MAX_FREE_ATOMS {
        return true;
    }

    for assignment in 0u32..(1u32 << free_atoms.len()) {
        let bound: BTreeMap<&str, bool> = free_atoms
            .iter()
            .enumerate()
            .map(|(i, atom)| (atom.as_str(), assignment & (1 << i) != 0))
            .collect();
        if eval_cfg_meta(&meta, &bound) {
            return true;
        }
    }
    false
}

/// Renders one `cfg` atom as the key the assignment map uses, or `None` when the
/// atom is `test` or `feature = "testing"` — the two this file binds to false.
fn free_atom_key(meta: &syn::Meta) -> Option<String> {
    match meta {
        syn::Meta::Path(path) => {
            if path.is_ident("test") {
                return None;
            }
            Some(format!(
                "path:{}",
                path.segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::")
            ))
        }
        syn::Meta::NameValue(nv) => {
            let name = nv
                .path
                .segments
                .last()
                .map_or_else(String::new, |s| s.ident.to_string());
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = &nv.value
            else {
                return Some(format!("nv:{name}:<non-string>"));
            };
            if name == "feature" && s.value() == "testing" {
                return None;
            }
            Some(format!("nv:{name}:{}", s.value()))
        }
        // A list is a combinator, not an atom.
        syn::Meta::List(_) => None,
    }
}

/// Collects the distinct free atoms of a predicate, in first-seen order.
fn collect_free_atoms(meta: &syn::Meta, out: &mut Vec<String>) {
    match meta {
        syn::Meta::Path(_) | syn::Meta::NameValue(_) => {
            if let Some(key) = free_atom_key(meta)
                && !out.contains(&key)
            {
                out.push(key);
            }
        }
        syn::Meta::List(list) => {
            let Ok(nested) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return;
            };
            for inner in &nested {
                collect_free_atoms(inner, out);
            }
        }
    }
}

/// Evaluates a predicate under one assignment of the free atoms. `test` and
/// `feature = "testing"` are bound to false and never appear in `bound`.
fn eval_cfg_meta(meta: &syn::Meta, bound: &BTreeMap<&str, bool>) -> bool {
    match meta {
        syn::Meta::Path(_) | syn::Meta::NameValue(_) => {
            free_atom_key(meta).is_some_and(|key| bound.get(key.as_str()).copied().unwrap_or(true))
        }
        syn::Meta::List(list) => {
            let Ok(nested) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                // An unparseable combinator is treated as satisfiable, the
                // direction that keeps the item in scope.
                return true;
            };
            if list.path.is_ident("not") {
                return nested.first().is_none_or(|m| !eval_cfg_meta(m, bound));
            }
            if list.path.is_ident("all") {
                return nested.iter().all(|m| eval_cfg_meta(m, bound));
            }
            if list.path.is_ident("any") {
                return nested.iter().any(|m| eval_cfg_meta(m, bound));
            }
            // An unrecognised combinator is treated as satisfiable.
            true
        }
    }
}

/// Reports whether any `#[cfg(…)]` on the item excludes it from every production
/// build.
fn attrs_exclude_from_production(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        !cfg_predicate_holds_in_production(list.tokens.clone())
    })
}

// ---------------------------------------------------------------------------
// The module-tree walk
// ---------------------------------------------------------------------------

/// Every crate root file a build compiles: each crate's `src/lib.rs`,
/// `src/main.rs`, and `src/bin/*.rs`.
fn crate_root_files(workspace: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut crate_dirs = Vec::new();
    collect_crate_dirs(&workspace.join("crates"), &mut crate_dirs);
    for crate_dir in crate_dirs {
        let src = crate_dir.join("src");
        for name in ["lib.rs", "main.rs"] {
            let candidate = src.join(name);
            if candidate.is_file() {
                roots.push(candidate);
            }
        }
        if let Ok(entries) = std::fs::read_dir(src.join("bin")) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "rs") {
                    roots.push(path);
                }
            }
        }
    }
    roots.sort();
    roots
}

/// Collects every directory under `dir` that holds a `Cargo.toml`, so a crate
/// nested inside another crate's directory (`scp-ffi/uniffi`, `scp-ffi/napi`,
/// `scp-ffi/common`) is found.
fn collect_crate_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("Cargo.toml").is_file() {
        out.push(dir.to_path_buf());
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == "src" || name.starts_with('.') {
            continue;
        }
        collect_crate_dirs(&path, out);
    }
}

/// Resolves a `mod name;` declaration to the file that holds it, honouring
/// `#[path = "…"]`.
///
/// **A declaration this function cannot resolve panics.** Returning `None` and
/// walking on would drop the whole subtree, so every capability impl inside it
/// would be absent from the inventory with nothing reporting the absence — the
/// silent hole is worse than a loud stop, because a ratchet that cannot see an
/// impl certifies that the impl does not exist.
///
/// `#[path]` resolves against a different directory from a plain `mod`, and the
/// two must not be conflated. Rust resolves a `#[path]` on a non-inline `mod`
/// against **the directory holding the source file that writes the
/// declaration**; it resolves a plain `mod name;` against the *module's* own
/// directory, which for a non-`mod.rs`, non-root file is a sibling directory
/// named for the file. `crates/scp-runtime/src/context/supervisor/key_package_actor.rs`
/// writes `#[path = "key_package_actor_tests.rs"] mod tests;`, whose target sits
/// beside it — resolving that against the module directory looks for a
/// `key_package_actor/` directory that does not exist.
fn resolve_module_file(owner_file: &Path, item_mod: &syn::ItemMod) -> PathBuf {
    let owner_dir = owner_file.parent().unwrap_or_else(|| Path::new("."));
    for attr in &item_mod.attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        let syn::Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) = &nv.value
        else {
            panic!(
                "capability-impl inventory: `{}` writes a `#[path = …]` whose \
                 value is not a string literal, so the walk cannot follow it and \
                 would silently drop every capability impl below it",
                owner_file.display()
            );
        };
        let candidate = owner_dir.join(s.value());
        assert!(
            candidate.is_file(),
            "capability-impl inventory: `{}` writes `#[path = \"{}\"] mod {};` \
             and {} is not a file. The walk cannot follow it, so every \
             capability impl below it would be absent from the inventory.",
            owner_file.display(),
            s.value(),
            item_mod.ident,
            candidate.display()
        );
        return candidate;
    }

    let dir = module_directory(owner_file);
    let name = item_mod.ident.to_string();
    let flat = dir.join(format!("{name}.rs"));
    if flat.is_file() {
        return flat;
    }
    let nested = dir.join(&name).join("mod.rs");
    assert!(
        nested.is_file(),
        "capability-impl inventory: `{}` declares `mod {};` and neither {} nor \
         {} exists. The walk cannot follow it, so every capability impl below \
         it would be absent from the inventory.",
        owner_file.display(),
        name,
        flat.display(),
        nested.display()
    );
    nested
}

/// The directory a module's `mod` declarations resolve against: the file's own
/// directory for a crate root or a `mod.rs`, and a sibling directory named for
/// the file otherwise.
fn module_directory(owner_file: &Path) -> PathBuf {
    let parent = owner_file.parent().unwrap_or_else(|| Path::new("."));
    let stem = owner_file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if matches!(stem.as_str(), "lib" | "main" | "mod") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    }
}

/// The workspace-relative path of a file, with forward slashes.
fn relative_path(path: &Path, workspace: &Path) -> String {
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Pass 1: enumerate the capability-trait impls
// ---------------------------------------------------------------------------

/// One `impl` of a registered capability trait. The record is the ratchet's unit
/// of identity: two impls differ when any field differs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ImplRecord {
    file: String,
    capability: String,
    trait_name: String,
    /// The implementing type's final path segment with its generic arguments,
    /// so a blanket impl over `Arc<S>` is a different record from an impl for
    /// `SqliteStorage`.
    type_name: String,
    /// `"production"` or `"testing-gated"`.
    gating: String,
}

/// What one full workspace walk learned.
#[derive(Default)]
struct Inventory {
    /// The records each walked file contributed, keyed by that file.
    ///
    /// Keying by file is what makes a re-walk idempotent. `walk_module_file`
    /// walks a file again when a production module path reaches a file an
    /// earlier gated path already reached, and replacing that file's entry
    /// discards the superseded gated records. Accumulating into one flat
    /// collection instead would leave both readings in the inventory, so one
    /// impl would produce a gated record and a production record.
    impls: BTreeMap<PathBuf, Vec<ImplRecord>>,
    files_walked: usize,
}

/// The gating state carried down the module tree.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gating {
    Production,
    TestingGated,
}

impl Gating {
    const fn label(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::TestingGated => "testing-gated",
        }
    }

    /// Applying a `cfg` that excludes production gates everything below it; a
    /// subtree already gated stays gated.
    fn and_attrs(self, attrs: &[syn::Attribute]) -> Self {
        if self == Self::TestingGated || attrs_exclude_from_production(attrs) {
            Self::TestingGated
        } else {
            Self::Production
        }
    }
}

/// Walks every crate's module tree and records every impl of a registered
/// capability trait, gated and ungated alike.
fn walk_workspace(workspace: &Path, registry: &[RegisteredCapability]) -> Inventory {
    let capability_of: BTreeMap<String, String> = registry
        .iter()
        .flat_map(|c| {
            c.traits
                .iter()
                .map(move |t| (t.clone(), c.capability.clone()))
        })
        .collect();

    let mut inventory = Inventory::default();
    // A file reachable from two module paths is walked once per gating state,
    // and a later production reading supersedes an earlier gated one: an impl
    // that any production module path reaches is production.
    let mut visited: BTreeMap<PathBuf, Gating> = BTreeMap::new();
    for root in crate_root_files(workspace) {
        walk_module_file(
            &root,
            Gating::Production,
            workspace,
            &capability_of,
            &mut visited,
            &mut inventory,
        );
    }
    inventory
}

fn walk_module_file(
    path: &Path,
    gating: Gating,
    workspace: &Path,
    capability_of: &BTreeMap<String, String>,
    visited: &mut BTreeMap<PathBuf, Gating>,
    inventory: &mut Inventory,
) {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    match visited.get(&canonical) {
        // Already walked in this state, or already walked in the state that
        // supersedes this one.
        Some(Gating::Production) => return,
        Some(Gating::TestingGated) if gating == Gating::TestingGated => return,
        _ => {}
    }
    visited.insert(canonical.clone(), gating);

    let src = std::fs::read_to_string(path).unwrap_or_else(|err| {
        panic!(
            "capability-impl inventory: cannot read the module file {} — {err}. \
             A module the walk cannot read is a module whose capability impls \
             this ratchet would not see.",
            path.display()
        )
    });
    let parsed = match syn::parse_file(&src) {
        Ok(f) => f,
        Err(err) => panic!(
            "capability-impl inventory: syn parse failed for {} — {err}",
            path.display()
        ),
    };
    inventory.files_walked += 1;
    // A re-walk at a superseding gating replaces this file's records rather than
    // adding a second reading of the same impls.
    let file_key = canonical;
    inventory.impls.insert(file_key.clone(), Vec::new());
    let rel = relative_path(path, workspace);
    walk_items(
        &parsed.items,
        &WalkSite {
            owner_file: path,
            file_key: &file_key,
            rel: &rel,
        },
        gating,
        workspace,
        capability_of,
        visited,
        inventory,
    );
}

/// Where a walk currently is: the file being walked, the key its records are
/// filed under, and the workspace-relative path a record records.
struct WalkSite<'a> {
    owner_file: &'a Path,
    file_key: &'a Path,
    rel: &'a str,
}

/// Recursive worker over a module's items.
///
/// A trait `impl` is global to the crate wherever Rust permits it to be written,
/// so the walk descends into the two item kinds that can enclose one without
/// being a module: a `const _: () = { … }` initializer (the derive-macro idiom)
/// and a function body. An impl written inside either applies workspace-wide,
/// and a walk that only opened `mod` blocks would not see it.
///
/// **What this walk cannot reach**, stated so a reader does not take its
/// coverage for more than it is: a capability impl produced by expanding a
/// macro, because `syn` parses a macro invocation as opaque tokens and this file
/// does not expand it; and an impl written with the trait renamed at the use
/// site (`use KeyCustody as Vault; impl Vault for …`), because matching the
/// written trait path against the registry is not name resolution.
/// `no_capability_trait_is_aliased` below closes the second one by refusing the
/// alias itself, which is a fact about a `use` item's own shape rather than a
/// resolution of it.
#[allow(clippy::too_many_arguments)]
fn walk_items(
    items: &[syn::Item],
    site: &WalkSite<'_>,
    gating: Gating,
    workspace: &Path,
    capability_of: &BTreeMap<String, String>,
    visited: &mut BTreeMap<PathBuf, Gating>,
    inventory: &mut Inventory,
) {
    for item in items {
        match item {
            syn::Item::Mod(item_mod) => {
                let inner_gating = gating.and_attrs(&item_mod.attrs);
                if let Some((_, inner)) = &item_mod.content {
                    walk_items(
                        inner,
                        site,
                        inner_gating,
                        workspace,
                        capability_of,
                        visited,
                        inventory,
                    );
                } else {
                    let child = resolve_module_file(site.owner_file, item_mod);
                    walk_module_file(
                        &child,
                        inner_gating,
                        workspace,
                        capability_of,
                        visited,
                        inventory,
                    );
                }
            }
            // A `const _: () = { impl Trait for Type { … } };` initializer and a
            // function body both hold items, and a trait impl written in either
            // is global. Descend into both.
            syn::Item::Const(item_const) => {
                walk_enclosed_block_items(
                    &item_const.expr,
                    site,
                    gating.and_attrs(&item_const.attrs),
                    workspace,
                    capability_of,
                    visited,
                    inventory,
                );
            }
            syn::Item::Fn(item_fn) => {
                let inner_gating = gating.and_attrs(&item_fn.attrs);
                walk_block_items(
                    &item_fn.block,
                    site,
                    inner_gating,
                    workspace,
                    capability_of,
                    visited,
                    inventory,
                );
            }
            syn::Item::Impl(item_impl) => {
                let Some((_, trait_path, _)) = &item_impl.trait_ else {
                    continue;
                };
                let Some(trait_name) = trait_path.segments.last().map(|s| s.ident.to_string())
                else {
                    continue;
                };
                let Some(capability) = capability_of.get(&trait_name) else {
                    continue;
                };
                inventory
                    .impls
                    .entry(site.file_key.to_path_buf())
                    .or_default()
                    .push(ImplRecord {
                        file: site.rel.to_owned(),
                        capability: capability.clone(),
                        trait_name,
                        type_name: render_type(&item_impl.self_ty),
                        gating: gating.and_attrs(&item_impl.attrs).label().to_owned(),
                    });
            }
            _ => {}
        }
    }
}

/// Walks the items a block statement-list holds, so an impl written inside a
/// function body is recorded.
#[allow(clippy::too_many_arguments)]
fn walk_block_items(
    block: &syn::Block,
    site: &WalkSite<'_>,
    gating: Gating,
    workspace: &Path,
    capability_of: &BTreeMap<String, String>,
    visited: &mut BTreeMap<PathBuf, Gating>,
    inventory: &mut Inventory,
) {
    let items: Vec<syn::Item> = block
        .stmts
        .iter()
        .filter_map(|stmt| match stmt {
            syn::Stmt::Item(item) => Some(item.clone()),
            _ => None,
        })
        .collect();
    if items.is_empty() {
        return;
    }
    walk_items(
        &items,
        site,
        gating,
        workspace,
        capability_of,
        visited,
        inventory,
    );
}

/// Walks the items a `const`'s initializer expression holds, looking through the
/// block and wrapper forms the derive-macro idiom uses.
#[allow(clippy::too_many_arguments)]
fn walk_enclosed_block_items(
    expr: &syn::Expr,
    site: &WalkSite<'_>,
    gating: Gating,
    workspace: &Path,
    capability_of: &BTreeMap<String, String>,
    visited: &mut BTreeMap<PathBuf, Gating>,
    inventory: &mut Inventory,
) {
    match expr {
        syn::Expr::Block(b) => walk_block_items(
            &b.block,
            site,
            gating,
            workspace,
            capability_of,
            visited,
            inventory,
        ),
        syn::Expr::Unsafe(u) => walk_block_items(
            &u.block,
            site,
            gating,
            workspace,
            capability_of,
            visited,
            inventory,
        ),
        syn::Expr::Paren(p) => walk_enclosed_block_items(
            &p.expr,
            site,
            gating,
            workspace,
            capability_of,
            visited,
            inventory,
        ),
        syn::Expr::Group(g) => walk_enclosed_block_items(
            &g.expr,
            site,
            gating,
            workspace,
            capability_of,
            visited,
            inventory,
        ),
        _ => {}
    }
}

/// Renders a type as its final path segment with its generic arguments, so the
/// rendering depends on neither the source file's formatting nor the path the
/// author happened to write.
///
/// The identity of a record depends on this string, so an impl for
/// `SqliteStorage` and a blanket impl for `Arc<S>` are two records rather than
/// one collision under the name `Arc`. Normalising every path to its final
/// segment keeps that distinction — it lives in the generic arguments, not in
/// the path prefix — while stopping a `use` statement from reading as a swap:
/// adding `use crate::sqlite::SqliteStorage;` and rewriting
/// `impl EncryptedStorage for crate::sqlite::SqliteStorage` as
/// `impl EncryptedStorage for SqliteStorage` changes no impl, and must not
/// report one addition and one removal, which is the signature this ratchet
/// reserves for a genuine swap.
///
/// The truncation is structural: a `syn::visit_mut` pass replaces every path in
/// the type with its own final segment, so the generic arguments each segment
/// carries survive. `quote` then prints one space between every token, which
/// spells `Arc < T >`, and the closing pass removes the spaces that surround
/// type-path punctuation so a reviewer reads `Arc<T>`.
fn render_type(ty: &syn::Type) -> String {
    struct TruncatePaths;
    impl syn::visit_mut::VisitMut for TruncatePaths {
        fn visit_path_mut(&mut self, path: &mut syn::Path) {
            syn::visit_mut::visit_path_mut(self, path);
            if let Some(last) = path.segments.pop() {
                let last = last.into_value();
                path.segments.clear();
                path.segments.push(last);
                path.leading_colon = None;
            }
        }
    }

    let mut normalised = ty.clone();
    syn::visit_mut::VisitMut::visit_type_mut(&mut TruncatePaths, &mut normalised);

    let spaced = quote::ToTokens::to_token_stream(&normalised).to_string();
    let mut out = String::with_capacity(spaced.len());
    let mut chars = spaced.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ' ' {
            out.push(c);
            continue;
        }
        // Drop a space whose neighbour on either side is type-path punctuation.
        let follows_punctuation = out.ends_with([':', '<', '&', '\'', '(', '[']);
        let precedes_punctuation = chars
            .peek()
            .is_some_and(|n| matches!(n, ':' | '<' | '>' | ',' | ')' | ']'));
        if !follows_punctuation && !precedes_punctuation {
            out.push(' ');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The full scan
// ---------------------------------------------------------------------------

/// The result of one workspace scan.
struct Scan {
    /// How many impls carry each record. A **multiset**, not a set: two impls
    /// that agree in every recorded field are two impls, and collapsing them
    /// into one entry would let a commit delete one of them without moving the
    /// inventory. `crates/scp-ffi/common/src/resolvers.rs` holds exactly that
    /// shape — `impl DidResolver for IdentityBackedDidResolver` and
    /// `impl scp_identity::resolver::DidResolver for IdentityBackedDidResolver`
    /// agree on every field once each trait path is read as its final segment.
    ///
    /// The multiplicity here is not the cardinality the ratchet refuses to key
    /// on. It counts identical copies of ONE identity; the ratchet still keys on
    /// which identities exist, so deleting one impl and adding a different one
    /// still reports one removal and one addition.
    records: BTreeMap<ImplRecord, usize>,
    files_walked: usize,
}

/// Walks the workspace and produces the record multiset the baseline freezes.
fn scan_workspace() -> Scan {
    let workspace = workspace_root();
    let registry = parse_detector_registry(&workspace);
    let inventory = walk_workspace(&workspace, &registry);

    let mut records: BTreeMap<ImplRecord, usize> = BTreeMap::new();
    for record in inventory.impls.into_values().flatten() {
        *records.entry(record).or_insert(0) += 1;
    }
    Scan {
        records,
        files_walked: inventory.files_walked,
    }
}

// ---------------------------------------------------------------------------
// The baseline
// ---------------------------------------------------------------------------

/// The frozen inventory, as the baseline file holds it.
struct Baseline {
    /// Each frozen record and how many impls carry it.
    impls: BTreeMap<ImplRecord, usize>,
    /// The trait names the detector's `CAPABILITY_TRAITS` registers.
    registry_traits: Vec<String>,
    /// The four lists `scripts/check-shipped-feature-graph.sh` evaluates,
    /// keyed by list name.
    gate_lists: BTreeMap<String, Vec<String>>,
}

fn read_baseline(workspace: &Path) -> Baseline {
    let path = workspace.join(BASELINE);
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {} — {err}", path.display()));
    let json: serde_json::Value = serde_json::from_str(&src)
        .unwrap_or_else(|err| panic!("{} is not valid JSON — {err}", path.display()));

    let mut impls: BTreeMap<ImplRecord, usize> = BTreeMap::new();
    for entry in json
        .get("capability_trait_impls")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("{BASELINE} has no `capability_trait_impls` array"))
    {
        let record = ImplRecord {
            file: json_string(entry, "file"),
            capability: json_string(entry, "capability"),
            trait_name: json_string(entry, "trait"),
            type_name: json_string(entry, "type"),
            gating: json_string(entry, "gating"),
        };
        let count = entry
            .get("impl_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{BASELINE} entry lacks the integer `impl_count`"));
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        assert!(
            count > 0,
            "{BASELINE} entry records an `impl_count` of zero"
        );
        assert!(
            impls.insert(record, count).is_none(),
            "{BASELINE} lists the same record twice; multiplicity belongs in \
             `impl_count`"
        );
    }

    let gate_lists_json = json
        .get("shipped_feature_graph_lists")
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| panic!("{BASELINE} has no `shipped_feature_graph_lists` object"));
    let gate_lists: BTreeMap<String, Vec<String>> = gate_lists_json
        .iter()
        .map(|(name, value)| {
            let entries = value
                .as_array()
                .unwrap_or_else(|| panic!("{BASELINE} list `{name}` is not an array"))
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| panic!("{BASELINE} list `{name}` holds a non-string"))
                        .to_owned()
                })
                .collect();
            (name.clone(), entries)
        })
        .collect();

    Baseline {
        impls,
        registry_traits: json_string_array(&json, "capability_registry_traits"),
        gate_lists,
    }
}

/// Reads a required array of strings out of the baseline.
fn json_string_array(json: &serde_json::Value, field: &str) -> Vec<String> {
    json.get(field)
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("{BASELINE} has no `{field}` array"))
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("{BASELINE} entry in `{field}` is not a string"))
                .to_owned()
        })
        .collect()
}

fn json_string(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{BASELINE} entry lacks the string field `{field}`"))
        .to_owned()
}

/// Renders one record and its multiplicity for a failure message.
fn render(record: &ImplRecord, count: usize) -> String {
    let multiplicity = if count == 1 {
        String::new()
    } else {
        format!(" ×{count}")
    };
    format!(
        "  {} — impl {} for {} [{}]{}\n    capability: {}",
        record.file,
        record.trait_name,
        record.type_name,
        record.gating,
        multiplicity,
        record.capability
    )
}

// ---------------------------------------------------------------------------
// The lists `check-shipped-feature-graph.sh` evaluates
// ---------------------------------------------------------------------------

/// Asks the prove-absence gate to print the lists it evaluates, and returns them
/// keyed by list name.
///
/// **The gate prints; this file does not scrape.** An earlier draft located the
/// `PERMITTED_ALLOWLIST="$(cat <<'EOF'` marker in the gate's source and read the
/// lines up to the heredoc terminator. Bash does not stop where that reader
/// stopped, so the two disagreed about what the allowlist is, and one inserted
/// line exploited the disagreement:
///
/// ```text
/// EOF
/// echo scp-identity/some-nullifier-feature
/// )"
/// ```
///
/// The heredoc terminator ends `cat` and the `echo` still runs inside the same
/// command substitution, so the shell's allowlist carried an entry the reader
/// could not see. Duplicating either list assignment did the same thing, because
/// bash takes the last assignment and a text reader takes the first match.
///
/// No text reader can agree with bash here. Freezing the gate's own evaluated
/// output removes the disagreement: whatever the shell computes is what this
/// ratchet compares.
fn read_gate_lists(workspace: &Path) -> BTreeMap<String, Vec<String>> {
    let gate = workspace.join(FEATURE_GRAPH_GATE);
    let output = std::process::Command::new("bash")
        .arg(&gate)
        .arg("--dump-lists")
        .current_dir(workspace)
        .output()
        .unwrap_or_else(|err| panic!("cannot run {} --dump-lists — {err}", gate.display()));
    assert!(
        output.status.success(),
        "{FEATURE_GRAPH_GATE} --dump-lists exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap_or_else(|err| {
        panic!("{FEATURE_GRAPH_GATE} --dump-lists emitted non-UTF-8 — {err}")
    });

    // Each line is `<list-name>\t<entry>`, which the gate emits after evaluating
    // every assignment in the file.
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (name, entry) = line.split_once('\t').unwrap_or_else(|| {
            panic!(
                "{FEATURE_GRAPH_GATE} --dump-lists emitted a line with no tab \
                 separator: {line:?}"
            )
        });
        lists
            .entry(name.to_owned())
            .or_default()
            .push(entry.to_owned());
    }

    assert!(
        !lists.is_empty(),
        "{FEATURE_GRAPH_GATE} --dump-lists emitted nothing, so this ratchet \
         would freeze no list at all"
    );
    lists
}

// ---------------------------------------------------------------------------
// The comparison — the sole decision procedure
// ---------------------------------------------------------------------------

/// What a comparison of the scan against the baseline found.
#[derive(Default)]
struct Difference {
    /// Records the workspace holds that the baseline does not, or holds fewer
    /// copies of, with the workspace's count.
    added: Vec<(ImplRecord, usize)>,
    /// Records the baseline holds that the workspace does not, or holds fewer
    /// copies of, with the baseline's count.
    removed: Vec<(ImplRecord, usize)>,
}

impl Difference {
    const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Compares the scanned record multiset against the baseline record multiset.
///
/// This function, and nothing else, decides whether the inventory ratchet
/// passes. It reports **difference in both directions**, so a commit that
/// deletes one impl and adds another — the swap a count-based ratchet cannot
/// see — reports one addition and one removal rather than a matching total.
///
/// The fixture harness drives this function with synthetic multisets, which is
/// how a caller confirms the ratchet is alive without waiting on a workspace
/// walk.
fn compare(
    scanned: &BTreeMap<ImplRecord, usize>,
    baseline: &BTreeMap<ImplRecord, usize>,
) -> Difference {
    let mut diff = Difference::default();
    for (record, count) in scanned {
        if baseline.get(record).copied().unwrap_or(0) != *count {
            diff.added.push((record.clone(), *count));
        }
    }
    for (record, count) in baseline {
        if scanned.get(record).copied().unwrap_or(0) != *count {
            diff.removed.push((record.clone(), *count));
        }
    }
    diff
}

/// Compares one of the gate's lists against its frozen copy, and renders the
/// difference both ways.
fn assert_gate_list_matches(gate: &[String], baseline: &[String], label: &str, why: &str) {
    let gate_set: BTreeSet<&String> = gate.iter().collect();
    let baseline_set: BTreeSet<&String> = baseline.iter().collect();
    let added: Vec<&&String> = gate_set.difference(&baseline_set).collect();
    let removed: Vec<&&String> = baseline_set.difference(&gate_set).collect();

    assert!(
        added.is_empty() && removed.is_empty(),
        "the {label} that {FEATURE_GRAPH_GATE} evaluates no longer matches the \
         frozen copy in {BASELINE}.\n\n{why}\n\n\
         {} entry(ies) the gate evaluates and the baseline does not hold: {:?}\n\
         {} entry(ies) the baseline holds and the gate does not evaluate: {:?}",
        added.len(),
        added,
        removed.len(),
        removed
    );
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// The floor the walk must clear. The clean tree walks 553 files; a walk that
/// collapses toward zero broke, rather than shrank.
const FILES_WALKED_FLOOR: usize = 400;

/// Spec §17.17.2 SCP-CAPSEL-8012 — a new `impl` of a production-capability trait
/// fails until a human reviews it into `ratchet/capability-impl-inventory.json`.
#[test]
fn capability_trait_impl_inventory_matches_the_baseline() {
    let workspace = workspace_root();
    let scan = scan_workspace();
    let baseline = read_baseline(&workspace);

    assert!(
        scan.files_walked > FILES_WALKED_FLOOR,
        "the inventory walk reached only {} files, which means the module-tree \
         walk broke rather than that the workspace shrank (the clean tree \
         reaches 553)",
        scan.files_walked
    );
    assert!(
        !baseline.impls.is_empty(),
        "{BASELINE} lists zero capability-trait impls, so this ratchet would \
         certify an emptied workspace"
    );

    let diff = compare(&scan.records, &baseline.impls);
    assert!(
        diff.is_empty(),
        "the set of `impl`s of the §17.17.2 production-capability traits no \
         longer matches {BASELINE}.\n\n\
         Every difference below needs a human to read the implementation and \
         decide whether it belongs on a production path, and then to record \
         that decision by editing the baseline. An addition is a new capability \
         implementation nobody has reviewed. A removal paired with an addition \
         is the swap this ratchet exists to catch, which is why removals fail \
         too — a ratchet that counted implementations would see the two cancel.\n\n\
         {} record(s) the workspace holds and the baseline does not:\n{}\n\n\
         {} record(s) the baseline holds and the workspace does not:\n{}",
        diff.added.len(),
        render_all(&diff.added),
        diff.removed.len(),
        render_all(&diff.removed)
    );
}

/// Renders a side of the difference, or `(none)` when it is empty.
fn render_all(records: &[(ImplRecord, usize)]) -> String {
    if records.is_empty() {
        return "  (none)".to_owned();
    }
    records
        .iter()
        .map(|(record, count)| render(record, *count))
        .collect::<Vec<_>>()
        .join("\n")
}

/// ADR-062 §Decision 6 — the lists that decide what a shipped artifact may
/// carry, and which artifacts are checked at all, may not change without a human
/// recording the change in the baseline.
#[test]
fn shipped_feature_graph_lists_match_the_baseline() {
    let workspace = workspace_root();
    let evaluated = read_gate_lists(&workspace);
    let frozen = read_baseline(&workspace).gate_lists;

    let evaluated_names: BTreeSet<&String> = evaluated.keys().collect();
    let frozen_names: BTreeSet<&String> = frozen.keys().collect();
    assert_eq!(
        evaluated_names, frozen_names,
        "{FEATURE_GRAPH_GATE} --dump-lists emits a different set of list names \
         from the set {BASELINE} freezes. A list the gate stopped emitting is a \
         list this ratchet stopped covering."
    );

    let why: BTreeMap<&str, &str> = [
        (
            "permitted_allowlist",
            "An allowlist entry is where an author who wants a nullifier feature \
             shipped would put it, so growth here fails this ratchet until a \
             human reviews the entry and records it in the baseline. A removal \
             narrows what ships and is safe, and it fails too, because a removal \
             paired with an addition is a swap that leaves the entry count \
             unchanged.",
        ),
        (
            "permitted_crates",
            "An entry here is where an author who wants a nullifier-carrying \
             crate shipped would put it. The crate dimension exists because a \
             crate that declares no `[features]` table emits no feature edge, \
             so `permitted_allowlist` cannot see it — growth here therefore \
             fails this ratchet until a human reads what the crate implements. \
             A removal narrows what may ship and fails too, because a removal \
             paired with an addition is a swap that leaves the entry count \
             unchanged.",
        ),
        (
            "nullifier_control_features",
            "Each entry here is a positive control the gate's allowlist-hygiene \
             check runs. Deleting one retires that control. The gate's own \
             `assert_control_features_resolve` separately rejects an entry that \
             names no feature or crate the workspace declares.",
        ),
        (
            "artifacts",
            "Each entry names a shipped artifact and the exact feature \
             configuration the gate resolves it in. Deleting an entry stops \
             gating that artifact, and editing a feature string gates it in a \
             configuration it does not ship — both leave the gate printing `OK` \
             for a narrower claim than the one it appears to make.",
        ),
    ]
    .into_iter()
    .collect();

    for (name, entries) in &evaluated {
        assert_gate_list_matches(
            entries,
            frozen.get(name).unwrap_or_else(|| {
                panic!("{BASELINE} has no frozen copy of the gate list `{name}`")
            }),
            name,
            why.get(name.as_str()).unwrap_or(
                &"This list decides what the prove-absence gate checks, so a \
                  change to it needs a human to record the change in the baseline.",
            ),
        );
    }
}

/// Scope integrity: this ratchet reads its trait scope out of the detector's
/// `CAPABILITY_TRAITS`, so the registry's contents are frozen here.
///
/// Freezing the names, not just their count, is what stops a swap. Replacing
/// `PreRotationCustody` with a trait that also resolves — `Clock`, say — holds
/// both the capability count and the trait count constant, satisfies the
/// detector's `registry_scope_still_resolves` (which asks only that each
/// registered name resolve to a trait that exists), and takes pre-rotation
/// custody out of both gates' scope in one commit.
#[test]
fn capability_registry_matches_the_baseline() {
    let workspace = workspace_root();
    let registry = parse_detector_registry(&workspace);
    let baseline = read_baseline(&workspace);

    let capabilities: BTreeSet<&String> = registry.iter().map(|c| &c.capability).collect();
    assert_eq!(
        capabilities.len(),
        7,
        "spec §17.17.2 enumerates seven provider capabilities, and the detector's \
         `CAPABILITY_TRAITS` resolved {}: {capabilities:?}",
        capabilities.len()
    );

    let traits: Vec<String> = {
        let mut t: Vec<String> = registry
            .iter()
            .flat_map(|c| c.traits.iter().cloned())
            .collect();
        t.sort();
        t
    };
    let frozen = {
        let mut f = baseline.registry_traits;
        f.sort();
        f
    };
    assert_eq!(
        traits, frozen,
        "the trait names in `CAPABILITY_TRAITS` ({DETECTOR_SOURCE}) no longer \
         match the frozen copy in {BASELINE}. Adding a trait widens both gates \
         and is the direction to welcome; removing or replacing one narrows \
         them, and the counts alone do not distinguish the two."
    );
}

/// A capability trait renamed at the use site is a capability trait this walk
/// does not recognise, because matching the written trait path against the
/// registry is not name resolution and must not become it. The alias is refused
/// instead — a fact about the `use` item's own shape.
///
/// `use crate::custody::KeyCustody as Vault;` followed by
/// `impl Vault for Sneaky` is a real `KeyCustody` implementation that
/// `walk_items` records under the name `Vault`, finds unregistered, and drops.
/// `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` forbids
/// resolving the alias; refusing to admit the alias item at all is the
/// definition-side closure that lesson blesses for the same-file `type` alias.
#[test]
fn no_capability_trait_is_renamed_by_a_use_alias() {
    let workspace = workspace_root();
    let registry = parse_detector_registry(&workspace);
    let registered: BTreeSet<String> = registry
        .iter()
        .flat_map(|c| c.traits.iter().cloned())
        .collect();

    let mut offenders: Vec<String> = Vec::new();
    for root in crate_root_files(&workspace) {
        let mut visited = BTreeSet::new();
        collect_trait_aliases(&root, &workspace, &registered, &mut visited, &mut offenders);
    }
    assert!(
        offenders.is_empty(),
        "a `use` item renames a §17.17.2 capability trait. An `impl` written \
         against the new name is a real implementation of the capability trait, \
         and this ratchet records it under a name its registry does not hold, so \
         the impl leaves the inventory without moving it. Write the trait's own \
         name at the impl:\n{}",
        offenders.join("\n")
    );
}

/// Walks the module tree collecting `use … as …` items that rename a registered
/// capability trait.
fn collect_trait_aliases(
    path: &Path,
    workspace: &Path,
    registered: &BTreeSet<String>,
    visited: &mut BTreeSet<PathBuf>,
    offenders: &mut Vec<String>,
) {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical) {
        return;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(parsed) = syn::parse_file(&src) else {
        return;
    };
    let rel = relative_path(path, workspace);
    scan_items_for_aliases(
        &parsed.items,
        path,
        &rel,
        registered,
        visited,
        offenders,
        workspace,
    );
}

fn scan_items_for_aliases(
    items: &[syn::Item],
    owner_file: &Path,
    rel: &str,
    registered: &BTreeSet<String>,
    visited: &mut BTreeSet<PathBuf>,
    offenders: &mut Vec<String>,
    workspace: &Path,
) {
    for item in items {
        match item {
            syn::Item::Use(item_use) => {
                if attrs_exclude_from_production(&item_use.attrs) {
                    continue;
                }
                collect_renames_in_use_tree(&item_use.tree, registered, rel, offenders);
            }
            syn::Item::Mod(item_mod) => {
                // An alias inside a `cfg`-excluded module can only support an
                // impl inside that same excluded module, and such an impl cannot
                // reach a shipped artifact — `scripts/check-shipped-feature-graph.sh`
                // proves the gating feature absent from every one. The alias this
                // check refuses is the one that hides a SHIPPED impl.
                if attrs_exclude_from_production(&item_mod.attrs) {
                    continue;
                }
                if let Some((_, inner)) = &item_mod.content {
                    scan_items_for_aliases(
                        inner, owner_file, rel, registered, visited, offenders, workspace,
                    );
                } else {
                    let child = resolve_module_file(owner_file, item_mod);
                    collect_trait_aliases(&child, workspace, registered, visited, offenders);
                }
            }
            _ => {}
        }
    }
}

/// Records every `X as Y` in a `use` tree whose `X` is a registered capability
/// trait and whose `Y` differs from it.
fn collect_renames_in_use_tree(
    tree: &syn::UseTree,
    registered: &BTreeSet<String>,
    rel: &str,
    offenders: &mut Vec<String>,
) {
    match tree {
        syn::UseTree::Path(p) => collect_renames_in_use_tree(&p.tree, registered, rel, offenders),
        syn::UseTree::Group(g) => {
            for inner in &g.items {
                collect_renames_in_use_tree(inner, registered, rel, offenders);
            }
        }
        syn::UseTree::Rename(rename) => {
            let original = rename.ident.to_string();
            let alias = rename.rename.to_string();
            // `use … Trait as _;` brings the trait's methods into scope without
            // naming it. `_` is not an identifier an `impl` can be written
            // against, so this form cannot produce the impl this check refuses.
            // Three live sites use it: `crates/scp-ffi/common/src/bridge_runtime.rs`,
            // `crates/scp-node/src/lib.rs`, and one more.
            if alias == "_" {
                return;
            }
            if registered.contains(&original) && alias != original {
                offenders.push(format!("  {rel} — `use … {original} as {alias};`"));
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
    }
}

/// Every crate under `crates/` contributes at least one root file to the walk.
///
/// `crate_root_files` looks for `src/lib.rs`, `src/main.rs`, and `src/bin/*.rs`
/// rather than reading each manifest's `[lib] path` / `[[bin]] path`, so a crate
/// that relocates its root would drop out of the walk. Dropping a crate lowers
/// `files_walked`, but the floor is 400 against a clean 553, so the floor alone
/// would not notice. This does.
#[test]
fn every_crate_contributes_a_root_file_to_the_walk() {
    let workspace = workspace_root();
    let roots = crate_root_files(&workspace);
    let mut crate_dirs = Vec::new();
    collect_crate_dirs(&workspace.join("crates"), &mut crate_dirs);

    let missing: Vec<String> = crate_dirs
        .iter()
        .filter(|dir| !roots.iter().any(|root| root.starts_with(dir)))
        .map(|dir| relative_path(dir, &workspace))
        .collect();
    assert!(
        missing.is_empty(),
        "these crates hold a Cargo.toml and contributed no root file to the \
         module walk, so every capability impl inside them is invisible to this \
         ratchet. `crate_root_files` looks for src/lib.rs, src/main.rs, and \
         src/bin/*.rs; a crate whose manifest relocates its root needs that \
         function widened: {missing:?}"
    );
    assert!(
        crate_dirs.len() >= 20,
        "found only {} crate directories under crates/, so this assertion \
         checked almost nothing",
        crate_dirs.len()
    );
}

/// Prints the workspace's current inventory as the JSON body the baseline
/// carries, so a human updating the baseline reads what changed instead of
/// hand-transcribing a hundred records.
///
/// This test is `#[ignore]`d, so the enforced run never invokes it, and
/// `scripts/check-capability-impl-inventory.sh --print` is the only caller. It
/// prints; it does not write. A human still has to read the difference and paste
/// it into `ratchet/capability-impl-inventory.json`, which is the review this
/// ratchet exists to force.
#[test]
#[ignore = "prints the current inventory for a human updating the baseline; never enforces anything"]
fn print_current_inventory() {
    let workspace = workspace_root();
    let scan = scan_workspace();
    let registry = parse_detector_registry(&workspace);

    let impls: Vec<serde_json::Value> = scan
        .records
        .iter()
        .map(|(r, count)| {
            serde_json::json!({
                "file": r.file,
                "capability": r.capability,
                "trait": r.trait_name,
                "type": r.type_name,
                "gating": r.gating,
                "impl_count": count,
            })
        })
        .collect();

    let mut registry_traits: Vec<String> = registry
        .iter()
        .flat_map(|c| c.traits.iter().cloned())
        .collect();
    registry_traits.sort();

    let body = serde_json::json!({
        "capability_trait_impls": impls,
        "capability_registry_traits": registry_traits,
        "shipped_feature_graph_lists": read_gate_lists(&workspace),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&body).expect("the inventory serialises")
    );
}

// ---------------------------------------------------------------------------
// Fixtures — behavioural proof that the comparison is load-bearing
// ---------------------------------------------------------------------------

/// Builds a record for the fixtures.
fn fixture_record(type_name: &str, gating: &str) -> ImplRecord {
    ImplRecord {
        file: "crates/scp-platform/src/fixture.rs".to_owned(),
        capability: "key custody (§17.8)".to_owned(),
        trait_name: "KeyCustody".to_owned(),
        type_name: type_name.to_owned(),
        gating: gating.to_owned(),
    }
}

/// A baseline of three records, for the fixtures to perturb.
fn fixture_baseline() -> BTreeMap<ImplRecord, usize> {
    [
        (fixture_record("FileKeyCustody", "production"), 1),
        (fixture_record("SqliteKeyCustody", "production"), 1),
        (fixture_record("InMemoryKeyCustody", "testing-gated"), 1),
    ]
    .into_iter()
    .collect()
}

/// An unchanged workspace matches its baseline, and a new impl fails.
#[test]
fn fixture_added_impl_is_rejected() {
    assert!(
        compare(&fixture_baseline(), &fixture_baseline()).is_empty(),
        "a scan identical to the baseline must report no difference"
    );

    let mut scanned = fixture_baseline();
    scanned.insert(fixture_record("PlausibleKeyCustody", "production"), 1);

    let diff = compare(&scanned, &fixture_baseline());
    assert_eq!(diff.added.len(), 1, "the new impl must be reported");
    assert_eq!(
        diff.added[0].0.type_name, "PlausibleKeyCustody",
        "the failure must name the impl that appeared"
    );
    assert!(diff.removed.is_empty());
}

/// The failure this ratchet exists for: one impl deleted and another added in
/// the same commit. A ratchet that recorded a count would see three before and
/// three after, and pass. This one reports the identity of both.
#[test]
fn fixture_count_preserving_swap_is_rejected() {
    let mut scanned = fixture_baseline();
    scanned.remove(&fixture_record("SqliteKeyCustody", "production"));
    scanned.insert(fixture_record("PlausibleKeyCustody", "production"), 1);

    assert_eq!(
        scanned.len(),
        fixture_baseline().len(),
        "the fixture must hold the cardinality constant, or it does not test the \
         swap a count-based ratchet misses"
    );

    let diff = compare(&scanned, &fixture_baseline());
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].0.type_name, "PlausibleKeyCustody");
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].0.type_name, "SqliteKeyCustody");
}

/// A deletion alone fails, and a `testing`-gated impl that loses its gate fails
/// even though the type, the trait, and the file all stayed the same.
#[test]
fn fixture_removal_and_gating_flip_are_rejected() {
    let mut deleted = fixture_baseline();
    deleted.remove(&fixture_record("InMemoryKeyCustody", "testing-gated"));
    let diff = compare(&deleted, &fixture_baseline());
    assert!(diff.added.is_empty());
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].0.type_name, "InMemoryKeyCustody");

    let mut flipped = fixture_baseline();
    flipped.remove(&fixture_record("InMemoryKeyCustody", "testing-gated"));
    flipped.insert(fixture_record("InMemoryKeyCustody", "production"), 1);
    let diff = compare(&flipped, &fixture_baseline());
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].0.gating, "production");
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].0.gating, "testing-gated");
}

/// Deleting one of two identical impls fails. Two impls that agree in every
/// recorded field are two impls; a set would hold one entry and report nothing
/// when one of them went away.
#[test]
fn fixture_deleting_one_of_two_identical_impls_is_rejected() {
    let mut baseline = fixture_baseline();
    baseline.insert(fixture_record("FileKeyCustody", "production"), 2);

    let scanned = fixture_baseline();
    let diff = compare(&scanned, &baseline);
    assert_eq!(diff.added.len(), 1, "the surviving single copy is reported");
    assert_eq!(diff.added[0].1, 1);
    assert_eq!(diff.removed.len(), 1, "the frozen pair is reported");
    assert_eq!(diff.removed[0].1, 2);
}

/// The `cfg` evaluator decides the `gating` field, so the fixtures pin the two
/// directions that field can lie in: a production-only arm must read
/// `production`, and a `testing`-gated arm must read `testing-gated`.
#[test]
fn fixture_cfg_evaluator_labels_gating_correctly() {
    let cases: &[(&str, Gating)] = &[
        ("test", Gating::TestingGated),
        ("feature = \"testing\"", Gating::TestingGated),
        ("any(test, feature = \"testing\")", Gating::TestingGated),
        ("all(feature = \"testing\", unix)", Gating::TestingGated),
        ("not(test)", Gating::Production),
        ("not(feature = \"testing\")", Gating::Production),
        ("unix", Gating::Production),
        ("feature = \"sqlite\"", Gating::Production),
        (
            "any(feature = \"testing\", feature = \"sqlite\")",
            Gating::Production,
        ),
        // A negated atom that is neither `test` nor `feature = "testing"`.
        // Cargo compiles each of these into an ordinary production build, so a
        // label of `testing-gated` would assert a compiler proof that does not
        // exist. An evaluator that binds every unknown atom to true reads all
        // four as `testing-gated`; the satisfiability criterion reads them as
        // production, which is what cargo does.
        ("not(target_arch = \"wasm32\")", Gating::Production),
        ("not(unix)", Gating::Production),
        ("not(windows)", Gating::Production),
        ("not(feature = \"sqlite\")", Gating::Production),
        (
            "all(unix, not(target_arch = \"wasm32\"))",
            Gating::Production,
        ),
        // Two free atoms of opposite polarity. This predicate is false when both
        // are true and false when both are false, so trying only those two
        // extremes labels it `testing-gated`. It is true on Linux.
        ("all(unix, not(windows))", Gating::Production),
        // A tautology over one free atom stays production under every
        // assignment.
        ("any(unix, not(unix))", Gating::Production),
        // The `testing` atoms still decide the cases they govern, whatever free
        // atoms accompany them.
        (
            "all(feature = \"testing\", not(target_arch = \"wasm32\"))",
            Gating::TestingGated,
        ),
        ("all(test, unix)", Gating::TestingGated),
    ];
    for (predicate, expected) in cases {
        let tokens: proc_macro2::TokenStream = predicate.parse().expect("predicate parses");
        let holds = cfg_predicate_holds_in_production(tokens);
        let labelled = if holds {
            Gating::Production
        } else {
            Gating::TestingGated
        };
        assert!(
            labelled == *expected,
            "cfg({predicate}) was labelled {}, expected {}",
            labelled.label(),
            expected.label()
        );
    }
}

/// The type renderer keeps the generic arguments, so a blanket impl and a
/// concrete impl are two records, and it normalises every path to its final
/// segment so a `use` statement does not read as a swap.
#[test]
fn fixture_type_renderer_normalises_paths_and_keeps_generics() {
    let cases: &[(&str, &str)] = &[
        ("SqliteStorage", "SqliteStorage"),
        ("std::sync::Arc<T>", "Arc<T>"),
        ("crate::sqlite::SqliteStorage", "SqliteStorage"),
        (
            "EncryptingAdapter<crate::sqlite::SqliteStorage>",
            "EncryptingAdapter<SqliteStorage>",
        ),
        ("DualLayerResolver<R, D, C>", "DualLayerResolver<R, D, C>"),
        ("KeyResolverDidResolver<'_>", "KeyResolverDidResolver<'_>"),
        ("&mut FileKeyCustody", "&mut FileKeyCustody"),
    ];
    for (src, expected) in cases {
        let ty: syn::Type = syn::parse_str(src).expect("the fixture type parses");
        assert_eq!(&render_type(&ty), expected, "rendering `{src}`");
    }

    let blanket: syn::Type = syn::parse_str("std::sync::Arc<T>").expect("parses");
    let concrete: syn::Type = syn::parse_str("SqliteStorage").expect("parses");
    assert_ne!(
        render_type(&blanket),
        render_type(&concrete),
        "a blanket impl and a concrete impl must not collide into one record"
    );
}

/// The `use`-alias scanner recognises a rename of a registered trait and ignores
/// the `use` forms that rename nothing.
#[test]
fn fixture_use_alias_scanner_recognises_only_renames() {
    let registered: BTreeSet<String> = std::iter::once("KeyCustody".to_owned()).collect();

    let renames = [
        "use crate::custody::KeyCustody as Vault;",
        "use crate::custody::{Other, KeyCustody as Vault};",
        "use a::b::c::KeyCustody as V;",
    ];
    for src in renames {
        let parsed = syn::parse_file(src).expect("fixture parses");
        let mut offenders = Vec::new();
        for item in &parsed.items {
            if let syn::Item::Use(u) = item {
                collect_renames_in_use_tree(&u.tree, &registered, "fixture.rs", &mut offenders);
            }
        }
        assert_eq!(offenders.len(), 1, "the scanner must flag `{src}`");
    }

    let no_rename = [
        "use crate::custody::KeyCustody;",
        "use crate::custody::*;",
        "use crate::custody::OtherTrait as Vault;",
        "use crate::custody::KeyCustody as KeyCustody;",
        // `_` is not an identifier an `impl` can be written against, so this
        // form brings the trait's methods into scope without enabling the impl
        // this check refuses.
        "use crate::custody::KeyCustody as _;",
    ];
    for src in no_rename {
        let parsed = syn::parse_file(src).expect("fixture parses");
        let mut offenders = Vec::new();
        for item in &parsed.items {
            if let syn::Item::Use(u) = item {
                collect_renames_in_use_tree(&u.tree, &registered, "fixture.rs", &mut offenders);
            }
        }
        assert!(offenders.is_empty(), "the scanner must not flag `{src}`");
    }
}

/// The gate-list reader must return the gate's evaluated lists, not an empty
/// map. An empty read would compare equal to an emptied baseline and certify
/// nothing.
#[test]
fn fixture_gate_list_reader_returns_the_evaluated_lists() {
    let workspace = workspace_root();
    let lists = read_gate_lists(&workspace);

    let allowlist = lists
        .get("permitted_allowlist")
        .expect("the gate emits its permitted-production allowlist");
    assert!(
        allowlist.len() >= 30,
        "read {} entries from the permitted-production allowlist; the clean tree \
         carries 36",
        allowlist.len()
    );
    assert!(
        allowlist.iter().all(|e| e.contains('/')),
        "every allowlist entry names a crate and a feature: {allowlist:?}"
    );

    let controls = lists
        .get("nullifier_control_features")
        .expect("the gate emits its nullifier control features");
    assert!(
        controls.iter().any(|e| e == "scp-platform/testing"),
        "`scp-platform/testing` is the control that gates the three platform \
         nullifier doubles, so its absence means the reader broke: {controls:?}"
    );

    let artifacts = lists
        .get("artifacts")
        .expect("the gate emits its shipped-artifact list");
    assert!(
        artifacts.len() >= 5,
        "the gate checks five shipped artifacts and emitted {}: {artifacts:?}",
        artifacts.len()
    );

    let crates = lists
        .get("permitted_crates")
        .expect("the gate emits its permitted-production crate allowlist");
    assert!(
        crates.iter().any(|e| e == "scp-relay"),
        "`scp-relay` declares no `[features]` table, so it contributes no \
         feature edge and the crate list is the only place the gate can admit \
         it; its absence means the reader broke: {crates:?}"
    );
    assert!(
        crates.iter().all(|e| !e.contains('/')),
        "every permitted-crate entry names a crate and nothing else: {crates:?}"
    );
}
