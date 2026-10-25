#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Structural gates for SCP-310's acceptance criteria on key-state parameters
//! and on the verdict classifier's match.
//!
//! `key_state_params`: `03-identity.md` §3.10.10 makes `ResolvedState` the
//! only key state a verification decision reads, because only the verdict
//! classifier constructs it. A `pub fn`, a method of a `pub trait`, or a field
//! of a `pub struct` that takes `KeyState`, `KeyStateView` or `ReplayedState`
//! would let a caller hand in key state no resolution accepted. This gate
//! parses every Rust file under `crates/*/src` and `crates/scp-ffi/*/src` with
//! `syn` and reports one hit per parameter or field whose type names a gated
//! type, through references, `Option`, slices, `Arc`, tuples, `impl` and `dyn`
//! bounds, generic bounds and where clauses, `Self` inside a gated type's own
//! impl, and type aliases or `use` renames of a gated name. The exemptions in
//! [`EXEMPTIONS`] are each pinned to a file path, and each must match at least
//! once, so a moved or deleted exempt item fails the gate instead of leaving a
//! stale exemption.
//!
//! `verdict_match_has_no_wildcard`: SCP-310 requires `classify` to match
//! `EntryVerdict` exhaustively under `#![deny(clippy::wildcard_enum_match_arm)]`
//! in `crates/scp-kel/src/verdict.rs`. Clippy enforces the lint only while the
//! attribute stands, so this check asserts the attribute, that nothing in the
//! file relaxes the lint, and that no `match` over `EntryVerdict` in the file
//! has a catch-all arm.
//!
//! Each check first runs on must-fail inputs and asserts their hit counts, so a
//! pass on the real tree means the tree is clean, not that the checker is blind.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// The key-state types no public parameter or field may take
/// (`03-identity.md` §3.10.10).
const GATED: [&str; 3] = ["KeyState", "KeyStateView", "ReplayedState"];

/// One pinned exemption. Paths are relative to the workspace root.
#[derive(Debug, Clone, Copy)]
enum Exemption {
    /// The defining struct of `name` at `path` and its inherent impls in the
    /// same file. It matches when the file defines a struct of that name.
    Type {
        path: &'static str,
        name: &'static str,
    },
    /// Every item of the file. It matches when it exempts at least one hit.
    File { path: &'static str },
    /// The fn of that name in the file. It matches when it exempts at least
    /// one hit.
    Fn {
        path: &'static str,
        name: &'static str,
    },
}

/// SCP-310's exemption list. SCP-314 adds the `KeyStateView` pin in the change
/// that creates that type in `crates/scp-ffi/common`.
const EXEMPTIONS: &[Exemption] = &[
    Exemption::Type {
        path: "crates/scp-did/src/key_state.rs",
        name: "KeyState",
    },
    Exemption::Type {
        path: "crates/scp-kel/src/validate/replay.rs",
        name: "ReplayedState",
    },
    Exemption::File {
        path: "crates/scp-kel/src/validate/replay.rs",
    },
    Exemption::File {
        path: "crates/scp-kel/src/verdict.rs",
    },
    Exemption::Fn {
        path: "crates/scp-protocol/src/crypto/key_continuity.rs",
        name: "compute_key_continuity_fingerprint",
    },
];

/// A parameter or field whose type names a gated type.
#[derive(Debug)]
struct Hit {
    path: String,
    site: String,
    /// Indices into the exemption list of every exemption that covers it.
    exempted_by: Vec<usize>,
}

#[derive(Debug)]
struct Scan {
    hits: Vec<Hit>,
    /// Per exemption: the defining struct was found (for `Type`) or at least
    /// one hit was exempted (for `File` and `Fn`).
    matched: Vec<bool>,
    /// Per exemption: the number of hits it exempted.
    exempted: Vec<usize>,
}

impl Scan {
    fn unexempted(&self) -> Vec<&Hit> {
        self.hits
            .iter()
            .filter(|h| h.exempted_by.is_empty())
            .collect()
    }
}

/// True when any path inside `node` ends in a name from `names`.
struct Finder<'a> {
    names: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for Finder<'_> {
    fn visit_path(&mut self, p: &'ast syn::Path) {
        if p.segments
            .last()
            .is_some_and(|s| self.names.contains(&s.ident.to_string()))
        {
            self.found = true;
        }
        syn::visit::visit_path(self, p);
    }
}

fn type_names(ty: &syn::Type, names: &BTreeSet<String>) -> bool {
    let mut f = Finder {
        names,
        found: false,
    };
    f.visit_type(ty);
    f.found
}

fn bounds_name(
    bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
    names: &BTreeSet<String>,
) -> bool {
    let mut f = Finder {
        names,
        found: false,
    };
    for b in bounds {
        f.visit_type_param_bound(b);
    }
    f.found
}

/// `names` plus every type parameter of `generics` whose bound, default, or
/// where-clause predicate names a gated type, directly or through another
/// such parameter.
fn with_bounded_params(names: &BTreeSet<String>, generics: &[&syn::Generics]) -> BTreeSet<String> {
    let mut out = names.clone();
    let params: Vec<&syn::TypeParam> = generics.iter().flat_map(|g| g.type_params()).collect();
    loop {
        let before = out.len();
        for tp in &params {
            let id = tp.ident.to_string();
            if !out.contains(&id)
                && (bounds_name(&tp.bounds, &out)
                    || tp.default.as_ref().is_some_and(|d| type_names(d, &out)))
            {
                out.insert(id);
            }
        }
        for g in generics {
            let Some(wc) = &g.where_clause else { continue };
            for pred in &wc.predicates {
                let syn::WherePredicate::Type(pt) = pred else {
                    continue;
                };
                if !bounds_name(&pt.bounds, &out) {
                    continue;
                }
                for tp in &params {
                    let one: BTreeSet<String> = [tp.ident.to_string()].into();
                    if type_names(&pt.bounded_ty, &one) {
                        out.insert(tp.ident.to_string());
                    }
                }
            }
        }
        if out.len() == before {
            return out;
        }
    }
}

fn last_ident(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(tp) = ty else { return None };
    tp.path.segments.last().map(|s| s.ident.to_string())
}

struct Walker<'a> {
    rel: &'a str,
    /// The gated names plus every alias of one.
    gated: &'a BTreeSet<String>,
    scan: &'a mut Scan,
}

impl Walker<'_> {
    fn file_exemptions(&self) -> Vec<usize> {
        EXEMPTIONS
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e, Exemption::File { path } if *path == self.rel))
            .map(|(i, _)| i)
            .collect()
    }

    fn fn_exemptions(&self, ident: &syn::Ident) -> Vec<usize> {
        EXEMPTIONS
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                matches!(e, Exemption::Fn { path, name } if *path == self.rel && ident == name)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn type_pin(&self, name: &str) -> Option<usize> {
        EXEMPTIONS.iter().position(
            |e| matches!(e, Exemption::Type { path, name: n } if *path == self.rel && *n == name),
        )
    }

    fn record(&mut self, site: String, exempted_by: Vec<usize>) {
        for &i in &exempted_by {
            self.scan.exempted[i] += 1;
            if !matches!(EXEMPTIONS[i], Exemption::Type { .. }) {
                self.scan.matched[i] = true;
            }
        }
        self.scan.hits.push(Hit {
            path: self.rel.to_owned(),
            site,
            exempted_by,
        });
    }

    fn check_sig(
        &mut self,
        owner: &str,
        sig: &syn::Signature,
        outer: &[&syn::Generics],
        names: &BTreeSet<String>,
        mut exempt: Vec<usize>,
    ) {
        let mut generics: Vec<&syn::Generics> = outer.to_vec();
        generics.push(&sig.generics);
        let names = with_bounded_params(names, &generics);
        exempt.extend(self.fn_exemptions(&sig.ident));
        for (i, arg) in sig.inputs.iter().enumerate() {
            let (ty, label) = match arg {
                syn::FnArg::Receiver(r) => (&*r.ty, "self".to_owned()),
                syn::FnArg::Typed(pt) => (&*pt.ty, format!("#{i} `{}`", pat_label(&pt.pat))),
            };
            if type_names(ty, &names) {
                self.record(
                    format!("{owner}fn {} param {label}", sig.ident),
                    exempt.clone(),
                );
            }
        }
    }

    fn walk(&mut self, items: &[syn::Item]) {
        for item in items {
            match item {
                syn::Item::Fn(f) if matches!(f.vis, syn::Visibility::Public(_)) => {
                    let ex = self.file_exemptions();
                    let gated = self.gated;
                    self.check_sig("", &f.sig, &[], gated, ex);
                }
                syn::Item::Struct(s) => self.walk_struct(s),
                syn::Item::Trait(t) if matches!(t.vis, syn::Visibility::Public(_)) => {
                    for ti in &t.items {
                        if let syn::TraitItem::Fn(m) = ti {
                            let ex = self.file_exemptions();
                            let gated = self.gated;
                            self.check_sig(
                                &format!("trait {}::", t.ident),
                                &m.sig,
                                &[&t.generics],
                                gated,
                                ex,
                            );
                        }
                    }
                }
                syn::Item::Impl(i) if i.trait_.is_none() => self.walk_impl(i),
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        self.walk(inner);
                    }
                }
                _ => {}
            }
        }
    }

    fn walk_struct(&mut self, s: &syn::ItemStruct) {
        let name = s.ident.to_string();
        let pin = self.type_pin(&name);
        if let Some(i) = pin {
            self.scan.matched[i] = true;
        }
        if !matches!(s.vis, syn::Visibility::Public(_)) {
            return;
        }
        let mut names = with_bounded_params(self.gated, &[&s.generics]);
        if self.gated.contains(&name) {
            names.insert("Self".to_owned());
        }
        let mut exempt = self.file_exemptions();
        exempt.extend(pin);
        for (i, field) in s.fields.iter().enumerate() {
            if type_names(&field.ty, &names) {
                let label = field
                    .ident
                    .as_ref()
                    .map_or_else(|| i.to_string(), ToString::to_string);
                self.record(format!("struct {name} field {label}"), exempt.clone());
            }
        }
    }

    fn walk_impl(&mut self, i: &syn::ItemImpl) {
        let self_name = last_ident(&i.self_ty).unwrap_or_default();
        let mut names = self.gated.clone();
        if self.gated.contains(&self_name) {
            names.insert("Self".to_owned());
        }
        let pin = self.type_pin(&self_name);
        for ii in &i.items {
            let syn::ImplItem::Fn(m) = ii else { continue };
            if !matches!(m.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let mut ex = self.file_exemptions();
            ex.extend(pin);
            self.check_sig(
                &format!("impl {self_name}::"),
                &m.sig,
                &[&i.generics],
                &names,
                ex,
            );
        }
    }
}

fn pat_label(pat: &syn::Pat) -> String {
    match pat {
        syn::Pat::Ident(i) => i.ident.to_string(),
        _ => "_".to_owned(),
    }
}

/// Every `type A = ..` alias and `use .. as A` rename in `items`, as
/// `(alias, Some(target type))` or `(alias, None)` with the renamed ident.
fn collect_aliases(items: &[syn::Item], out: &mut Vec<(String, AliasOf)>) {
    for item in items {
        match item {
            syn::Item::Type(t) => out.push((t.ident.to_string(), AliasOf::Type((*t.ty).clone()))),
            syn::Item::Use(u) => use_renames(&u.tree, out),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_aliases(inner, out);
                }
            }
            _ => {}
        }
    }
}

enum AliasOf {
    Type(syn::Type),
    Ident(String),
}

fn use_renames(tree: &syn::UseTree, out: &mut Vec<(String, AliasOf)>) {
    match tree {
        syn::UseTree::Path(p) => use_renames(&p.tree, out),
        syn::UseTree::Rename(r) => {
            out.push((r.rename.to_string(), AliasOf::Ident(r.ident.to_string())));
        }
        syn::UseTree::Group(g) => g.items.iter().for_each(|t| use_renames(t, out)),
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
    }
}

/// The gated names plus every alias that reaches one, across all `files`.
fn gated_names(files: &[(String, syn::File)]) -> BTreeSet<String> {
    let mut aliases = Vec::new();
    for (_, f) in files {
        collect_aliases(&f.items, &mut aliases);
    }
    let mut names: BTreeSet<String> = GATED.iter().map(|s| (*s).to_owned()).collect();
    loop {
        let before = names.len();
        for (alias, of) in &aliases {
            let reaches = match of {
                AliasOf::Type(ty) => type_names(ty, &names),
                AliasOf::Ident(id) => names.contains(id),
            };
            if reaches {
                names.insert(alias.clone());
            }
        }
        if names.len() == before {
            return names;
        }
    }
}

fn scan(files: &[(String, syn::File)]) -> Scan {
    let gated = gated_names(files);
    let mut out = Scan {
        hits: Vec::new(),
        matched: vec![false; EXEMPTIONS.len()],
        exempted: vec![0; EXEMPTIONS.len()],
    };
    for (rel, file) in files {
        Walker {
            rel,
            gated: &gated,
            scan: &mut out,
        }
        .walk(&file.items);
    }
    out
}

fn scan_fixture(rel: &str, src: &str) -> Scan {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("fixture parses: {e}: {src}"));
    scan(&[(rel.to_owned(), file)])
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("scp-testing sits at crates/scp-testing")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{} is not readable: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry reads").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `src` directory under `crates/*/` and `crates/scp-ffi/*/`.
fn source_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for parent in [root.join("crates"), root.join("crates/scp-ffi")] {
        let entries = std::fs::read_dir(&parent)
            .unwrap_or_else(|e| panic!("{} is not readable: {e}", parent.display()));
        for entry in entries {
            let src = entry.expect("directory entry reads").path().join("src");
            if src.is_dir() {
                roots.push(src);
            }
        }
    }
    roots.sort();
    roots
}

fn workspace_files() -> Vec<(String, syn::File)> {
    let root = workspace_root();
    let mut paths = Vec::new();
    for src in source_roots(&root) {
        rust_files(&src, &mut paths);
    }
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("source sits under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("{rel} is not readable: {e}"));
            let file =
                syn::parse_file(&src).unwrap_or_else(|e| panic!("{rel} does not parse: {e}"));
            (rel, file)
        })
        .collect()
}

const OTHER: &str = "crates/scp-other/src/lib.rs";

/// Must-fail and must-pass inputs, each with the number of unexempted hits
/// the gate must report.
const FIXTURES: &[(&str, &str, usize)] = &[
    // The story's two must-fail inputs.
    (OTHER, "pub fn f(k: Option<&scp_did::KeyState>) {}", 1),
    (OTHER, "pub fn g(r: &[ReplayedState]) {}", 1),
    // Wrappers, trait bounds, and generic bounds.
    (OTHER, "pub struct S { k: Arc<KeyStateView> }", 1),
    (OTHER, "pub trait T { fn m(&self, k: &KeyState); }", 1),
    (OTHER, "pub fn b<T: Into<ReplayedState>>(t: T) {}", 1),
    (
        OTHER,
        "pub fn w<T>(t: Vec<T>) where T: Into<KeyState> {}",
        1,
    ),
    (OTHER, "pub fn c<U: Into<KeyState>, T: Into<U>>(t: T) {}", 1),
    (OTHER, "pub fn i(a: impl Into<KeyState>) {}", 1),
    (OTHER, "pub fn d(a: &dyn AsRef<ReplayedState>) {}", 1),
    (OTHER, "pub fn q(a: <KeyState as X>::Y) {}", 1),
    (OTHER, "pub fn n(a: (&[Option<Arc<KeyState>>], u8)) {}", 1),
    // One hit per parameter or field, not per path.
    (OTHER, "pub fn p(a: Vec<(KeyState, ReplayedState)>) {}", 1),
    (
        OTHER,
        "pub fn two(a: &KeyState, b: &ReplayedState, c: u8) {}",
        2,
    ),
    // Private fields of a pub struct, tuple fields, inline modules, methods.
    (OTHER, "pub struct P { k: KeyState, n: u8 }", 1),
    (OTHER, "pub struct T(pub KeyState, u8);", 1),
    (OTHER, "mod m { pub fn f(k: &KeyState) {} }", 1),
    (OTHER, "impl Foo { pub fn f(&self, k: &KeyState) {} }", 1),
    (
        OTHER,
        "impl<T: Into<KeyState>> Foo<T> { pub fn f(t: T) {} }",
        1,
    ),
    (OTHER, "pub trait G<T: Into<KeyState>> { fn m(t: T); }", 1),
    // Aliases and renames of a gated name.
    (OTHER, "type K = Arc<KeyState>; pub fn f(k: K) {}", 1),
    (OTHER, "use scp_did::KeyState as K; pub fn f(k: &K) {}", 1),
    // A gated name declared at another path is walked like any other type.
    (OTHER, "pub struct KeyState { k: ReplayedState }", 1),
    (OTHER, "pub struct KeyState { next: Option<Box<Self>> }", 1),
    (OTHER, "impl KeyState { pub fn f(&self, o: u8) {} }", 1),
    (
        "crates/scp-did/src/other.rs",
        "pub struct KeyState { k: ReplayedState }",
        1,
    ),
    (
        "crates/scp-protocol/src/crypto/other.rs",
        "pub fn compute_key_continuity_fingerprint(a: &ReplayedState, b: &ReplayedState) {}",
        2,
    ),
    // Not hits: crate-visible or private items, trait impls, returns, enum
    // variants that share a gated name.
    (OTHER, "pub(crate) fn h(k: &KeyState) {}", 0),
    (OTHER, "struct Q { k: KeyState }", 0),
    (OTHER, "impl Foo { fn f(k: &KeyState) {} }", 0),
    (OTHER, "impl X for Foo { fn f(k: &KeyState) {} }", 0),
    (OTHER, "pub fn r() -> KeyState { todo!() }", 0),
    (
        OTHER,
        "pub fn e(k: EventKind) { let _ = EventKind::KeyState; }",
        0,
    ),
    // Exempt at the pinned paths.
    (
        "crates/scp-did/src/key_state.rs",
        "pub struct KeyState { k: Box<Self> } impl KeyState { pub fn f(&self, o: &KeyState) {} }",
        0,
    ),
    (
        "crates/scp-kel/src/validate/replay.rs",
        "pub struct ReplayedState { key_state: KeyState } pub fn x(r: &ReplayedState) {}",
        0,
    ),
    (
        "crates/scp-kel/src/verdict.rs",
        "pub struct ResolvedState { replayed: ReplayedState }",
        0,
    ),
    (
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "pub fn compute_key_continuity_fingerprint(a: &ReplayedState, b: &ReplayedState) {} \
         pub fn other(a: &ReplayedState) {}",
        1,
    ),
];

fn assert_fixtures() {
    for (rel, src, want) in FIXTURES {
        let s = scan_fixture(rel, src);
        let got = s.unexempted();
        assert_eq!(got.len(), *want, "{rel}: {src}: {got:#?}");
    }
}

/// The stale-exemption assertion fails on a tree in which a pin's struct or a
/// file's exempt hit is missing.
fn assert_stale_exemption_detected() {
    let pin = EXEMPTIONS
        .iter()
        .position(|e| matches!(e, Exemption::Type { name, .. } if *name == "KeyState"))
        .expect("the KeyState pin is listed");
    let verdict = EXEMPTIONS
        .iter()
        .position(
            |e| matches!(e, Exemption::File { path } if *path == "crates/scp-kel/src/verdict.rs"),
        )
        .expect("the verdict.rs exemption is listed");
    let s = scan_fixture("crates/scp-did/src/key_state.rs", "pub struct Other;");
    assert!(
        !s.matched[pin],
        "a KeyState pin with no defining struct reads as matched"
    );
    let s = scan_fixture(
        "crates/scp-kel/src/verdict.rs",
        "pub struct ResolvedState { n: u8 }",
    );
    assert!(
        !s.matched[verdict],
        "a file exemption that exempts nothing reads as matched"
    );
    let s = scan_fixture(
        "crates/scp-did/src/key_state.rs",
        "pub struct KeyState { a: u8 }",
    );
    assert!(s.matched[pin], "the KeyState pin did not match its struct");
}

#[test]
fn key_state_params() {
    assert_fixtures();
    assert_stale_exemption_detected();

    let files = workspace_files();
    let s = scan(&files);
    println!("key_state_params: scanned {} files", files.len());
    for (i, e) in EXEMPTIONS.iter().enumerate() {
        println!(
            "  exemption {e:?}: matched={} exempted_hits={}",
            s.matched[i], s.exempted[i]
        );
    }
    for h in s.hits.iter().filter(|h| !h.exempted_by.is_empty()) {
        println!("  exempt: {}: {}", h.path, h.site);
    }
    let bad = s.unexempted();
    println!("  unexempted hits: {}", bad.len());
    for h in &bad {
        println!("  HIT: {}: {}", h.path, h.site);
    }

    let stale: Vec<_> = EXEMPTIONS
        .iter()
        .zip(&s.matched)
        .filter(|(_, m)| !**m)
        .map(|(e, _)| e)
        .collect();
    assert!(
        stale.is_empty(),
        "these exemptions match nothing, so each is stale: {stale:#?}"
    );
    assert!(
        bad.is_empty(),
        "these public parameters or fields take key state that no resolution \
         accepted; take a `ResolvedState` instead (`03-identity.md` §3.10.10):\n{}",
        bad.iter()
            .map(|h| format!("{}: {}", h.path, h.site))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ---------------------------------------------------------------------------
// verdict_match_has_no_wildcard
// ---------------------------------------------------------------------------

const LINT: &str = "wildcard_enum_match_arm";

fn names_entry_verdict(pat: &syn::Pat) -> bool {
    struct V(bool);
    impl<'ast> Visit<'ast> for V {
        fn visit_path(&mut self, p: &'ast syn::Path) {
            self.0 |= p.segments.iter().any(|s| s.ident == "EntryVerdict");
            syn::visit::visit_path(self, p);
        }
    }
    let mut v = V(false);
    v.visit_pat(pat);
    v.0
}

/// True when `pat`, or an alternative of it, matches every value: `_`, or a
/// binding with no subpattern (a lowercase name, so not a unit variant).
fn is_catch_all(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Wild(_) => true,
        syn::Pat::Or(o) => o.cases.iter().any(is_catch_all),
        syn::Pat::Paren(p) => is_catch_all(&p.pat),
        syn::Pat::Ident(i) => {
            i.subpat.is_none()
                && i.ident
                    .to_string()
                    .starts_with(|c: char| c.is_lowercase() || c == '_')
        }
        _ => false,
    }
}

/// One entry per catch-all arm of a `match` whose arms name `EntryVerdict`.
fn wildcard_arms(file: &syn::File) -> Vec<String> {
    struct V(Vec<String>);
    impl<'ast> Visit<'ast> for V {
        fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
            if m.arms.iter().any(|a| names_entry_verdict(&a.pat)) {
                for a in &m.arms {
                    if is_catch_all(&a.pat) {
                        self.0.push(pat_label(&a.pat));
                    }
                }
            }
            syn::visit::visit_expr_match(self, m);
        }
    }
    let mut v = V(Vec::new());
    v.visit_file(file);
    v.0
}

/// True when `attr` is `deny(..)` or `forbid(..)` listing the lint.
fn attr_denies_lint(attr: &syn::Attribute) -> bool {
    (attr.path().is_ident("deny") || attr.path().is_ident("forbid"))
        && attr
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|paths| {
                paths.iter().any(|p| {
                    p.segments.len() == 2
                        && p.segments[0].ident == "clippy"
                        && p.segments[1].ident == LINT
                })
            })
}

fn file_denies_lint(file: &syn::File) -> bool {
    file.attrs
        .iter()
        .any(|a| matches!(a.style, syn::AttrStyle::Inner(_)) && attr_denies_lint(a))
}

/// Every attribute anywhere in the file that could lower the lint below deny:
/// `allow`, `warn`, `expect`, or a `cfg_attr` that names the lint.
fn lint_relaxations(file: &syn::File) -> Vec<String> {
    struct V(Vec<String>);
    impl<'ast> Visit<'ast> for V {
        fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
            let relaxing = ["allow", "warn", "expect", "cfg_attr"]
                .iter()
                .any(|n| a.path().is_ident(n));
            if let (true, syn::Meta::List(list)) = (relaxing, &a.meta) {
                let text = list.tokens.to_string();
                if text.contains(LINT) {
                    self.0.push(text);
                }
            }
        }
    }
    let mut v = V(Vec::new());
    v.visit_file(file);
    v.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerdictCheck {
    denies: bool,
    relaxations: usize,
    wildcard_arms: usize,
}

fn check_verdict_source(src: &str) -> VerdictCheck {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("source parses: {e}"));
    VerdictCheck {
        denies: file_denies_lint(&file),
        relaxations: lint_relaxations(&file).len(),
        wildcard_arms: wildcard_arms(&file).len(),
    }
}

#[test]
fn verdict_match_has_no_wildcard() {
    const DENY: &str = "#![deny(clippy::wildcard_enum_match_arm)]\n";
    let clean = VerdictCheck {
        denies: true,
        relaxations: 0,
        wildcard_arms: 0,
    };
    let cases: &[(String, VerdictCheck)] = &[
        (
            format!(
                "{DENY}fn f(v: EntryVerdict) {{ match v {{ EntryVerdict::NoInception => (), _ => () }} }}"
            ),
            VerdictCheck {
                wildcard_arms: 1,
                ..clean
            },
        ),
        (
            format!(
                "{DENY}fn f(v: EntryVerdict) {{ match v {{ EntryVerdict::NoInception => (), other => () }} }}"
            ),
            VerdictCheck {
                wildcard_arms: 1,
                ..clean
            },
        ),
        (
            format!(
                "{DENY}fn f(v: EntryVerdict) {{ let _ = || match v {{ EntryVerdict::NoInception | _ => () }}; }}"
            ),
            VerdictCheck {
                wildcard_arms: 1,
                ..clean
            },
        ),
        (
            "fn f(v: EntryVerdict) { match v { EntryVerdict::NoInception => () } }".to_owned(),
            VerdictCheck {
                denies: false,
                ..clean
            },
        ),
        (
            "#![warn(clippy::wildcard_enum_match_arm)]\nfn f() {}".to_owned(),
            VerdictCheck {
                denies: false,
                relaxations: 1,
                ..clean
            },
        ),
        (
            format!("{DENY}#[allow(clippy::wildcard_enum_match_arm)]\nfn f() {{}}"),
            VerdictCheck {
                relaxations: 1,
                ..clean
            },
        ),
        (
            format!(
                "{DENY}fn f(v: EntryVerdict) {{ match v {{ EntryVerdict::NoInception => (), \
                 EntryVerdict::InceptionInvalid {{ .. }} => (), EntryVerdict::Valid {{ .. }} => () }} }}"
            ),
            clean,
        ),
        // A wildcard over another enum is outside the check.
        (
            format!("{DENY}fn f(v: Other) {{ match v {{ Other::A => (), _ => () }} }}"),
            clean,
        ),
    ];
    for (src, want) in cases {
        assert_eq!(&check_verdict_source(src), want, "{src}");
    }

    let path = workspace_root().join("crates/scp-kel/src/verdict.rs");
    let src = std::fs::read_to_string(&path).expect("crates/scp-kel/src/verdict.rs is readable");
    assert!(
        src.contains("EntryVerdict::"),
        "verdict.rs no longer matches EntryVerdict, so this check reads nothing"
    );
    let got = check_verdict_source(&src);
    println!("verdict_match_has_no_wildcard: {got:?}");
    assert_eq!(got, clean, "crates/scp-kel/src/verdict.rs");
}
