#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Structural gates for SCP-310's acceptance criteria on key-state input
//! positions and on the verdict classifier's match.
//!
//! `key_state_params`: `03-identity.md` §3.10.10 makes `ResolvedState` the
//! only key state a verification decision reads, because only the verdict
//! classifier constructs it. The criterion is that no external input position
//! names `KeyState`, `KeyStateView` or `ReplayedState`: no position through
//! which code outside the defining item can hand a gated type into a crate's
//! API. The gate parses every Rust file under `crates/*/src` and
//! `crates/scp-ffi/*/src` with `syn` and reports one hit per such position.
//!
//! Indicators, not the criterion: the positions the walk reads are
//! - each parameter of a `pub fn`, a `pub` inherent method, a method of a
//!   `pub trait`, a `pub` foreign fn, and every method of every trait impl;
//! - in the return type of each of those fns, a `Fn(..)`-trait or `fn(..)`
//!   argument and a `&mut` reference;
//! - each field of a `pub struct`, `pub union`, and each variant of a
//!   `pub enum`, and the type of a `pub static`;
//! - each macro invocation, in any position, whose tokens name a gated type
//!   outside an enum-variant path (no expansion).
//!
//! A type names a gated type through references, `Option`, slices, `Arc`,
//! tuples, `impl` and `dyn` bounds, qualified paths, generic bounds, defaults
//! and where clauses, `Self` inside a gated type's own struct or impl, an
//! associated type an impl binds to one, and `type` aliases or `use .. as`
//! renames of one. Items in nested scopes (fn bodies, `const _: () = {..}`,
//! inline modules) are walked like top-level items.
//!
//! The exemptions in [`EXEMPTIONS`] are each pinned to a file path, and each
//! must match at least once, so a moved or deleted exempt item fails the gate
//! instead of leaving a stale exemption.
//!
//! `verdict_match_has_no_wildcard`: SCP-310 requires `classify` to match
//! `EntryVerdict` exhaustively under `#![deny(clippy::wildcard_enum_match_arm)]`
//! in `crates/scp-kel/src/verdict.rs`. Clippy enforces the lint only while the
//! attribute stands and nothing lowers it, so this check asserts the inner
//! attribute, that no attribute in the file allows, warns or expects the lint
//! or a group or tool that contains it, and that every `match` over
//! `EntryVerdict` names every variant and has no arm that matches every value.
//!
//! Each check first runs on must-fail inputs and asserts their hit counts, so a
//! pass on the real tree means the tree is clean, not that the checker is blind.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

/// The key-state types no external input position may take
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

/// The index in [`EXEMPTIONS`] of the exemption whose name (for `Type` and
/// `Fn`) or path (for `File`) is `key`.
fn exemption(key: &str) -> usize {
    EXEMPTIONS
        .iter()
        .position(|e| match e {
            Exemption::Type { name, .. } | Exemption::Fn { name, .. } => *name == key,
            Exemption::File { path } => *path == key,
        })
        .unwrap_or_else(|| panic!("no exemption keyed {key}"))
}

/// An input position whose type names a gated type.
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

const fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// True when any path inside the visited node ends in a name from `names`.
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

    fn visit_type_macro(&mut self, m: &'ast syn::TypeMacro) {
        self.found |= tokens_name(&m.mac.tokens, self.names);
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

/// True when a return type lets the caller hand a gated type back in: an
/// argument of a `Fn(..)`-trait bound or a `fn(..)` pointer, or a `&mut`
/// reference to a type that names one.
struct ReturnInput<'a> {
    names: &'a BTreeSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for ReturnInput<'_> {
    fn visit_parenthesized_generic_arguments(
        &mut self,
        args: &'ast syn::ParenthesizedGenericArguments,
    ) {
        self.found |= args.inputs.iter().any(|t| type_names(t, self.names));
        syn::visit::visit_return_type(self, &args.output);
    }

    fn visit_type_bare_fn(&mut self, f: &'ast syn::TypeBareFn) {
        self.found |= f.inputs.iter().any(|a| type_names(&a.ty, self.names));
        syn::visit::visit_return_type(self, &f.output);
    }

    fn visit_type_reference(&mut self, r: &'ast syn::TypeReference) {
        if r.mutability.is_some() && type_names(&r.elem, self.names) {
            self.found = true;
        }
        syn::visit::visit_type_reference(self, r);
    }
}

fn return_takes_input(ret: &syn::ReturnType, names: &BTreeSet<String>) -> bool {
    let mut f = ReturnInput {
        names,
        found: false,
    };
    f.visit_return_type(ret);
    f.found
}

/// True when `tokens` name a gated type: an ident from `names` that is not the
/// variant segment of an enum path such as `EventKind::KeyState`.
fn tokens_name(tokens: &TokenStream, names: &BTreeSet<String>) -> bool {
    let toks: Vec<TokenTree> = tokens.clone().into_iter().collect();
    toks.iter().enumerate().any(|(i, t)| match t {
        TokenTree::Group(g) => tokens_name(&g.stream(), names),
        TokenTree::Ident(id) if names.contains(&id.to_string()) => {
            let colon =
                |k: usize| matches!(toks.get(k), Some(TokenTree::Punct(p)) if p.as_char() == ':');
            let variant = i >= 3
                && colon(i - 1)
                && colon(i - 2)
                && matches!(&toks[i - 3], TokenTree::Ident(p)
                    if p.to_string().starts_with(char::is_uppercase)
                        && !names.contains(&p.to_string()));
            !variant
        }
        _ => false,
    })
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

/// `names` plus every associated type `impl` binds to a type that names a
/// gated type, so `Self::S` in its methods reads as gated.
fn with_assoc_types(names: &BTreeSet<String>, i: &syn::ItemImpl) -> BTreeSet<String> {
    let mut out = names.clone();
    loop {
        let before = out.len();
        for ii in &i.items {
            if let syn::ImplItem::Type(t) = ii
                && type_names(&t.ty, &out)
            {
                out.insert(t.ident.to_string());
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

fn pat_label(pat: &syn::Pat) -> String {
    match pat {
        syn::Pat::Ident(i) => i.ident.to_string(),
        _ => "_".to_owned(),
    }
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
        if return_takes_input(&sig.output, &names) {
            self.record(
                format!("{owner}fn {} return input", sig.ident),
                exempt.clone(),
            );
        }
    }

    fn check_fields<'f>(
        &mut self,
        owner: &str,
        fields: impl Iterator<Item = &'f syn::Field>,
        names: &BTreeSet<String>,
        exempt: &[usize],
    ) {
        for (i, field) in fields.enumerate() {
            if type_names(&field.ty, names) {
                let label = field
                    .ident
                    .as_ref()
                    .map_or_else(|| i.to_string(), ToString::to_string);
                self.record(format!("{owner} field {label}"), exempt.to_vec());
            }
        }
    }

    /// `gated` plus the bounded generics, plus `Self` where the item itself
    /// carries a gated name.
    fn item_names(&self, ident: &syn::Ident, generics: &syn::Generics) -> BTreeSet<String> {
        let mut names = with_bounded_params(self.gated, &[generics]);
        if self.gated.contains(&ident.to_string()) {
            names.insert("Self".to_owned());
        }
        names
    }

    fn check_macro(&mut self, mac: &syn::Macro) {
        if tokens_name(&mac.tokens, self.gated) {
            let name = mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            let ex = self.file_exemptions();
            self.record(format!("macro {name}!"), ex);
        }
    }
}

impl<'ast> Visit<'ast> for Walker<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if is_pub(&f.vis) {
            let ex = self.file_exemptions();
            let gated = self.gated;
            self.check_sig("", &f.sig, &[], gated, ex);
        }
        syn::visit::visit_item_fn(self, f);
    }

    fn visit_foreign_item_fn(&mut self, f: &'ast syn::ForeignItemFn) {
        if is_pub(&f.vis) {
            let ex = self.file_exemptions();
            let gated = self.gated;
            self.check_sig("extern ", &f.sig, &[], gated, ex);
        }
        syn::visit::visit_foreign_item_fn(self, f);
    }

    fn visit_item_struct(&mut self, s: &'ast syn::ItemStruct) {
        let name = s.ident.to_string();
        let pin = self.type_pin(&name);
        if let Some(i) = pin {
            self.scan.matched[i] = true;
        }
        if is_pub(&s.vis) {
            let names = self.item_names(&s.ident, &s.generics);
            let mut exempt = self.file_exemptions();
            exempt.extend(pin);
            self.check_fields(&format!("struct {name}"), s.fields.iter(), &names, &exempt);
        }
        syn::visit::visit_item_struct(self, s);
    }

    fn visit_item_enum(&mut self, e: &'ast syn::ItemEnum) {
        if is_pub(&e.vis) {
            let names = self.item_names(&e.ident, &e.generics);
            let exempt = self.file_exemptions();
            for v in &e.variants {
                self.check_fields(
                    &format!("enum {}::{}", e.ident, v.ident),
                    v.fields.iter(),
                    &names,
                    &exempt,
                );
            }
        }
        syn::visit::visit_item_enum(self, e);
    }

    fn visit_item_union(&mut self, u: &'ast syn::ItemUnion) {
        if is_pub(&u.vis) {
            let names = self.item_names(&u.ident, &u.generics);
            let exempt = self.file_exemptions();
            self.check_fields(
                &format!("union {}", u.ident),
                u.fields.named.iter(),
                &names,
                &exempt,
            );
        }
        syn::visit::visit_item_union(self, u);
    }

    fn visit_item_static(&mut self, s: &'ast syn::ItemStatic) {
        if is_pub(&s.vis) && type_names(&s.ty, self.gated) {
            let ex = self.file_exemptions();
            self.record(format!("static {}", s.ident), ex);
        }
        syn::visit::visit_item_static(self, s);
    }

    fn visit_item_trait(&mut self, t: &'ast syn::ItemTrait) {
        if is_pub(&t.vis) {
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
        syn::visit::visit_item_trait(self, t);
    }

    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let self_name = last_ident(&i.self_ty).unwrap_or_default();
        let mut names = with_assoc_types(self.gated, i);
        if self.gated.contains(&self_name) {
            names.insert("Self".to_owned());
        }
        // A trait impl's methods are reachable wherever the trait and the
        // type are, so each counts; an inherent impl's count when `pub`, and
        // only an inherent impl in the pinned file is covered by the pin.
        let (pin, owner) = match &i.trait_ {
            None => (self.type_pin(&self_name), format!("impl {self_name}::")),
            Some((_, path, _)) => {
                let tr = path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                (None, format!("impl {tr} for {self_name}::"))
            }
        };
        for ii in &i.items {
            let syn::ImplItem::Fn(m) = ii else { continue };
            if i.trait_.is_none() && !is_pub(&m.vis) {
                continue;
            }
            let mut ex = self.file_exemptions();
            ex.extend(pin);
            self.check_sig(&owner, &m.sig, &[&i.generics], &names, ex);
        }
        syn::visit::visit_item_impl(self, i);
    }

    /// Every macro invocation in any position: item, statement, expression,
    /// pattern, type, impl, trait or extern. An expression macro can expand to
    /// a block whose `impl` is visible crate-wide, so no position is exempt.
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        self.check_macro(m);
    }
}

enum AliasOf {
    Type(syn::Type),
    Ident(String),
}

/// Every `type A = ..` alias and `use .. as A` rename in a file, at any depth.
struct Aliases(Vec<(String, AliasOf)>);

impl<'ast> Visit<'ast> for Aliases {
    fn visit_item_type(&mut self, t: &'ast syn::ItemType) {
        self.0
            .push((t.ident.to_string(), AliasOf::Type((*t.ty).clone())));
        syn::visit::visit_item_type(self, t);
    }

    fn visit_use_tree(&mut self, tree: &'ast syn::UseTree) {
        match tree {
            syn::UseTree::Path(p) => self.visit_use_tree(&p.tree),
            syn::UseTree::Rename(r) => {
                self.0
                    .push((r.rename.to_string(), AliasOf::Ident(r.ident.to_string())));
            }
            syn::UseTree::Group(g) => g.items.iter().for_each(|t| self.visit_use_tree(t)),
            syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
        }
    }
}

/// The gated names plus every alias that reaches one, across all `files`.
fn gated_names(files: &[(String, syn::File)]) -> BTreeSet<String> {
    let mut aliases = Aliases(Vec::new());
    for (_, f) in files {
        aliases.visit_file(f);
    }
    let mut names: BTreeSet<String> = GATED.iter().map(|s| (*s).to_owned()).collect();
    loop {
        let before = names.len();
        for (alias, of) in &aliases.0 {
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
        .visit_file(file);
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

/// Must-fail and must-pass inputs at non-exempt paths, each with the number of
/// unexempted hits the gate must report.
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
    // A parameter bounded through one declared after it needs a second pass.
    (OTHER, "pub fn c<T: Into<U>, U: Into<KeyState>>(t: T) {}", 1),
    (OTHER, "pub fn i(a: impl Into<KeyState>) {}", 1),
    (OTHER, "pub fn d(a: &dyn AsRef<ReplayedState>) {}", 1),
    (OTHER, "pub fn q(a: <KeyState as X>::Y) {}", 1),
    (OTHER, "pub fn n(a: (&[Option<Arc<KeyState>>], u8)) {}", 1),
    // Struct generics: a bound and a default.
    (OTHER, "pub struct S<T: Into<KeyState>> { t: T }", 1),
    (OTHER, "pub struct S<T = KeyState> { t: T }", 1),
    // One hit per position, not per path.
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
    // Aliases and renames of a gated name, in any order and in a use group.
    (OTHER, "type K = Arc<KeyState>; pub fn f(k: K) {}", 1),
    (OTHER, "type B = A; type A = KeyState; pub fn f(b: B) {}", 1),
    (OTHER, "use scp_did::KeyState as K; pub fn f(k: &K) {}", 1),
    (OTHER, "use scp_did::{KeyState as K}; pub fn f(k: &K) {}", 1),
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
    // Positions outside pub fn parameters and pub struct fields.
    (OTHER, "pub enum E { A(KeyState) }", 1),
    (OTHER, "pub enum E { A { k: Box<ReplayedState> }, B }", 1),
    (
        OTHER,
        "pub union U { k: std::mem::ManuallyDrop<KeyState> }",
        1,
    ),
    (OTHER, "pub static S: Mutex<Option<KeyState>> = todo!();", 1),
    (OTHER, "extern \"C\" { pub fn f(k: *const KeyState); }", 1),
    (OTHER, "impl X for Foo { fn f(k: &KeyState) {} }", 1),
    (
        OTHER,
        "impl From<KeyState> for F { fn from(k: KeyState) -> Self { todo!() } }",
        1,
    ),
    (
        OTHER,
        "impl TryFrom<KeyState> for F { type Error = (); \
         fn try_from(k: KeyState) -> Result<Self, ()> { todo!() } }",
        1,
    ),
    (
        OTHER,
        "pub trait T { type S; fn m(s: Self::S); } \
         impl T for X { type S = KeyState; fn m(s: Self::S) {} }",
        1,
    ),
    (OTHER, "pub fn mk() -> impl FnOnce(KeyState) { |_| () }", 1),
    (
        OTHER,
        "pub fn mk() -> Box<dyn Fn(u8, &ReplayedState)> { todo!() }",
        1,
    ),
    (OTHER, "pub fn mk() -> fn(KeyState) { todo!() }", 1),
    (
        OTHER,
        "impl Foo { pub fn m(&mut self) -> &mut KeyState { todo!() } }",
        1,
    ),
    (
        OTHER,
        "fn outer() { impl Foo { pub fn take(k: KeyState) {} } }",
        1,
    ),
    (
        OTHER,
        "impl A { fn f() { impl Foo { pub fn take(k: KeyState) {} } } }",
        1,
    ),
    (
        OTHER,
        "const _: () = { impl Foo { pub fn take(k: KeyState) {} } };",
        1,
    ),
    (OTHER, "m! { pub fn f(k: KeyState) {} }", 1),
    (
        OTHER,
        "fn f() { m! { pub fn g(k: scp_did::KeyState) {} } }",
        1,
    ),
    // A type macro in a parameter is two findings: the parameter and the macro.
    (OTHER, "pub fn f(k: m!(KeyState)) {}", 2),
    (
        OTHER,
        "fn f() { let _ = m!({ impl Foo { pub fn t(k: KeyState) {} } }); }",
        1,
    ),
    (OTHER, "fn f(x: u8) { if let m!(KeyState) = x {} }", 1),
    // Not hits: crate-visible or private items, non-pub inherent methods,
    // outputs, enum variants that share a gated name.
    (OTHER, "pub(crate) fn h(k: &KeyState) {}", 0),
    (OTHER, "struct Q { k: KeyState }", 0),
    (OTHER, "enum Q { A(KeyState) }", 0),
    (OTHER, "impl Foo { fn f(k: &KeyState) {} }", 0),
    (OTHER, "pub fn r() -> KeyState { todo!() }", 0),
    (OTHER, "pub fn r(&self) -> &KeyState { todo!() }", 0),
    (OTHER, "pub fn r() -> impl Fn() -> KeyState { todo!() }", 0),
    (
        OTHER,
        "pub fn e(k: EventKind) { let _ = EventKind::KeyState; \
         assert!(matches!(k, EventKind::KeyState)); }",
        0,
    ),
    (OTHER, "m! { Kind::KeyState }", 0),
];

/// An input at an exempt path.
struct ExemptFixture {
    rel: &'static str,
    src: &'static str,
    /// Unexempted hits the gate must report.
    unexempted: usize,
    /// Per exemption key (see [`exemption`]): the hits it must cover.
    exempted: &'static [(&'static str, usize)],
}

const fn ef(
    rel: &'static str,
    src: &'static str,
    unexempted: usize,
    exempted: &'static [(&'static str, usize)],
) -> ExemptFixture {
    ExemptFixture {
        rel,
        src,
        unexempted,
        exempted,
    }
}

const EXEMPT_FIXTURES: &[ExemptFixture] = &[
    ef(
        "crates/scp-did/src/key_state.rs",
        "pub struct KeyState { k: Box<Self> } impl KeyState { pub fn f(&self, o: &KeyState) {} }",
        0,
        &[("KeyState", 3)],
    ),
    ef(
        "crates/scp-did/src/key_state.rs",
        "pub struct KeyState { a: u8 } impl From<ReplayedState> for KeyState { \
         fn from(r: ReplayedState) -> Self { todo!() } }",
        1,
        &[("KeyState", 0)],
    ),
    ef(
        "crates/scp-kel/src/validate/replay.rs",
        "pub struct ReplayedState { key_state: KeyState } pub fn x(r: &ReplayedState) {}",
        0,
        &[
            ("ReplayedState", 1),
            ("crates/scp-kel/src/validate/replay.rs", 2),
        ],
    ),
    ef(
        "crates/scp-kel/src/verdict.rs",
        "pub struct ResolvedState { replayed: ReplayedState } m! { KeyState }",
        0,
        &[("crates/scp-kel/src/verdict.rs", 2)],
    ),
    ef(
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "pub fn compute_key_continuity_fingerprint(a: &ReplayedState, b: &ReplayedState) {} \
         pub fn other(a: &ReplayedState) {}",
        1,
        &[("compute_key_continuity_fingerprint", 2)],
    ),
];

fn assert_fixtures() {
    for (rel, src, want) in FIXTURES {
        let s = scan_fixture(rel, src);
        let got = s.unexempted();
        assert_eq!(got.len(), *want, "{rel}: {src}: {got:#?}");
    }
    for f in EXEMPT_FIXTURES {
        let (rel, src) = (f.rel, f.src);
        let s = scan_fixture(rel, src);
        let got = s.unexempted();
        assert_eq!(got.len(), f.unexempted, "{rel}: {src}: {got:#?}");
        for (key, n) in f.exempted {
            assert_eq!(
                s.exempted[exemption(key)],
                *n,
                "{rel}: {src}: exemption {key}: {:#?}",
                s.hits
            );
        }
    }
}

/// The stale-exemption assertion fails on a tree in which a pin's struct or a
/// file's exempt hit is missing.
fn assert_stale_exemption_detected() {
    let pin = exemption("KeyState");
    let verdict = exemption("crates/scp-kel/src/verdict.rs");
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
        "these input positions take key state that no resolution accepted; \
         take a `ResolvedState` instead (`03-identity.md` §3.10.10):\n{}",
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

/// The variant names of `EntryVerdict`, read from its definition.
fn entry_verdict_variants() -> BTreeSet<String> {
    let path = workspace_root().join("crates/scp-kel/src/validate/entry.rs");
    let src = std::fs::read_to_string(&path).expect("crates/scp-kel/src/validate/entry.rs reads");
    let file = syn::parse_file(&src).expect("entry.rs parses");
    let variants: BTreeSet<String> = file
        .items
        .iter()
        .find_map(|i| match i {
            syn::Item::Enum(e) if e.ident == "EntryVerdict" => {
                Some(e.variants.iter().map(|v| v.ident.to_string()).collect())
            }
            _ => None,
        })
        .expect("entry.rs defines EntryVerdict");
    assert!(variants.len() >= 2, "{variants:?}");
    variants
}

/// The `EntryVerdict` variants a pattern names, by an `EntryVerdict::V` path
/// or by a bare variant name a glob import brought in; `named_enum` is set
/// when the pattern spells `EntryVerdict`.
struct VariantsIn<'a> {
    variants: &'a BTreeSet<String>,
    named: BTreeSet<String>,
    named_enum: bool,
}

impl<'ast> Visit<'ast> for VariantsIn<'_> {
    fn visit_path(&mut self, p: &'ast syn::Path) {
        self.named_enum |= p.segments.iter().any(|s| s.ident == "EntryVerdict");
        if let Some(last) = p.segments.last() {
            let id = last.ident.to_string();
            if self.variants.contains(&id) {
                self.named.insert(id);
            }
        }
        syn::visit::visit_path(self, p);
    }

    fn visit_pat_ident(&mut self, i: &'ast syn::PatIdent) {
        let id = i.ident.to_string();
        if i.subpat.is_none() && self.variants.contains(&id) {
            self.named.insert(id);
        }
        syn::visit::visit_pat_ident(self, i);
    }
}

/// True when `pat` matches every value: `_`, a binding that is not a
/// variant name, `x @ <catch-all>`, or an or-pattern, parenthesis or
/// reference around one.
fn is_catch_all(pat: &syn::Pat, variants: &BTreeSet<String>) -> bool {
    match pat {
        syn::Pat::Wild(_) => true,
        syn::Pat::Or(o) => o.cases.iter().any(|c| is_catch_all(c, variants)),
        syn::Pat::Paren(p) => is_catch_all(&p.pat, variants),
        syn::Pat::Reference(r) => is_catch_all(&r.pat, variants),
        syn::Pat::Ident(i) => match &i.subpat {
            Some((_, sub)) => is_catch_all(sub, variants),
            None => !variants.contains(&i.ident.to_string()),
        },
        _ => false,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct VerdictCheck {
    denies: bool,
    relaxations: usize,
    wildcard_arms: usize,
    incomplete_matches: usize,
}

#[derive(Debug, Default)]
struct MatchFindings {
    /// Matches whose arms name `EntryVerdict` or one of its variants.
    matches: usize,
    /// Catch-all arms across those matches.
    wildcard: usize,
    /// Those matches that name fewer than every variant.
    incomplete: usize,
}

/// Catch-all arms, and matches that name fewer than every variant, over every
/// `match` whose arms name an `EntryVerdict` variant.
fn match_findings(file: &syn::File, variants: &BTreeSet<String>) -> MatchFindings {
    struct V<'a> {
        variants: &'a BTreeSet<String>,
        out: MatchFindings,
    }
    impl<'ast> Visit<'ast> for V<'_> {
        fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
            let mut seen = VariantsIn {
                variants: self.variants,
                named: BTreeSet::new(),
                named_enum: false,
            };
            for a in &m.arms {
                seen.visit_pat(&a.pat);
            }
            if seen.named_enum || !seen.named.is_empty() {
                self.out.matches += 1;
                self.out.wildcard += m
                    .arms
                    .iter()
                    .filter(|a| is_catch_all(&a.pat, self.variants))
                    .count();
                if seen.named != *self.variants {
                    self.out.incomplete += 1;
                }
            }
            syn::visit::visit_expr_match(self, m);
        }
    }
    let mut v = V {
        variants,
        out: MatchFindings::default(),
    };
    v.visit_file(file);
    v.out
}

fn path_is(p: &syn::Path, segs: &[&str]) -> bool {
    p.segments.len() == segs.len() && p.segments.iter().zip(segs).all(|(s, w)| s.ident == w)
}

/// True when `meta` is `deny(..)` or `forbid(..)` listing the lint.
fn meta_denies_lint(meta: &syn::Meta) -> bool {
    let syn::Meta::List(list) = meta else {
        return false;
    };
    (list.path.is_ident("deny") || list.path.is_ident("forbid"))
        && list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|ms| ms.iter().any(|m| path_is(m.path(), &["clippy", LINT])))
}

/// `syn::File::attrs` holds only the file's inner attributes, so an outer
/// `#[deny(..)]` on one item never counts.
fn file_denies_lint(file: &syn::File) -> bool {
    file.attrs.iter().any(|a| meta_denies_lint(&a.meta))
}

/// True when `meta` lowers the lint below deny: `allow`, `warn` or `expect`
/// naming the lint, `clippy::restriction` (the group holding it), or the bare
/// `clippy` tool; or a `cfg_attr` whose attributes do. A list that does not
/// parse counts when its text names the lint or the group.
fn meta_relaxes(meta: &syn::Meta) -> bool {
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let text_names = |_| {
        let text = list.tokens.to_string();
        text.contains(LINT) || text.contains("restriction")
    };
    let parsed = list.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    );
    if list.path.is_ident("cfg_attr") {
        return parsed.map_or_else(text_names, |ms| ms.iter().skip(1).any(meta_relaxes));
    }
    if !["allow", "warn", "expect"]
        .iter()
        .any(|n| list.path.is_ident(n))
    {
        return false;
    }
    parsed.map_or_else(text_names, |ms| {
        ms.iter().any(|m| {
            let p = m.path();
            p.is_ident("clippy")
                || path_is(p, &["clippy", LINT])
                || path_is(p, &["clippy", "restriction"])
        })
    })
}

fn lint_relaxations(file: &syn::File) -> usize {
    struct V(usize);
    impl<'ast> Visit<'ast> for V {
        fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
            self.0 += usize::from(meta_relaxes(&a.meta));
        }
    }
    let mut v = V(0);
    v.visit_file(file);
    v.0
}

fn check_verdict_source(src: &str, variants: &BTreeSet<String>) -> VerdictCheck {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("source parses: {e}: {src}"));
    let m = match_findings(&file, variants);
    VerdictCheck {
        denies: file_denies_lint(&file),
        relaxations: lint_relaxations(&file),
        wildcard_arms: m.wildcard,
        incomplete_matches: m.incomplete,
    }
}

const CLEAN: VerdictCheck = VerdictCheck {
    denies: true,
    relaxations: 0,
    wildcard_arms: 0,
    incomplete_matches: 0,
};

/// Must-fail and must-pass sources for the verdict check, each with the
/// result it must produce.
fn verdict_cases() -> Vec<(String, VerdictCheck)> {
    const DENY: &str = "#![deny(clippy::wildcard_enum_match_arm)]\n";
    const FULL: &str = "EntryVerdict::NoInception => (), \
         EntryVerdict::InceptionInvalid { .. } => (), EntryVerdict::Valid { .. } => ()";
    let clean = CLEAN;
    let wild = |n| VerdictCheck {
        wildcard_arms: n,
        ..clean
    };
    let partial = VerdictCheck {
        wildcard_arms: 1,
        incomplete_matches: 1,
        ..clean
    };
    let relaxed = |n| VerdictCheck {
        relaxations: n,
        ..clean
    };
    let m = |arms: &str| format!("{DENY}fn f(v: EntryVerdict) {{ match v {{ {arms} }} }}");
    vec![
        // Catch-all arms beside a complete set of variants.
        (m(&format!("{FULL}, _ => ()")), wild(1)),
        (m(&format!("{FULL}, other => ()")), wild(1)),
        (m(&format!("{FULL}, x @ _ => ()")), wild(1)),
        (m(&format!("{FULL}, (_) => ()")), wild(1)),
        (m(&format!("{FULL}, &_ => ()")), wild(1)),
        (m("EntryVerdict::NoInception | _ => ()"), partial),
        (m("EntryVerdict::NoInception => (), _ => ()"), partial),
        // Through a glob import, with no `EntryVerdict` path in any arm.
        (
            format!(
                "{DENY}use EntryVerdict::*; fn f(v: EntryVerdict) {{ \
                 match v {{ Valid {{ .. }} => (), _ => () }} }}"
            ),
            partial,
        ),
        (
            format!(
                "{DENY}use EntryVerdict::*; fn f(v: EntryVerdict) {{ match v {{ \
                 Valid {{ .. }} => (), NoInception => (), InceptionInvalid {{ .. }} => () }} }}"
            ),
            clean,
        ),
        (m(FULL), clean),
        // A wildcard over another enum is outside the check.
        (
            format!("{DENY}fn f(v: Other) {{ match v {{ Other::A => (), _ => () }} }}"),
            clean,
        ),
        // The deny: missing, outer on one fn, forbid in its place.
        ("fn f() {}".to_owned(), VerdictCheck::default()),
        (
            "#[deny(clippy::wildcard_enum_match_arm)] fn f() {}".to_owned(),
            VerdictCheck::default(),
        ),
        (
            "#![forbid(clippy::wildcard_enum_match_arm)] fn f() {}".to_owned(),
            clean,
        ),
        // Every attribute that lowers the lint.
        (
            "#![warn(clippy::wildcard_enum_match_arm)]\nfn f() {}".to_owned(),
            VerdictCheck {
                relaxations: 1,
                ..VerdictCheck::default()
            },
        ),
        (
            format!("{DENY}#[allow(clippy::wildcard_enum_match_arm)] fn f() {{}}"),
            relaxed(1),
        ),
        (
            format!("{DENY}#[expect(clippy::wildcard_enum_match_arm)] fn f() {{}}"),
            relaxed(1),
        ),
        (
            format!("{DENY}#[cfg_attr(test, allow(clippy::wildcard_enum_match_arm))] fn f() {{}}"),
            relaxed(1),
        ),
        (
            format!("{DENY}#[allow(clippy::restriction)] fn f() {{}}"),
            relaxed(1),
        ),
        (
            format!("{DENY}#![allow(clippy::restriction)]\nfn f() {{}}"),
            relaxed(1),
        ),
        (format!("{DENY}#[allow(clippy)] fn f() {{}}"), relaxed(1)),
        (
            format!("{DENY}#[allow(dead_code, clippy::all)] fn f() {{}}"),
            clean,
        ),
    ]
}

#[test]
fn verdict_match_has_no_wildcard() {
    let variants = entry_verdict_variants();
    for (src, want) in &verdict_cases() {
        assert_eq!(&check_verdict_source(src, &variants), want, "{src}");
    }

    let path = workspace_root().join("crates/scp-kel/src/verdict.rs");
    let src = std::fs::read_to_string(&path).expect("crates/scp-kel/src/verdict.rs is readable");
    let file = syn::parse_file(&src).expect("verdict.rs parses");
    let seen = match_findings(&file, &variants).matches;
    assert!(
        seen > 0,
        "verdict.rs no longer matches EntryVerdict, so this check reads nothing"
    );
    let got = check_verdict_source(&src, &variants);
    println!("verdict_match_has_no_wildcard: {seen} EntryVerdict matches, {got:?}");
    assert_eq!(got, CLEAN, "crates/scp-kel/src/verdict.rs");
}
