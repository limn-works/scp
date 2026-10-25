#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Structural gates for SCP-310's acceptance criteria on key-state mentions and
//! on the verdict classifier's match.
//!
//! `key_state_params`: `03-identity.md` §3.10.10 makes `ResolvedState` the
//! only key state a verification decision reads, because only the verdict
//! classifier constructs it. SCP-310 AC11 forbids any external input position
//! that names `KeyState`, `KeyStateView` or `ReplayedState`. The gate does not
//! reason about positions: it parses every Rust file under `crates/*/src` and
//! `crates/scp-ffi/*/src` with `syn` and counts every top-level item whose
//! full token stream (attributes, signature, body, macro arguments) names a
//! gated type. A name a `type` alias or a `use .. as` rename binds to one,
//! anywhere in the scanned tree, counts as a gated name. Items compiled only
//! under exactly `#[cfg(test)]` are out of scope: an item carrying it, a file
//! with `#![cfg(test)]`, and every file a `#[cfg(test)] mod` declaration loads
//! or whose module descends from one. Every other `cfg`, `cfg(any(test,
//! feature = "testing"))` included, stays in, because that code can ship. Every item that may
//! mention one is pinned in [`ALLOWLIST`] by file path and item, with the
//! reason the mention cannot hand in key state no resolution accepted, and
//! each entry must match a mention, so a moved or deleted item fails the gate
//! instead of leaving a stale entry.
//!
//! `verdict_match_has_no_wildcard`: SCP-310 AC8 requires `classify` to match
//! `EntryVerdict` with no wildcard arm. `crates/scp-kel/src/verdict.rs`
//! carries `#![forbid(clippy::wildcard_enum_match_arm)]`: clippy checks the
//! lint over the file, macro expansions included, and `forbid` makes any lower
//! `allow` or `expect` inside the file a compile error. The check asserts that
//! inner attribute.
//!
//! Each check first runs on must-fail inputs, so a pass on the real tree means
//! the tree is clean, not that the checker is blind.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use syn::visit::Visit;

/// The key-state types no external input position may take
/// (`03-identity.md` §3.10.10).
const GATED: [&str; 3] = ["KeyState", "KeyStateView", "ReplayedState"];

/// One approved mention: the top-level item `item` of the file at `path`
/// (relative to the workspace root), with the reason it cannot hand in key
/// state no resolution accepted. `item` is the label [`item_label`] gives.
#[derive(Debug, Clone, Copy)]
struct Allowed {
    path: &'static str,
    item: &'static str,
    reason: &'static str,
}

const fn allow(path: &'static str, item: &'static str, reason: &'static str) -> Allowed {
    Allowed { path, item, reason }
}

/// Every approved mention of a gated name. SCP-314 adds the `KeyStateView`
/// entries in the change that creates that type in `crates/scp-ffi/common`.
const ALLOWLIST: &[Allowed] = &[
    allow(
        "crates/scp-did/src/key_state.rs",
        "struct KeyState",
        "the defining item",
    ),
    allow(
        "crates/scp-did/src/lib.rs",
        "use",
        "re-exports the type from its defining crate; takes no input",
    ),
    allow(
        "crates/scp-kel/src/error.rs",
        "enum BodyField",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/error.rs",
        "impl Display for BodyField",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "use",
        "imports the type for `KeyStateSnapshot::into_key_state`; takes no input",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "enum EventKind",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "impl EventKind",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "fn signer_group_roles",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "impl KeyStateSnapshot",
        "`into_key_state` is `pub(crate)` and returns a `KeyState`; only `replay` and `key_state_at` call it, each on a `ValidatedChain`",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "impl EventPreimage",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/lib.rs",
        "use",
        "re-exports `ReplayedState` from its defining crate; takes no input",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn kind_byte",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn kind_from_byte",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "impl EncodedPreimage",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn read_snapshot",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn read_key_entry",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/validate/content.rs",
        "fn check_sentinels",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/validate/content.rs",
        "fn check_continuation_present",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "use",
        "imports the type `ReplayedState` holds; takes no input",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "struct ReplayedState",
        "the defining item; private fields, no public constructor",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "impl ReplayedState",
        "the defining impl; its accessors return state a `ValidatedChain` derived and take none in",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "fn replay",
        "returns a `ReplayedState` derived from the `ValidatedChain` it takes",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "fn key_state_at",
        "returns a `ReplayedState` derived from the `ValidatedChain` it takes",
    ),
    allow(
        "crates/scp-kel/src/validate.rs",
        "use",
        "re-exports `ReplayedState` within its defining crate; takes no input",
    ),
    allow(
        "crates/scp-kel/src/verdict.rs",
        "use",
        "imports the types `ResolvedState` wraps and returns; takes no input",
    ),
    allow(
        "crates/scp-kel/src/verdict.rs",
        "struct ResolvedState",
        "holds the replayed state of the chain resolution accepted, in a private field",
    ),
    allow(
        "crates/scp-kel/src/verdict.rs",
        "impl ResolvedState",
        "`key_state` returns the state of the chain resolution accepted; takes none in",
    ),
    allow(
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "use",
        "imports `ReplayedState` for the fingerprint; takes no input",
    ),
    allow(
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "impl PartyBlock",
        "private block builder over a `ReplayedState` for the §9.11 fingerprint, a display value that gates nothing",
    ),
    allow(
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "fn compute_key_continuity_fingerprint",
        "§9.11 fingerprint, a display value that gates nothing; it reads `ReplayedState` because one party is the device's own adopted log",
    ),
];

/// A top-level item whose tokens name a gated type.
#[derive(Debug)]
struct Mention {
    path: String,
    item: String,
    /// Index into [`ALLOWLIST`] of the entry that approves it.
    allowed_by: Option<usize>,
}

#[derive(Debug)]
struct Scan {
    mentions: Vec<Mention>,
    /// Per allowlist entry: the number of mentions it approved.
    approved: Vec<usize>,
}

impl Scan {
    fn unapproved(&self) -> Vec<&Mention> {
        self.mentions
            .iter()
            .filter(|m| m.allowed_by.is_none())
            .collect()
    }

    fn unapproved_in(&self, path: &str) -> usize {
        self.unapproved().iter().filter(|m| m.path == path).count()
    }
}

/// Every identifier in `tokens`, at any depth.
fn idents(tokens: TokenStream, out: &mut Vec<String>) {
    for t in tokens {
        match t {
            TokenTree::Ident(i) => out.push(i.to_string()),
            TokenTree::Group(g) => idents(g.stream(), out),
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

fn names_any(tokens: TokenStream, names: &BTreeSet<String>) -> bool {
    let mut ids = Vec::new();
    idents(tokens, &mut ids);
    ids.iter().any(|i| names.contains(i))
}

fn last_ident(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn type_label(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => last_ident(&p.path),
        other => {
            let mut ids = Vec::new();
            idents(other.to_token_stream(), &mut ids);
            ids.join(" ")
        }
    }
}

/// The allowlist label of a top-level item: its keyword and name, `impl T`,
/// `impl Tr for T`, `use`, `name!` for a macro invocation, or `verbatim`.
fn item_label(item: &syn::Item) -> String {
    match item {
        syn::Item::Const(i) => format!("const {}", i.ident),
        syn::Item::Enum(i) => format!("enum {}", i.ident),
        syn::Item::ExternCrate(i) => format!("extern crate {}", i.ident),
        syn::Item::Fn(i) => format!("fn {}", i.sig.ident),
        syn::Item::ForeignMod(_) => "extern".to_owned(),
        syn::Item::Impl(i) => match &i.trait_ {
            None => format!("impl {}", type_label(&i.self_ty)),
            Some((_, tr, _)) => format!("impl {} for {}", last_ident(tr), type_label(&i.self_ty)),
        },
        syn::Item::Macro(i) => i.ident.as_ref().map_or_else(
            || format!("{}!", last_ident(&i.mac.path)),
            |id| format!("macro {id}"),
        ),
        syn::Item::Mod(i) => format!("mod {}", i.ident),
        syn::Item::Static(i) => format!("static {}", i.ident),
        syn::Item::Struct(i) => format!("struct {}", i.ident),
        syn::Item::Trait(i) => format!("trait {}", i.ident),
        syn::Item::TraitAlias(i) => format!("trait {}", i.ident),
        syn::Item::Type(i) => format!("type {}", i.ident),
        syn::Item::Union(i) => format!("union {}", i.ident),
        syn::Item::Use(_) => "use".to_owned(),
        _ => "verbatim".to_owned(),
    }
}

/// Every `type A = ..` alias and `use .. as A` rename, at any depth.
struct Aliases(Vec<(String, TokenStream)>);

impl<'ast> Visit<'ast> for Aliases {
    fn visit_item_type(&mut self, t: &'ast syn::ItemType) {
        self.0.push((t.ident.to_string(), t.ty.to_token_stream()));
        syn::visit::visit_item_type(self, t);
    }

    fn visit_use_rename(&mut self, r: &'ast syn::UseRename) {
        self.0
            .push((r.rename.to_string(), r.ident.to_token_stream()));
    }
}

/// The gated names plus every alias or rename that reaches one, closed over
/// every file scanned together.
fn gated_names(files: &[(String, syn::File)]) -> BTreeSet<String> {
    let mut aliases = Aliases(Vec::new());
    for (_, f) in files {
        aliases.visit_file(f);
    }
    let mut names: BTreeSet<String> = GATED.iter().map(|s| (*s).to_owned()).collect();
    loop {
        let before = names.len();
        for (alias, of) in &aliases.0 {
            if names_any(of.clone(), &names) {
                names.insert(alias.clone());
            }
        }
        if names.len() == before {
            return names;
        }
    }
}

/// True for an attribute that is exactly `cfg(test)`. Any other predicate,
/// `cfg(any(test, feature = "testing"))` included, can hold in a shipped build.
fn is_cfg_test(attr: &syn::Attribute) -> bool {
    matches!(&attr.meta, syn::Meta::List(l) if l.path.is_ident("cfg") && l.tokens.to_string() == "test")
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::ExternCrate(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::ForeignMod(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::TraitAlias(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Union(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

fn test_only_item(item: &syn::Item) -> bool {
    item_attrs(item).iter().any(is_cfg_test)
}

/// `a/b/../c` → `a/c`.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

/// The file a `mod ident;` declared in `decl` loads, if it was scanned. A file
/// loaded through `#[path]`, a crate root, or a `mod.rs` keeps its children in
/// its own directory; any other file keeps them in the directory named by its
/// stem.
fn module_file(
    decl: &str,
    path_loaded: &BTreeSet<String>,
    m: &syn::ItemMod,
    scanned: &BTreeSet<&str>,
) -> Option<String> {
    let (dir, name) = decl.rsplit_once('/').unwrap_or(("", decl));
    let path_attr = m.attrs.iter().find_map(|a| match &a.meta {
        syn::Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => Some(s.value()),
            _ => None,
        },
        _ => None,
    });
    if let Some(p) = path_attr {
        let file = normalize(&format!("{dir}/{p}"));
        return scanned.contains(file.as_str()).then_some(file);
    }
    let mod_rs = matches!(name, "mod.rs" | "lib.rs" | "main.rs")
        || dir.ends_with("src/bin")
        || path_loaded.contains(decl);
    let base = if mod_rs {
        dir.to_owned()
    } else {
        format!("{dir}/{}", name.trim_end_matches(".rs"))
    };
    [
        format!("{base}/{}.rs", m.ident),
        format!("{base}/{}/mod.rs", m.ident),
    ]
    .into_iter()
    .find(|f| scanned.contains(f.as_str()))
}

/// Every scanned file compiled only under exactly `#[cfg(test)]`: a file with
/// an inner `#![cfg(test)]`, the file a `#[cfg(test)] mod x;` loads, and every
/// file a module declared in one of those loads. A declaration the walk cannot
/// resolve leaves its file in scope, so the gate over-counts and never hides.
fn test_only_files(files: &[(String, syn::File)]) -> BTreeSet<String> {
    let scanned: BTreeSet<&str> = files.iter().map(|(r, _)| r.as_str()).collect();
    let mut path_loaded = BTreeSet::new();
    for (rel, file) in files {
        for item in &file.items {
            if let syn::Item::Mod(m) = item
                && m.content.is_none()
                && m.attrs.iter().any(|a| a.path().is_ident("path"))
            {
                path_loaded.extend(module_file(rel, &BTreeSet::new(), m, &scanned));
            }
        }
    }
    let mut test_only: BTreeSet<String> = files
        .iter()
        .filter(|(_, f)| f.attrs.iter().any(is_cfg_test))
        .map(|(r, _)| r.clone())
        .collect();
    loop {
        let before = test_only.len();
        for (rel, file) in files {
            let whole = test_only.contains(rel);
            for item in &file.items {
                let syn::Item::Mod(m) = item else { continue };
                if m.content.is_none() && (whole || test_only_item(item)) {
                    test_only.extend(module_file(rel, &path_loaded, m, &scanned));
                }
            }
        }
        if test_only.len() == before {
            return test_only;
        }
    }
}

fn scan(files: &[(String, syn::File)]) -> Scan {
    let names = gated_names(files);
    let test_only = test_only_files(files);
    let mut out = Scan {
        mentions: Vec::new(),
        approved: vec![0; ALLOWLIST.len()],
    };
    for (rel, file) in files.iter().filter(|(r, _)| !test_only.contains(r)) {
        let inner: TokenStream = file.attrs.iter().map(ToTokens::to_token_stream).collect();
        let items = file
            .items
            .iter()
            .filter(|i| !test_only_item(i))
            .map(|i| (item_label(i), i.to_token_stream()));
        for (item, tokens) in std::iter::once(("#![..]".to_owned(), inner)).chain(items) {
            if !names_any(tokens, &names) {
                continue;
            }
            let allowed_by = ALLOWLIST
                .iter()
                .position(|a| a.path == rel && a.item == item);
            if let Some(i) = allowed_by {
                out.approved[i] += 1;
            }
            out.mentions.push(Mention {
                path: rel.clone(),
                item,
                allowed_by,
            });
        }
    }
    out
}

fn parse(rel: &str, src: &str) -> (String, syn::File) {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("fixture parses: {e}: {src}"));
    (rel.to_owned(), file)
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

/// Must-fail and must-pass inputs at a path with no allowlist entry, each with
/// the number of unapproved mentions the gate must report.
const FIXTURES: &[(&str, usize)] = &[
    // The story's two must-fail inputs.
    ("pub fn f(k: Option<&scp_did::KeyState>) {}", 1),
    ("pub fn g(r: &[ReplayedState]) {}", 1),
    ("pub struct S { k: Arc<KeyStateView> }", 1),
    // One mention per item, however many tokens name a gated type.
    (
        "pub fn p(a: Vec<(KeyState, ReplayedState)>, b: &KeyState) {}",
        1,
    ),
    (
        "pub fn a(k: &KeyState) {} pub fn b(r: &ReplayedState) {}",
        2,
    ),
    // Inputs the earlier position walk missed.
    ("pub enum E { A(KeyState) }", 1),
    ("pub union U { k: std::mem::ManuallyDrop<KeyState> }", 1),
    ("impl X for Foo { fn f(k: &KeyState) {} }", 1),
    (
        "impl From<KeyState> for F { fn from(k: KeyState) -> Self { todo!() } }",
        1,
    ),
    (
        "impl TryFrom<KeyState> for F { type Error = (); \
         fn try_from(k: KeyState) -> Result<Self, ()> { todo!() } }",
        1,
    ),
    (
        "pub trait T { type S; fn m(s: Self::S); } \
         impl T for X { type S = KeyState; fn m(s: Self::S) {} }",
        1,
    ),
    ("pub fn mk() -> impl FnOnce(KeyState) { |_| () }", 1),
    ("fn outer() { impl Foo { pub fn take(k: KeyState) {} } }", 1),
    (
        "const _: () = { impl Foo { pub fn take(k: KeyState) {} } };",
        1,
    ),
    ("m! { pub fn f(k: KeyState) {} }", 1),
    ("pub fn f<T>(t: T) where T: Into<KeyState> {}", 1),
    ("pub struct S<T = KeyState> { t: T }", 1),
    (
        "pub fn f<I: Iterator>(i: I) where I::Item: Into<KeyState> {}",
        1,
    ),
    ("type F = fn(KeyState); pub fn r() -> F { todo!() }", 2),
    ("pub fn r() -> Sender<KeyState> { todo!() }", 1),
    ("pub fn r() -> &'static Mutex<KeyState> { todo!() }", 1),
    ("pub const F: fn(KeyState) = |_| ();", 1),
    (
        "pub trait T { type S: Into<KeyState>; fn m(s: Self::S); }",
        1,
    ),
    ("impl T for X { fn m(s: Self::S) {} type S = KeyState; }", 1),
    ("fn f() { m!(Did::KeyState); }", 1),
    ("#[my_attr(KeyState)] pub fn f() {}", 1),
    (
        "fn f(v: Kind) { match v { m!(KeyState) => (), _ => () } }",
        1,
    ),
    ("#![doc = \"x\"] #![my_attr(KeyState)] fn f() {}", 1),
    // Private and crate-visible items count: the mention, not its visibility,
    // is what an approval covers.
    ("pub(crate) fn h(k: &KeyState) {}", 1),
    ("fn r() -> KeyState { todo!() }", 1),
    ("enum Kind { KeyState }", 1),
    // Aliases and renames in the same file, in either order.
    ("type K = Arc<KeyState>; pub fn f(k: K) {}", 2),
    ("type B = A; type A = KeyState; pub fn f(b: B) {}", 3),
    ("use scp_did::{KeyState as K}; pub fn f(k: &K) {}", 2),
    // Exactly `#[cfg(test)]` never ships; every other predicate can.
    ("#[cfg(test)] mod t { pub fn f(k: KeyState) {} }", 0),
    ("#[cfg(test)] pub fn f(k: KeyState) {}", 0),
    ("#![cfg(test)] pub fn f(k: KeyState) {}", 0),
    (
        "#[cfg(any(test, feature = \"testing\"))] mod t { pub fn f(k: KeyState) {} }",
        1,
    ),
    ("#[cfg(all(test))] pub fn f(k: KeyState) {}", 1),
    ("#[cfg(not(test))] pub fn f(k: KeyState) {}", 1),
    (
        "#[cfg_attr(test, allow(dead_code))] pub fn f(k: KeyState) {}",
        1,
    ),
    // A string or a doc comment is not a mention.
    (
        "/// A `KeyState` doc.\npub fn f() { let _ = \"KeyState\"; }",
        0,
    ),
    ("pub fn f(k: &KeyStates, s: KeyStateSnapshot) {}", 0),
];

/// A rename or alias declared in one file reaches a use in another.
fn assert_cross_file_aliases() {
    let cases: [(&str, &str); 3] = [
        ("pub use scp_did::KeyState as Ks;", "pub fn f(k: Ks) {}"),
        ("pub type A = Vec<KeyState>;", "pub fn f(a: &A) {}"),
        (
            "pub type A = KeyState; pub type B = Option<A>;",
            "pub fn f(b: B) {}",
        ),
    ];
    for (decl, user) in cases {
        let s = scan(&[
            parse("crates/scp-decl/src/lib.rs", decl),
            parse(OTHER, user),
        ]);
        assert_eq!(
            s.unapproved_in(OTHER),
            1,
            "{decl} / {user}: {:#?}",
            s.mentions
        );
    }
}

/// The file a `#[cfg(test)] mod x;` loads, and every file below it, is out of
/// scope; a file loaded by any other declaration is in.
fn assert_test_only_files() {
    let k = "pub fn f(k: KeyState) {}";
    let cases: &[(&[(&str, &str)], usize)] = &[
        (
            &[
                ("crates/x/src/lib.rs", "#[cfg(test)] mod tests;"),
                ("crates/x/src/tests.rs", k),
            ],
            0,
        ),
        (
            &[
                ("crates/x/src/lib.rs", "#[cfg(test)] mod tests;"),
                ("crates/x/src/tests/mod.rs", k),
            ],
            0,
        ),
        (
            &[
                ("crates/x/src/lib.rs", "#[cfg(test)] mod tests;"),
                ("crates/x/src/tests.rs", "mod deep;"),
                ("crates/x/src/tests/deep.rs", k),
            ],
            0,
        ),
        (
            &[
                ("crates/x/src/a.rs", "#[cfg(test)] mod t;"),
                ("crates/x/src/a/t.rs", k),
            ],
            0,
        ),
        (
            &[
                (
                    "crates/x/src/a.rs",
                    "#[cfg(test)] #[path = \"a_tests.rs\"] mod t;",
                ),
                ("crates/x/src/a_tests.rs", k),
            ],
            0,
        ),
        (
            &[
                ("crates/x/src/lib.rs", "mod tests;"),
                ("crates/x/src/tests.rs", k),
            ],
            1,
        ),
        // `a.rs` keeps its children in `a/`, so a sibling `t.rs` is another module.
        (
            &[
                ("crates/x/src/a.rs", "#[cfg(test)] mod t;"),
                ("crates/x/src/t.rs", k),
            ],
            1,
        ),
        (
            &[
                (
                    "crates/x/src/lib.rs",
                    "#[cfg(any(test, feature = \"testing\"))] mod tests;",
                ),
                ("crates/x/src/tests.rs", k),
            ],
            1,
        ),
    ];
    for (srcs, want) in cases {
        let files: Vec<_> = srcs.iter().map(|(r, s)| parse(r, s)).collect();
        let s = scan(&files);
        assert_eq!(s.unapproved().len(), *want, "{srcs:?}: {:#?}", s.mentions);
    }
}

fn assert_fixtures() {
    for (src, want) in FIXTURES {
        let s = scan(&[parse(OTHER, src)]);
        assert_eq!(s.unapproved().len(), *want, "{src}: {:#?}", s.mentions);
    }
    assert_cross_file_aliases();
    assert_test_only_files();
}

/// An approved item gives no unapproved mention, another item in the same
/// file does, and an entry whose item is missing reads as stale.
fn assert_allowlist_semantics() {
    let entry = ALLOWLIST
        .iter()
        .position(|a| a.path == "crates/scp-kel/src/verdict.rs" && a.item == "impl ResolvedState")
        .expect("verdict.rs `impl ResolvedState` is approved");
    let path = ALLOWLIST[entry].path;
    let s = scan(&[parse(
        path,
        "impl ResolvedState { pub const fn key_state(&self) -> &KeyState { todo!() } }",
    )]);
    assert_eq!(s.unapproved().len(), 0, "{:#?}", s.mentions);
    assert_eq!(s.approved[entry], 1);
    let s = scan(&[parse(
        path,
        "impl ResolvedState { pub const fn key_state(&self) -> &KeyState { todo!() } } \
         pub fn leak(k: KeyState) {}",
    )]);
    assert_eq!(s.unapproved().len(), 1, "{:#?}", s.mentions);
    assert_eq!(s.unapproved()[0].item, "fn leak");
    let s = scan(&[parse(path, "pub struct ResolvedState { n: u8 }")]);
    assert_eq!(
        s.approved[entry], 0,
        "a missing approved item reads as matched"
    );
}

#[test]
fn key_state_params() {
    let files = workspace_files();
    let s = scan(&files);
    println!(
        "key_state_params: scanned {} files, {} allowlist entries",
        files.len(),
        ALLOWLIST.len()
    );
    for (a, n) in ALLOWLIST.iter().zip(&s.approved) {
        println!("  approved x{n}: {} `{}`: {}", a.path, a.item, a.reason);
    }
    let bad = s.unapproved();
    println!("  unapproved mentions: {}", bad.len());
    for m in &bad {
        println!("  MENTION: {} `{}`", m.path, m.item);
    }

    assert_fixtures();
    assert_allowlist_semantics();

    let stale: Vec<_> = ALLOWLIST
        .iter()
        .zip(&s.approved)
        .filter(|(_, n)| **n == 0)
        .map(|(a, _)| a)
        .collect();
    assert!(
        stale.is_empty(),
        "these allowlist entries match no mention, so each is stale: {stale:#?}"
    );
    assert!(
        bad.is_empty(),
        "these items name key state that no resolution accepted; take a \
         `ResolvedState` instead (`03-identity.md` §3.10.10), or pin the item in \
         ALLOWLIST with the reason its mention cannot hand such state in:\n{}",
        bad.iter()
            .map(|m| format!("{} `{}`", m.path, m.item))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ---------------------------------------------------------------------------
// verdict_match_has_no_wildcard
// ---------------------------------------------------------------------------

/// True when the file's inner attributes forbid the lint. `syn::File::attrs`
/// holds only inner attributes, so a `#[forbid(..)]` on one item never counts.
fn file_forbids_wildcard(src: &str) -> bool {
    let file = syn::parse_file(src).unwrap_or_else(|e| panic!("source parses: {e}: {src}"));
    file.attrs.iter().any(|a| {
        let syn::Meta::List(list) = &a.meta else {
            return false;
        };
        list.path.is_ident("forbid")
            && list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|ps| {
                    ps.iter().any(|p| {
                        p.segments.len() == 2
                            && p.segments[0].ident == "clippy"
                            && p.segments[1].ident == "wildcard_enum_match_arm"
                    })
                })
    })
}

#[test]
fn verdict_match_has_no_wildcard() {
    let cases = [
        (
            "#![forbid(clippy::wildcard_enum_match_arm)]\nfn f() {}",
            true,
        ),
        (
            "#![forbid(unsafe_code, clippy::wildcard_enum_match_arm)]\nfn f() {}",
            true,
        ),
        (
            "#![deny(clippy::wildcard_enum_match_arm)]\nfn f() {}",
            false,
        ),
        (
            "#![warn(clippy::wildcard_enum_match_arm)]\nfn f() {}",
            false,
        ),
        (
            "#[forbid(clippy::wildcard_enum_match_arm)] fn f() {}",
            false,
        ),
        (
            "#![forbid(clippy::match_wildcard_for_single_variants)]\nfn f() {}",
            false,
        ),
        ("fn f() {}", false),
    ];
    for (src, want) in cases {
        assert_eq!(file_forbids_wildcard(src), want, "{src}");
    }
    let path = workspace_root().join("crates/scp-kel/src/verdict.rs");
    let src = std::fs::read_to_string(&path).expect("crates/scp-kel/src/verdict.rs is readable");
    assert!(
        file_forbids_wildcard(&src),
        "crates/scp-kel/src/verdict.rs must carry #![forbid(clippy::wildcard_enum_match_arm)]"
    );
}
