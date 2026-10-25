#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Structural gates for SCP-310's acceptance criteria on key-state mentions and
//! on the verdict classifier's match.
//!
//! `key_state_params`: `03-identity.md` §3.10.10 makes `ResolvedState` the
//! only key state a verification decision reads, because only the verdict
//! classifier constructs it. SCP-310 AC11 forbids any external input position
//! that names `KeyState`, `KeyStateView` or `ReplayedState`. The gate does not
//! reason about positions: it parses every Rust file under `crates/*/src` and
//! `crates/scp-ffi/*/src`, and every file a `#[path]` reaches from them, with
//! `syn`, and counts every top-level item whose full token stream (attributes,
//! signature, body, macro arguments) names a gated type. A raw identifier
//! names what it spells, and a name a `type` alias or a `use .. as` rename
//! binds to one, anywhere in the scanned tree, counts as a gated name. A
//! module declaration that loads no scanned file, and an `include!` whose
//! target is not a scanned file, count as items too: the scan cannot see the
//! code they bring in. `include_str!` and `include_bytes!` expand to a string
//! or byte literal, never tokens, so they never count.
//!
//! Items compiled only under exactly `#[cfg(test)]` are out of scope: an item
//! carrying it, a file with `#![cfg(test)]`, and a file every non-test-build
//! declaration of which sits in such a file, with `cfg_attr(test, path = ..)`
//! resolved per build. Every other `cfg`, `cfg(any(test, feature =
//! "testing"))` included, stays in, because that code can ship.
//!
//! Every counted item is pinned in [`ALLOWLIST`] by file path, item label and
//! the SHA-256 of its tokens, with the reason the mention cannot hand in key
//! state no resolution accepted. An edit inside a pinned item, or a second
//! item under a pinned label, is a new mention naming the entry it differs
//! from, and each entry must match a mention, so a moved or deleted item fails
//! the gate instead of leaving a stale entry. Identifiers a macro builds (a
//! `paste!` concatenation, a proc macro's output) are beyond a syntax scan.
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
/// (relative to the workspace root) whose token stream hashes to `digest`,
/// with the reason it cannot hand in key state no resolution accepted. `item`
/// is the label [`item_label`] gives; `digest` is [`digest`] of the item, so
/// any edit inside an approved item, and any second item under the same
/// label, is a new mention to review.
#[derive(Debug, Clone, Copy)]
struct Allowed {
    path: &'static str,
    item: &'static str,
    digest: &'static str,
    reason: &'static str,
}

const fn allow(
    path: &'static str,
    item: &'static str,
    digest: &'static str,
    reason: &'static str,
) -> Allowed {
    Allowed {
        path,
        item,
        digest,
        reason,
    }
}

/// Every approved mention of a gated name. SCP-314 adds the `KeyStateView`
/// entries in the change that creates that type in `crates/scp-ffi/common`.
const ALLOWLIST: &[Allowed] = &[
    allow(
        "crates/scp-did/src/key_state.rs",
        "struct KeyState",
        "743e334d26e0beee3f4270e5d58de29275372989ba76e9691630755250d31fdb",
        "the defining item",
    ),
    allow(
        "crates/scp-did/src/lib.rs",
        "use",
        "9b8936562f990fc43692603c503829233d671b00163ceeea069e2699c720665d",
        "re-exports the type from its defining crate; takes no input",
    ),
    allow(
        "crates/scp-kel/src/error.rs",
        "enum BodyField",
        "2832d73c7f86b5473b1b50eb7121153d95fcc5f4db256647a1376ffe86dbcd7d",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/error.rs",
        "impl Display for BodyField",
        "caa28ed21d281fd2fc3fae48cb4646196b2b9744ec59ab9a482873553c1ecd51",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "use",
        "16b57a840e48c572d0e10f7a60af23f8beab1dd2d9502b3c6eb44631fd5c8fb5",
        "imports the type for `KeyStateSnapshot::into_key_state`; takes no input",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "enum EventKind",
        "42a0d1ee94b1d10f2c430a017a01ea79ce896e4214c59c6c485754f799bb69b3",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "impl EventKind",
        "5e3fc9f677a90072cfad7d42fc5857708ac0f395eddade73497aa0c756f87265",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "fn signer_group_roles",
        "b02ad78561fa64637ee0b3820e2b3ad138a6096c2d82ae55b2f00a58600bc268",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "impl KeyStateSnapshot",
        "0b68a33a6261f26cf41b483e3c71aaf3c10b7895ad00a920f1add752f4d4087b",
        "`into_key_state` is `pub(crate)` and returns a `KeyState`; only `replay` and `key_state_at` call it, each on a `ValidatedChain`",
    ),
    allow(
        "crates/scp-kel/src/event.rs",
        "impl EventPreimage",
        "0500d170271b494448847066af1a14d8beaaa6102aa02461252e8c9da0f794a6",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/lib.rs",
        "use",
        "68aa79f0477f3b7088a1156549ba45463595c641a277b89f2ec79cb922a0f0cd",
        "re-exports `ReplayedState` from its defining crate; takes no input",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn kind_byte",
        "0252f70a616a6a15ac35780fa4ff5158f15f321f9a3641c5cf7464804b6d89c5",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn kind_from_byte",
        "c83f25f45c7f76cbb4ecebe5a790f6c7ba822fb89cecb315522c033ef1cd8867",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "impl EncodedPreimage",
        "3224c719a1d6682fca9da22d71df58f387ea57c06b59782df23a52f7a3b149fd",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn read_snapshot",
        "a435f895158819499868574e82192bc77f25b93c024e0b13d54799d778836488",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/preimage.rs",
        "fn read_key_entry",
        "c8fd2f49f7ac9a6387d4cd6f8bdb24f9784b367ae3f1aa0fb76118c3d97db356",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/validate/content.rs",
        "fn check_sentinels",
        "7611bc6798af661e56f249f77e6c4b1353f22bff93838fd5e93c158654d3364b",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/validate/content.rs",
        "fn check_continuation_present",
        "39ab64fdd6aefc3f2674fd9080736533323881f1f68bb4bf6d2da10a72420656",
        "enum variant `EventKind::KeyState` / `BodyField::KeyState`, not the type",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "use",
        "256a1c84308c59bd8b5a080c07a8bfda5cb0d1341b6802c47da0d0d42e31332d",
        "imports the type `ReplayedState` holds; takes no input",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "struct ReplayedState",
        "7b177092f52185801eec1b12cdeb38b3fb67fc729b4005b08c6ee453b3430ad4",
        "the defining item; private fields, no public constructor",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "impl ReplayedState",
        "b4f80586750c314d92a1d6c414c7122d18a93b01b06554afd9d77f0d175912be",
        "the defining impl; its accessors return state a `ValidatedChain` derived and take none in",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "fn replay",
        "d8f622da831f609e11b7b1646e6b1075e8ccc0cffcb2f7fa51ed4dcad7295f3a",
        "returns a `ReplayedState` derived from the `ValidatedChain` it takes",
    ),
    allow(
        "crates/scp-kel/src/validate/replay.rs",
        "fn key_state_at",
        "28654554755f1b3310a595653906946d7fb1935c33a59366dc6f908a303e90e5",
        "returns a `ReplayedState` derived from the `ValidatedChain` it takes",
    ),
    allow(
        "crates/scp-kel/src/validate.rs",
        "use",
        "66645f316914f66e17d49757e627292a829496ad36ba2cb9a12636319ab84e65",
        "re-exports `ReplayedState` within its defining crate; takes no input",
    ),
    allow(
        "crates/scp-kel/src/verdict.rs",
        "use",
        "1baa861338f8f15797c5f69094b3594fee9c4a63ca75560ed88dfe18e2c7fcd5",
        "imports `KeyState`, the type `ResolvedState::key_state` returns; takes no input",
    ),
    allow(
        "crates/scp-kel/src/verdict.rs",
        "use",
        "76b0a6cb5c39ca77194315eecc83a612b259e58716e8ea483fcb811d6687cdf9",
        "imports `ReplayedState`, the type `ResolvedState` holds; takes no input",
    ),
    allow(
        "crates/scp-kel/src/verdict.rs",
        "struct ResolvedState",
        "27f11d950be95e2e0a0356fdb1133bdb04926d5dc7fcede76eb82543e0fb76f1",
        "holds the replayed state of the chain resolution accepted, in a private field",
    ),
    allow(
        "crates/scp-kel/src/verdict.rs",
        "impl ResolvedState",
        "7e28a093730f2175ac738acf5d34376aeee5a997b57d10d215eb9bcbea330938",
        "`key_state` returns the state of the chain resolution accepted; takes none in",
    ),
    allow(
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "use",
        "51aaff0f7442c8b0595a51f675bfb6dbe85a252b496e5d4700212671d838a81f",
        "imports `ReplayedState` for the fingerprint; takes no input",
    ),
    allow(
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "impl PartyBlock",
        "e685171a8fd9b5cd12f1783e07a700a1fc6eff5de28728699da56edf0b1e50cc",
        "private block builder over a `ReplayedState` for the §9.11 fingerprint, a display value that gates nothing",
    ),
    allow(
        "crates/scp-protocol/src/crypto/key_continuity.rs",
        "fn compute_key_continuity_fingerprint",
        "1a30d320845207027b708b801b358682b41ceda93595ede93ec13e5feefaa06a",
        "§9.11 fingerprint, a display value that gates nothing; it reads `ReplayedState` because one party is the device's own adopted log",
    ),
];

/// A top-level item whose tokens name a gated type, or a hole the scan cannot
/// see through: a module declaration or `include!` that loads no scanned file.
#[derive(Debug)]
struct Mention {
    path: String,
    item: String,
    digest: String,
    /// Index into [`ALLOWLIST`] of the entry that approves it.
    allowed_by: Option<usize>,
    /// Index of an entry with this path and label but another digest: the
    /// approved item changed, or a second item shares its label.
    changed_from: Option<usize>,
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

/// An identifier's name with any `r#` prefix removed, so `r#KeyState` names
/// `KeyState`.
fn ident_name(i: &proc_macro2::Ident) -> String {
    let s = i.to_string();
    s.strip_prefix("r#")
        .map_or_else(|| s.clone(), str::to_owned)
}

/// Every identifier in `tokens`, at any depth.
fn idents(tokens: TokenStream, out: &mut Vec<String>) {
    for t in tokens {
        match t {
            TokenTree::Ident(i) => out.push(ident_name(&i)),
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
        self.0.push((ident_name(&t.ident), t.ty.to_token_stream()));
        syn::visit::visit_item_type(self, t);
    }

    fn visit_use_rename(&mut self, r: &'ast syn::UseRename) {
        // `use .. as _` binds no name.
        if r.rename != "_" {
            self.0
                .push((ident_name(&r.rename), r.ident.to_token_stream()));
        }
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

/// When a `#[path]` applies: always, only in a test build (`cfg_attr(test,
/// path = ..)`), or under a predicate the gate does not evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applies {
    Always,
    TestBuild,
    Unknown,
}

fn str_lit(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => Some(s.value()),
        _ => None,
    }
}

/// Every `#[path = ..]` and `#[cfg_attr(pred, path = ..)]` on a declaration.
fn path_attrs(m: &syn::ItemMod) -> Vec<(Applies, String)> {
    let mut out = Vec::new();
    for a in &m.attrs {
        match &a.meta {
            syn::Meta::NameValue(nv) if nv.path.is_ident("path") => {
                out.extend(str_lit(&nv.value).map(|p| (Applies::Always, p)));
            }
            syn::Meta::List(l) if l.path.is_ident("cfg_attr") => {
                let Ok(metas) = l.parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                ) else {
                    continue;
                };
                let mut metas = metas.into_iter();
                let applies = match metas.next() {
                    Some(syn::Meta::Path(pred)) if pred.is_ident("test") => Applies::TestBuild,
                    _ => Applies::Unknown,
                };
                for meta in metas {
                    if let syn::Meta::NameValue(nv) = meta
                        && nv.path.is_ident("path")
                    {
                        out.extend(str_lit(&nv.value).map(|p| (applies, p)));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The files a `mod` declaration in `from` loads in one build, each as its
/// alternatives (the first scanned one wins). A file loaded through `#[path]`,
/// a crate root, or a `mod.rs` keeps its children in its own directory; any
/// other file keeps them in the directory named by its stem. A `#[path]` under
/// a predicate the gate does not evaluate adds its file beside the default.
fn decl_targets(from: &str, m: &syn::ItemMod, mod_rs: bool, test_build: bool) -> Vec<Vec<String>> {
    let (dir, name) = from.rsplit_once('/').unwrap_or(("", from));
    let mut out = Vec::new();
    let mut default = true;
    for (applies, p) in path_attrs(m) {
        let file = vec![normalize(&format!("{dir}/{p}"))];
        match applies {
            Applies::Always => {
                out.push(file);
                default = false;
            }
            Applies::TestBuild if test_build => {
                out.push(file);
                default = false;
            }
            Applies::TestBuild => {}
            Applies::Unknown => out.push(file),
        }
    }
    if default {
        let base = if mod_rs {
            dir.to_owned()
        } else {
            format!("{dir}/{}", name.trim_end_matches(".rs"))
        };
        out.push(vec![
            format!("{base}/{}.rs", m.ident),
            format!("{base}/{}/mod.rs", m.ident),
        ]);
    }
    out
}

/// One file a `mod x;` declaration loads in one build.
#[derive(Debug)]
struct Load {
    from: String,
    label: String,
    /// The build it loads in: a `#[cfg(test)]` declaration loads only in a
    /// test build, any other in both.
    test_build: bool,
    candidates: Vec<String>,
    /// The scanned file among `candidates`, if any.
    target: Option<String>,
}

/// Every load of every top-level `mod x;` declaration in `files`.
fn loads(files: &[(String, syn::File)]) -> Vec<Load> {
    let known: BTreeSet<&str> = files.iter().map(|(r, _)| r.as_str()).collect();
    let decls: Vec<(&str, &syn::ItemMod)> = files
        .iter()
        .flat_map(|(r, f)| {
            f.items.iter().filter_map(move |i| match i {
                syn::Item::Mod(m) if m.content.is_none() => Some((r.as_str(), m)),
                _ => None,
            })
        })
        .collect();
    let path_loaded: BTreeSet<String> = decls
        .iter()
        .flat_map(|(from, m)| {
            let dir = from.rsplit_once('/').map_or("", |(d, _)| d);
            path_attrs(m)
                .into_iter()
                .map(move |(_, p)| normalize(&format!("{dir}/{p}")))
        })
        .collect();
    let mut out = Vec::new();
    for (from, m) in decls {
        let (dir, name) = from.rsplit_once('/').unwrap_or(("", from));
        let mod_rs = matches!(name, "mod.rs" | "lib.rs" | "main.rs")
            || dir.ends_with("src/bin")
            || path_loaded.contains(from);
        let cfg_test = m.attrs.iter().any(is_cfg_test);
        for test_build in [false, true] {
            if cfg_test && !test_build {
                continue;
            }
            for candidates in decl_targets(from, m, mod_rs, test_build) {
                let target = candidates
                    .iter()
                    .find(|c| known.contains(c.as_str()))
                    .cloned();
                out.push(Load {
                    from: from.to_owned(),
                    label: format!("mod {}", m.ident),
                    test_build,
                    candidates,
                    target,
                });
            }
        }
    }
    out
}

/// Every scanned file compiled only under exactly `#[cfg(test)]`: a file with
/// an inner `#![cfg(test)]`, or a file some declaration loads where every
/// declaration loading it in a non-test build sits in such a file. A file a
/// non-test declaration loads, and a file nothing loads, stays in scope.
fn test_only_files(files: &[(String, syn::File)], loads: &[Load]) -> BTreeSet<String> {
    let mut test_only: BTreeSet<String> = files
        .iter()
        .filter(|(_, f)| f.attrs.iter().any(is_cfg_test))
        .map(|(r, _)| r.clone())
        .collect();
    loop {
        let before = test_only.len();
        for (rel, _) in files {
            if test_only.contains(rel) {
                continue;
            }
            let mut into = loads
                .iter()
                .filter(|l| l.target.as_ref() == Some(rel))
                .peekable();
            if into.peek().is_some() && into.all(|l| l.test_build || test_only.contains(&l.from)) {
                test_only.insert(rel.clone());
            }
        }
        if test_only.len() == before {
            return test_only;
        }
    }
}

/// Every `include!` (code inclusion) in `tokens`, with its argument when that
/// is one string literal.
fn includes(tokens: TokenStream, out: &mut Vec<(String, Option<String>)>) {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, t) in tokens.iter().enumerate() {
        match t {
            TokenTree::Group(g) => includes(g.stream(), out),
            TokenTree::Ident(id) if ident_name(id) == "include" => {
                if let (Some(TokenTree::Punct(bang)), Some(TokenTree::Group(args))) =
                    (tokens.get(i + 1), tokens.get(i + 2))
                    && bang.as_char() == '!'
                {
                    let arg = syn::parse2::<syn::LitStr>(args.stream())
                        .ok()
                        .map(|l| l.value());
                    out.push((ident_name(id), arg));
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// The SHA-256 of an item's token stream, as lowercase hex.
fn digest(tokens: &TokenStream) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(tokens.to_string().as_bytes()))
}

impl Scan {
    fn push(&mut self, path: &str, item: String, tokens: &TokenStream) {
        let digest = digest(tokens);
        let same_label = |a: &&Allowed| a.path == path && a.item == item;
        let allowed_by = ALLOWLIST
            .iter()
            .position(|a| same_label(&a) && a.digest == digest);
        let changed_from = match allowed_by {
            Some(i) => {
                self.approved[i] += 1;
                None
            }
            None => ALLOWLIST.iter().position(|a| same_label(&a)),
        };
        self.mentions.push(Mention {
            path: path.to_owned(),
            item,
            digest,
            allowed_by,
            changed_from,
        });
    }
}

fn scan(files: &[(String, syn::File)]) -> Scan {
    let names = gated_names(files);
    let loads = loads(files);
    let test_only = test_only_files(files, &loads);
    let known: BTreeSet<&str> = files.iter().map(|(r, _)| r.as_str()).collect();
    let mut out = Scan {
        mentions: Vec::new(),
        approved: vec![0; ALLOWLIST.len()],
    };
    for l in &loads {
        if l.target.is_none() && !l.test_build && !test_only.contains(&l.from) {
            let item = format!(
                "{}: loads no scanned file ({})",
                l.label,
                l.candidates.join(" | ")
            );
            out.push(&l.from, item, &TokenStream::new());
        }
    }
    for (rel, file) in files.iter().filter(|(r, _)| !test_only.contains(r)) {
        let dir = rel.rsplit_once('/').map_or("", |(d, _)| d);
        let inner: TokenStream = file.attrs.iter().map(ToTokens::to_token_stream).collect();
        let items = file
            .items
            .iter()
            .filter(|i| !test_only_item(i))
            .map(|i| (item_label(i), i.to_token_stream()));
        for (item, tokens) in std::iter::once(("#![..]".to_owned(), inner)).chain(items) {
            let mut incl = Vec::new();
            includes(tokens.clone(), &mut incl);
            for (mac, arg) in incl {
                let target = arg.as_ref().map(|a| normalize(&format!("{dir}/{a}")));
                if target.as_deref().is_none_or(|t| !known.contains(t)) {
                    let what = arg.unwrap_or_else(|| "<computed path>".to_owned());
                    out.push(
                        rel,
                        format!("{item}: {mac}!({what}) reads no scanned file"),
                        &tokens,
                    );
                }
            }
            if names_any(tokens.clone(), &names) {
                out.push(rel, item, &tokens);
            }
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

fn read_parse(root: &Path, rel: &str) -> (String, syn::File) {
    let src = std::fs::read_to_string(root.join(rel))
        .unwrap_or_else(|e| panic!("{rel} is not readable: {e}"));
    let file = syn::parse_file(&src).unwrap_or_else(|e| panic!("{rel} does not parse: {e}"));
    (rel.to_owned(), file)
}

/// Every Rust file under the source roots, plus every file a module
/// declaration reaches outside them (through `#[path]`, or as a child of such
/// a file), read until no declaration reaches an unread file on disk.
fn workspace_files() -> Vec<(String, syn::File)> {
    let root = workspace_root();
    let mut paths = Vec::new();
    for src in source_roots(&root) {
        rust_files(&src, &mut paths);
    }
    let mut files: Vec<_> = paths
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("source sits under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            read_parse(&root, &rel)
        })
        .collect();
    loop {
        let mut reached: Vec<String> = loads(&files)
            .into_iter()
            .filter(|l| l.target.is_none())
            .filter_map(|l| l.candidates.into_iter().find(|c| root.join(c).is_file()))
            .collect();
        reached.sort();
        reached.dedup();
        if reached.is_empty() {
            files.sort_by(|a, b| a.0.cmp(&b.0));
            return files;
        }
        files.extend(reached.iter().map(|r| read_parse(&root, r)));
    }
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
    // A raw identifier names the type it spells.
    ("pub fn f(k: scp_did::r#KeyState) {}", 1),
    ("type r#K = KeyState; pub fn f(k: K) {}", 2),
    // `use .. as _` binds no name, so `_` elsewhere is no mention.
    ("use scp_did::KeyState as _; pub fn f() { let _ = 1; }", 1),
    // A file the scan cannot read is a hole, whatever it holds.
    // `include_str!` and `include_bytes!` yield a literal, never tokens.
    ("pub fn f() -> &'static str { include_str!(\"x.rs\") }", 0),
    (
        "pub fn f() -> &'static [u8] { include_bytes!(\"x.rs\") }",
        0,
    ),
    ("pub fn f() { include!(\"../x.rs\"); }", 1),
    ("include!(\"gen.rs\");", 1),
    (
        "pub fn f() { include!(concat!(env!(\"OUT_DIR\"), \"/k.rs\")); }",
        1,
    ),
    ("pub fn f() { std::include!(\"gen.rs\"); }", 1),
    ("#[cfg(test)] fn f() { include!(\"gen.rs\"); }", 0),
    ("mod absent;", 1),
    ("#[path = \"../elsewhere/absent.rs\"] mod m;", 1),
    ("#[cfg(test)] mod absent;", 0),
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

const K: &str = "pub fn f(k: KeyState) {}";

/// Multi-file inputs, each with the number of unapproved mentions: a file is
/// out of scope only when every declaration loading it in a non-test build is
/// test-only, and a file reached through `#[path]` or `include!` is scanned.
const MULTI_FILE_FIXTURES: &[(&[(&str, &str)], usize)] = &[
    (
        &[
            ("crates/x/src/lib.rs", "#[cfg(test)] mod tests;"),
            ("crates/x/src/tests.rs", K),
        ],
        0,
    ),
    (
        &[
            ("crates/x/src/lib.rs", "#[cfg(test)] mod tests;"),
            ("crates/x/src/tests/mod.rs", K),
        ],
        0,
    ),
    (
        &[
            ("crates/x/src/lib.rs", "#[cfg(test)] mod tests;"),
            ("crates/x/src/tests.rs", "mod deep;"),
            ("crates/x/src/tests/deep.rs", K),
        ],
        0,
    ),
    (
        &[
            ("crates/x/src/a.rs", "#[cfg(test)] mod t;"),
            ("crates/x/src/a/t.rs", K),
        ],
        0,
    ),
    (
        &[
            (
                "crates/x/src/a.rs",
                "#[cfg(test)] #[path = \"a_tests.rs\"] mod t;",
            ),
            ("crates/x/src/a_tests.rs", K),
        ],
        0,
    ),
    (
        &[
            ("crates/x/src/lib.rs", "mod tests;"),
            ("crates/x/src/tests.rs", K),
        ],
        1,
    ),
    // `a.rs` keeps its children in `a/`, so a sibling `t.rs` is another module.
    (
        &[
            ("crates/x/src/a.rs", "#[cfg(test)] mod t;"),
            ("crates/x/src/t.rs", K),
        ],
        1,
    ),
    (
        &[
            (
                "crates/x/src/lib.rs",
                "#[cfg(any(test, feature = \"testing\"))] mod tests;",
            ),
            ("crates/x/src/tests.rs", K),
        ],
        1,
    ),
    // A file is out only when every declaration loading it is test-only.
    (
        &[
            (
                "crates/x/src/lib.rs",
                "#[cfg(test)] pub mod shipped; #[cfg(not(test))] pub mod shipped;",
            ),
            ("crates/x/src/shipped.rs", K),
        ],
        1,
    ),
    (
        &[
            (
                "crates/x/src/lib.rs",
                "#[cfg(test)] #[path = \"prod.rs\"] mod t; pub mod prod;",
            ),
            ("crates/x/src/prod.rs", K),
        ],
        1,
    ),
    // `cfg_attr(test, path = ..)` loads `t_impl.rs` only in a test build; a
    // non-test build loads `t.rs`.
    (
        &[
            (
                "crates/x/src/lib.rs",
                "#[cfg_attr(test, path = \"t_impl.rs\")] mod t;",
            ),
            ("crates/x/src/t.rs", K),
            ("crates/x/src/t_impl.rs", K),
        ],
        1,
    ),
    // A `#[path]` outside `src` is scanned like any other file.
    (
        &[
            (
                "crates/x/src/lib.rs",
                "#[path = \"../tests/shared.rs\"] mod shared;",
            ),
            ("crates/x/tests/shared.rs", K),
        ],
        1,
    ),
    // An `include!` of a scanned file is no hole; the file is scanned.
    (
        &[
            ("crates/x/src/lib.rs", "include!(\"gen.rs\");"),
            ("crates/x/src/gen.rs", "pub fn g() {}"),
        ],
        0,
    ),
    (
        &[
            ("crates/x/src/lib.rs", "include!(\"gen.rs\");"),
            ("crates/x/src/gen.rs", K),
        ],
        1,
    ),
];

fn assert_test_only_files() {
    for (srcs, want) in MULTI_FILE_FIXTURES {
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

fn real(rel: &str) -> (String, syn::File) {
    read_parse(&workspace_root(), rel)
}

fn entry(path: &str, item: &str) -> usize {
    ALLOWLIST
        .iter()
        .position(|a| a.path == path && a.item == item)
        .unwrap_or_else(|| panic!("{path} `{item}` is approved"))
}

/// A pinned file as it stands gives no unapproved mention; an edit inside an
/// approved item, or a second item under an approved label, gives one naming
/// the entry; an entry whose item is gone reads as stale.
fn assert_allowlist_semantics() {
    let replay = "crates/scp-kel/src/validate/replay.rs";
    let s = scan(&[real(replay)]);
    assert_eq!(s.unapproved().len(), 0, "{:#?}", s.mentions);
    let impl_entry = entry(replay, "impl ReplayedState");
    assert_eq!(s.approved[impl_entry], 1);

    let (rel, mut file) = real(replay);
    for item in &mut file.items {
        if let syn::Item::Impl(i) = item
            && item_label(&syn::Item::Impl(i.clone())) == "impl ReplayedState"
        {
            i.items.push(syn::parse_quote!(
                pub fn leak(&self) -> KeyState {
                    self.key_state.clone()
                }
            ));
        }
    }
    let s = scan(&[(rel, file)]);
    let bad = s.unapproved();
    assert_eq!(bad.len(), 1, "{:#?}", s.mentions);
    assert_eq!(bad[0].item, "impl ReplayedState");
    assert_eq!(bad[0].changed_from, Some(impl_entry));
    assert_eq!(s.approved[impl_entry], 0);

    let verdict = "crates/scp-kel/src/verdict.rs";
    let (rel, mut file) = real(verdict);
    file.items.push(syn::parse_quote!(
        use crate::validate::ReplayedState as Leaked;
    ));
    let s = scan(&[(rel, file)]);
    let bad = s.unapproved();
    assert_eq!(bad.len(), 1, "{:#?}", s.mentions);
    assert_eq!(bad[0].item, "use");
    assert!(bad[0].changed_from.is_some());

    let resolved = entry(verdict, "impl ResolvedState");
    let s = scan(&[parse(verdict, "pub struct ResolvedState { n: u8 }")]);
    assert_eq!(
        s.approved[resolved], 0,
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
        println!(
            "  MENTION: {} `{}` digest {} changed_from {:?}",
            m.path, m.item, m.digest, m.changed_from
        );
    }

    // `#[path]` reaches outside `src`, and the loader read the file it names.
    assert!(
        files
            .iter()
            .any(|(r, _)| r == "crates/scp-kel/tests/kel/fixtures.rs"),
        "the file `crates/scp-kel/src/rank/tests.rs` loads through `#[path]` was not scanned"
    );
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
            .map(|m| m.changed_from.map_or_else(
                || format!("{} `{}` (digest {})", m.path, m.item, m.digest),
                |i| format!(
                    "{} `{}` (digest {}): changed since ALLOWLIST[{i}] approved it; re-review \
                     and pin the new digest",
                    m.path, m.item, m.digest
                ),
            ))
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
