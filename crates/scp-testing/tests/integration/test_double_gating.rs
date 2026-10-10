#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Structural check that named test doubles compile only in test builds.
//!
//! Root `AGENTS.md` ("No dev/test-only stand-ins in production") forbids an
//! in-memory store or an always-succeeds verifier on a shipped path, and §17.17
//! of `.docs/specs/17-persistence-and-storage.md` gives the mechanism: the
//! stand-in compiles only under a `testing` feature, and
//! `scripts/check-shipped-feature-graph.sh` proves that no shipped artifact
//! resolves a `testing` feature. That gate reads feature graphs, so it cannot
//! see a stand-in whose `#[cfg]` someone deleted. This test closes that hole for
//! the types in [`GATED_DOUBLES`]: it parses every Rust source file under
//! `crates/` with `syn` and fails when an item that declares, implements, or
//! re-exports one of them carries no cfg predicate that implies
//! `test || feature = "testing"`.

use std::path::{Path, PathBuf};

/// Test doubles that must compile only under `test` or `feature = "testing"`.
///
/// `InMemoryFfiTrustStore` forgets every entry when dropped, so trust
/// aggregation through it reads an empty store. `InMemoryViolationStore`
/// forgets every custody violation, which ADR-039 requires to be durable.
/// `NoOpRevocationChecker` reports every attestation as not revoked without
/// consulting a revocation list.
const GATED_DOUBLES: &[&str] = &[
    "InMemoryFfiTrustStore",
    "InMemoryViolationStore",
    "NoOpRevocationChecker",
];

/// True when a cfg predicate holds only if `test` or `feature = "testing"` holds.
///
/// `all(..)` implies the gate when any child does; `any(..)` only when every
/// child does, because a non-test child reaches a shipped build; `not(..)`
/// never does, which errs toward reporting an item as ungated.
fn implies_harness(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(p) => p.is_ident("test"),
        syn::Meta::NameValue(nv) => {
            nv.path.is_ident("feature")
                && matches!(
                    &nv.value,
                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) if s.value() == "testing"
                )
        }
        syn::Meta::List(list) => {
            let Ok(nested) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return false;
            };
            if list.path.is_ident("all") {
                nested.iter().any(implies_harness)
            } else if list.path.is_ident("any") {
                !nested.is_empty() && nested.iter().all(implies_harness)
            } else {
                false
            }
        }
    }
}

/// True when any `#[cfg(..)]` among `attrs` implies the harness gate.
fn attrs_gated(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| implies_harness(&meta))
    })
}

fn type_names_double(ty: &syn::Type) -> Option<&'static str> {
    let syn::Type::Path(tp) = ty else {
        return None;
    };
    let last = tp.path.segments.last()?;
    GATED_DOUBLES
        .iter()
        .copied()
        .find(|name| last.ident == name)
}

fn use_tree_doubles(tree: &syn::UseTree, out: &mut Vec<&'static str>) {
    match tree {
        syn::UseTree::Path(p) => use_tree_doubles(&p.tree, out),
        syn::UseTree::Name(n) => {
            out.extend(GATED_DOUBLES.iter().copied().filter(|name| n.ident == name));
        }
        syn::UseTree::Rename(r) => {
            out.extend(GATED_DOUBLES.iter().copied().filter(|name| r.ident == name));
        }
        syn::UseTree::Group(g) => {
            for t in &g.items {
                use_tree_doubles(t, out);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

/// One item that declares, implements, or re-exports a gated double.
#[derive(Debug)]
struct Mention {
    name: &'static str,
    kind: &'static str,
    gated: bool,
}

fn collect(items: &[syn::Item], inherited: bool, out: &mut Vec<Mention>) {
    for item in items {
        let (attrs, names, kind): (&[syn::Attribute], Vec<&'static str>, &'static str) = match item
        {
            syn::Item::Struct(s) => (
                &s.attrs,
                GATED_DOUBLES
                    .iter()
                    .copied()
                    .filter(|n| s.ident == n)
                    .collect(),
                "struct",
            ),
            syn::Item::Enum(e) => (
                &e.attrs,
                GATED_DOUBLES
                    .iter()
                    .copied()
                    .filter(|n| e.ident == n)
                    .collect(),
                "enum",
            ),
            syn::Item::Impl(i) => (
                &i.attrs,
                type_names_double(&i.self_ty).into_iter().collect(),
                "impl",
            ),
            syn::Item::Use(u) => {
                let mut names = Vec::new();
                use_tree_doubles(&u.tree, &mut names);
                (&u.attrs, names, "use")
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect(inner, inherited || attrs_gated(&m.attrs), out);
                }
                continue;
            }
            _ => continue,
        };
        let gated = inherited || attrs_gated(attrs);
        out.extend(names.into_iter().map(|name| Mention { name, kind, gated }));
    }
}

fn mentions_in_source(src: &str) -> Vec<Mention> {
    let file = syn::parse_file(src).expect("fixture or workspace source parses");
    let mut out = Vec::new();
    collect(&file.items, attrs_gated(&file.attrs), &mut out);
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            // Build output and vendored trees hold no workspace source.
            if name != "target" && name != "node_modules" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn named_test_doubles_compile_only_under_test_or_testing() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("scp-testing sits under crates/")
        .to_path_buf();
    let mut files = Vec::new();
    rust_files(&crates_dir, &mut files);

    let mut ungated = Vec::new();
    let mut declarations: Vec<&'static str> = Vec::new();
    for path in &files {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        if !GATED_DOUBLES.iter().any(|n| src.contains(n)) {
            continue;
        }
        let Ok(file) = syn::parse_file(&src) else {
            panic!("{} does not parse", path.display());
        };
        let mut found = Vec::new();
        collect(&file.items, attrs_gated(&file.attrs), &mut found);
        for m in found {
            if m.kind == "struct" || m.kind == "enum" {
                declarations.push(m.name);
            }
            if !m.gated {
                let shown = path.strip_prefix(&crates_dir).unwrap_or(path);
                ungated.push(format!("crates/{}: {} {}", shown.display(), m.kind, m.name));
            }
        }
    }

    // Each double is declared exactly once; a rename or a move out of `crates/`
    // would otherwise leave this test checking nothing.
    for name in GATED_DOUBLES {
        let count = declarations.iter().filter(|d| *d == name).count();
        assert_eq!(
            count, 1,
            "expected one declaration of `{name}` under crates/, found {count}"
        );
    }
    assert!(
        ungated.is_empty(),
        "these items declare, implement, or re-export a test double without a \
         cfg that implies `test` or `feature = \"testing\"`, so a shipped build \
         compiles them:\n{}",
        ungated.join("\n")
    );
}

/// The checker reports the gated fixture as gated and every weakened copy as
/// ungated, so a pass above means the cfg is present, not that the checker is
/// blind.
#[test]
fn checker_rejects_each_weakened_gate() {
    let gated = r#"
        #[cfg(any(test, feature = "testing"))]
        pub struct NoOpRevocationChecker;
        #[cfg(any(test, feature = "testing"))]
        impl Checker for NoOpRevocationChecker {}
        #[cfg(feature = "testing")]
        pub use a::b::NoOpRevocationChecker;
        #[cfg(test)]
        mod tests {
            impl Default for NoOpRevocationChecker { fn default() -> Self { Self } }
        }
        #[cfg(all(unix, feature = "testing"))]
        impl Other for NoOpRevocationChecker {}
    "#;
    let found = mentions_in_source(gated);
    assert_eq!(found.len(), 5, "{found:?}");
    assert!(found.iter().all(|m| m.gated), "{found:?}");

    let weakened = [
        // The gate deleted.
        "pub struct NoOpRevocationChecker;",
        // A non-test arm of `any` reaches a shipped build.
        r#"#[cfg(any(test, feature = "other"))] pub struct NoOpRevocationChecker;"#,
        // A negated gate is the shipped build.
        r#"#[cfg(not(feature = "testing"))] pub struct NoOpRevocationChecker;"#,
        // A gate on a sibling item does not cover the impl.
        "impl Checker for NoOpRevocationChecker {}",
        // An ungated re-export, in a group, under a rename.
        "pub use a::{b::NoOpRevocationChecker as Checker};",
        // An ungated enclosing module gates nothing.
        "pub mod m { pub struct InMemoryViolationStore; }",
    ];
    for src in weakened {
        let found = mentions_in_source(src);
        assert_eq!(found.len(), 1, "{src}: {found:?}");
        assert!(!found[0].gated, "checker accepted an ungated item: {src}");
    }
}
