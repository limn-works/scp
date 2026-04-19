// ---------------------------------------------------------------------------
// Self-test fixture for scripts/check-owned-identity-did.py.
//
// This file is deliberately NOT compiled by cargo — it lives under
// `scripts/tests/` and is consumed only by the CI AST checker. The
// scanner runs its `--self-test` against this fixture and asserts every
// bypass pattern below triggers a distinct enforcement failure.
//
// DO NOT add `mod owned_identity_did_fixture;` anywhere. This is never
// built.
//
// The fixture is split into multiple synthetic source files via a
// sentinel comment:
//
//     // @file: <rel-path-under-scp-runtime-src>
//
// Each block from one `@file:` line to the next is written to that
// path in a temp staging tree at self-test time. The required path is
// `context/supervisor/identity_capability.rs`; a second file at
// `context/handlers/bad.rs` hosts the wrong-location declaration.
//
// Run:
//   python3.12 scripts/check-owned-identity-did.py --self-test
//
// The script asserts every bypass pattern below is caught. If the
// scanner regresses on any one, the self-test fails with the list of
// missed patterns.
// ---------------------------------------------------------------------------

// @file: context/supervisor/identity_capability.rs
// This file is at the REQUIRED path. Every declaration here bypasses
// one of the shape constraints (derive / visibility / public field /
// manual impl / type alias) while sitting at the correct location.

// BYPASS 1: forbidden derive on the struct. The scanner's derive check
// must flag Clone + Debug + Serialize.
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct OwnedIdentityDid {
    // BYPASS 2: public tuple-struct field is caught separately; this
    // one is a NAMED field with pub(crate) visibility. Enforcement E
    // flags this even though the file otherwise looks correct.
    pub(crate) inner: [u8; 32],
}

// BYPASS 3: manual impl Clone for OwnedIdentityDid. Clone is banned in
// FORBIDDEN_IMPL_TRAITS; the scanner must walk impl_item nodes.
impl Clone for OwnedIdentityDid {
    fn clone(&self) -> Self {
        Self { inner: self.inner }
    }
}

// BYPASS 4: manual impl From<Did> for OwnedIdentityDid. From is banned
// in FORBIDDEN_IMPL_TRAITS because it permits fabrication without the
// supervisor-blessed constructor.
struct Did([u8; 32]);
impl From<Did> for OwnedIdentityDid {
    fn from(d: Did) -> Self {
        Self { inner: d.0 }
    }
}

// Inherent impl. Allowed — the constructor lives here.
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
}

// BYPASS 5: tuple-struct form named OwnedIdentityDid with a
// `pub(super)` inner field. Tree-sitter-rust 0.21+ emits
// `visibility_modifier` as a DIRECT child of
// `ordered_field_declaration_list` (no `ordered_field_declaration`
// wrapper), so a pub tuple field bypasses any walker that scans for
// the wrapper. The scanner MUST flag this case. We use `pub(super)`
// here (the named-field case above uses `pub(crate)`) so the scanner
// self-test can distinguish the tuple-field diagnostic from the
// named-field diagnostic by visibility string. (Duplicate
// `OwnedIdentityDid` names parse cleanly at the syntax level —
// tree-sitter does not resolve names, and the fixture is never
// compiled by cargo. Production code has exactly one declaration.)
#[allow(dead_code)]
pub(super) struct OwnedIdentityDid(pub(super) Did);

// BYPASS 8: conditional-derive via `cfg_attr` with a single feature
// predicate. The outer attribute is
// `#[cfg_attr(feature = "testing", derive(Clone))]` — NOT a
// `#[derive(Clone)]` literal, so a scanner that only recognizes an
// attribute whose text starts with `#[derive(` misses it completely.
// At cfg-eval time the feature activates and this becomes a real
// `#[derive(Clone)]`, minting the forbidden trait. The scanner MUST
// scan every attribute's TEXT for a balanced `derive(...)` group,
// regardless of outer wrapper (cfg_attr, other future wrappers).
//
// Kept as a unit struct so NO other enforcement check fires — only
// the derive check (C) produces a `forbidden derive(s): Clone.`
// diagnostic. Detection here is proven by transitivity: BYPASS 9
// uses the same `_extract_derive_groups` code path against a nested
// cfg_attr predicate and carries the self-test's substring anchor
// (`forbidden derive(s): Deserialize`). If extraction works for
// the nested case, it works for this simple case too.
#[allow(dead_code)]
#[cfg_attr(feature = "testing", derive(Clone))]
pub(super) struct OwnedIdentityDid;

// BYPASS 9: conditional-derive with a nested predicate —
// `cfg_attr(all(feature = "a", not(feature = "b")), derive(Serialize, Deserialize))`.
// Tests the derive-group extractor against a `cfg_attr` whose first
// argument is a nested `all(...)` / `not(...)` predicate (paren-
// balanced with multiple `feature = "..."` strings). The derive group
// contains two identifiers and must extract BOTH.
//
// `Deserialize` is unique to this bypass — no other fixture
// declaration has `Deserialize` in its derive list — so the
// self-test asserts the diagnostic contains `Deserialize` to prove
// the nested form is handled.
#[allow(dead_code)]
#[cfg_attr(all(feature = "a", not(feature = "b")), derive(Serialize, Deserialize))]
pub(super) struct OwnedIdentityDid;

// @file: context/supervisor/other_bypass.rs
// Still under the required supervisor module tree, but NOT at the
// `identity_capability.rs` path. The location check should flag these.

// BYPASS 6: wrong visibility (pub(crate)). Flagged by check (B).
#[allow(dead_code)]
pub(crate) struct OwnedIdentityDid {
    inner: [u8; 32],
}

// @file: context/handlers/bad.rs
// Wrong file entirely — handlers must NOT name the type's constructor.
// The location check (A) must flag this.

// BYPASS 7: type alias. Even at a wrong location the alias is itself
// illegal regardless of location. Flag (F) triggers first; (A) also
// triggers.
#[allow(dead_code)]
pub(super) type OwnedIdentityDid = [u8; 32];
