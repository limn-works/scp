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
// `context/supervisor/identity_capability.rs`; additional files host the
// wrong-location declaration and the per-mode mint-path bypasses (kept in
// SEPARATE files so the closed-allowlist rule G classifies each file's
// inherent fns in isolation — and so the per-mode diagnostics do not
// interleave, making each `REQUIRED_FIXTURE_FAILURES` substring easy to
// pin to its own file).
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
// one of the SHAPE constraints (derive / public field / manual impl /
// cfg_attr derive) while sitting at the correct location. It also hosts the
// one correct allowlisted mint fn (`pub(super) issue_for_actor`) so the
// closed-allowlist rule G does NOT fire here (the inherent impl contains
// only an allowlisted name) — the mint-path bypasses live in their own
// files below, where they can be classified in isolation.

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
// supervisor-blessed constructor. (This is a TRAIT impl, not inherent,
// so its `from` fn is NOT collected into the structural mint-path
// classification — the manual-impl check D flags it instead.)
struct Did([u8; 32]);
impl From<Did> for OwnedIdentityDid {
    fn from(d: Did) -> Self {
        Self { inner: d.0 }
    }
}

// The single CORRECT inherent mint. `issue_for_actor` returns `Self` and
// takes a raw `Did` parameter; its NAME is allowlisted and it is
// `pub(super)`, so the closed-allowlist rule G does NOT fire here. Its
// presence also satisfies the mint-MUST-exist check (G.4) for this file so
// the mint-absent diagnostic does not false-positive.
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

// BYPASS 10: a PRODUCTION-PATH macro invocation in the DECLARING file
// (NOT inside `#[cfg(test)]`). The new declaring-file rule is a CATEGORY
// BAN: any macro definition/invocation outside `#[cfg(test)]` code is
// rejected regardless of payload — robust to `paste!`/token-split/metavar
// evasions that no literal-`impl …OwnedIdentityDid` text search could see.
// This invocation names no cap token and synthesizes no visible impl, yet
// MUST be flagged purely because it is a non-test-gated macro in the
// capability module. Diagnostic: `… in the declaring file (…) outside
// `#[cfg(test)]` code`.
//
// The declaring file's REAL `#[cfg(test)] mod tests` macros (`assert_eq!`,
// the `assert_send_sync` witness) are exempt — proven by the production
// scan, which has those cfg(test) macros and MUST still pass. Here we add a
// cfg(test)-gated counterpart too (BYPASS 10b) to prove the exemption path
// in the self-test itself: a `#[cfg(test)]`-gated macro invocation that must
// NOT contribute a declaring-file-ban diagnostic.
#[allow(dead_code)]
fn production_macro_user() {
    forge_via_macro!();
}

// BYPASS 10b (NEGATIVE control): a `#[cfg(test)]`-gated macro invocation in
// the declaring file. It MUST NOT trip the category ban (the test module is
// exempt). If the exemption regressed, this would add a spurious
// declaring-file-ban diagnostic — but the self-test does not assert on it,
// and the production scan (which has the real cfg(test) assert_eq!) would
// fail, so the exemption is doubly covered.
#[cfg(test)]
mod fixture_tests {
    #[test]
    fn exempt_test_macro() {
        assert_eq!(1, 1);
    }
}

// BYPASS 10c (FIX-1 — `not(test)` is PRODUCTION, not test-only). A macro
// invocation gated by `#[cfg(not(test))]` in the DECLARING file. The cfg
// text CONTAINS the `test` token, but the item compiles when NOT testing —
// it is PRODUCTION code and MUST be subject to the declaring-file category
// ban. The OLD boolean-blind `_attr_is_cfg_test` ("`test` appears anywhere
// in cfg(...)") mislabeled this as test-gating and WRONGLY EXEMPTED it,
// letting a `paste!`/metavar mint under `#[cfg(not(test))]` slip the gate.
// The combinator-stack walker now classifies `not(test)` as test-REQUIRING
// = False (not exempt), so this invocation is REJECTED. The diagnostic
// names the macro (`forge_via_not_test_macro`) so this case is asserted
// DISTINCTLY from BYPASS 10's `forge_via_macro`.
#[cfg(not(test))]
fn production_not_test_macro_user() {
    forge_via_not_test_macro!();
}

// BYPASS 10d (FIX-1 — `any(test, feature)` is PRODUCTION-active when the
// feature is on). A macro invocation gated by `#[cfg(any(test, feature =
// "x"))]` in the DECLARING file. The crate uses `#[cfg(any(test, feature =
// "testing"))]` PERVASIVELY; such an item compiles into a production build
// whenever the feature is enabled, so it MUST be subject to the
// declaring-file category ban. The OLD predicate saw the `test` token and
// WRONGLY EXEMPTED it. The combinator-stack walker classifies the `test`
// occurrence as enclosed by `any` = NOT test-requiring, so the whole gate
// is non-exempt and this invocation is REJECTED. Named distinctly
// (`forge_via_any_test_macro`) for an independent assertion.
#[cfg(any(test, feature = "x"))]
fn production_any_test_macro_user() {
    forge_via_any_test_macro!();
}

// @file: context/actor/forge_metavar_macro.rs
// FIX-1 (BLACK-G05) — METAVARIABLE MACRO MINT in a NON-declaring file. The
// macro DEFINITION synthesizes `impl $t { … }` on a passed-in type
// (`$t:ty`); its body carries `impl $t`, NOT the literal cap token. The
// INVOCATION `build_mint!(OwnedIdentityDid)` carries the cap token, NOT
// `impl`. Neither alone trips a literal `impl …OwnedIdentityDid` text test —
// the recognition heuristic is defeated by splitting the impl and the type
// across def/invocation. The CATEGORY rules close both ends:
//   - the def is flagged because it synthesizes an `impl $<metavariable>`
//     (diagnostic: `synthesizing an `impl $<metavariable>``), AND
//   - the invocation is flagged because it passes the cap type as an
//     argument (diagnostic: `passing OwnedIdentityDid as an argument`).
// The self-test asserts the metavar-def substring (the structural risk).
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
// Metavariable impl-synthesizer: `impl $t` on a passed-in type. Invoked with
// the cap type, it materializes a mint the AST walk never sees.
macro_rules! build_mint {
    ($t:ty) => {
        impl $t {
            fn forge(_d: DID) -> $t {
                Self { inner: [0; 32] }
            }
        }
    };
}
// The invocation passes the cap type INTO the metavar macro.
build_mint!(OwnedIdentityDid);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/forge_trait_alias.rs
// FIX-2 — ALIAS-RETURN TRAIT MINT caught by the PARAM check. A custom trait
// whose method returns an ALIAS of the cap type (`type OwnedCap =
// OwnedIdentityDid; trait Forger { fn forge(d: DID) -> OwnedCap; }`). The
// return-type classifier (`_returns_self`) sees `OwnedCap`, not Self/
// OwnedIdentityDid, and would SKIP the method — the same BLACK-G01 dodge that
// defeated inherent-fn return classification. The extended rule D now also
// flags a trait method that TAKES A RAW `DID` (`_takes_raw_did`), so this
// method is caught INDEPENDENTLY of the F.2 alias backstop: no legitimate
// trait method on this type consumes a raw `DID`. The trait/method are named
// distinctly (`ForgerAlias`/`forge_alias`) so the self-test substring
// `forge_alias` (trait `ForgerAlias`)` is UNIQUE to this case — and because
// `forge_alias`'s return text is the alias `OwnedCap` (which `_returns_self`
// does NOT match), the ONLY way that diagnostic can appear is via the
// raw-`DID`-PARAM arm. Diagnostic: `forbidden trait-impl mint `forge_alias`
// (trait `ForgerAlias`)`. (The alias also independently trips F.2, but this
// case isolates the PARAM arm.)
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
#[allow(dead_code)]
type OwnedCap = OwnedIdentityDid;
trait ForgerAlias {
    fn forge_alias(d: DID) -> OwnedCap;
}
// The forgery: returns the ALIAS (dodges `_returns_self`) but takes a raw
// `DID` (caught by `_takes_raw_did`).
impl ForgerAlias for OwnedIdentityDid {
    fn forge_alias(_d: DID) -> OwnedCap {
        OwnedCap { inner: [0; 32] }
    }
}
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/two_mints.rs
// ALLOWLIST rule G — a SECOND inherent mint path named `issue_again`. Under
// the closed allowlist this fails because its NAME is not allowlisted (the
// allowlist is issue_for_actor/reissue/as_did) — NOT via any "more than one
// raw-DID mint" count or return-type classification. The extra fn is just
// an unexpected inherent fn. Diagnostic: `unexpected inherent fn
// `issue_again``. (This file is also at the wrong location, so check (A)
// fires too.)
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
    // A SECOND inherent fn. Its NAME (`issue_again`) is not allowlisted, so
    // the allowlist rejects it as an unexpected inherent fn — independent of
    // its visibility, params, or return type.
    #[allow(dead_code)]
    pub(super) fn issue_again(_: &Did) -> Self {
        Self { inner: [1; 32] }
    }
}

// @file: context/supervisor/forge.rs
// ALLOWLIST rule G — alternately-NAMED raw-DID mint. A differently-named
// minting fn that takes a raw `DID` and returns `Self`. The compiler caps
// its blast radius at `crate::context`, but spec §9.4.1.3 requires the
// mint be a single NAMED constructor (`issue_for_actor`). The closed
// allowlist flags this purely because `forge` is NOT an allowlisted name —
// no return-type inspection is needed. Diagnostic:
// `unexpected inherent fn `forge``.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    // Differently-named raw-DID mint. Returns Self, takes a raw DID — but
    // the NAME is what damns it under the allowlist.
    #[allow(dead_code)]
    pub(in crate::context) fn forge(did: DID) -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/wrong_mint_vis.rs
// ALLOWLIST rule G — the sole mint fn is correctly NAMED `issue_for_actor`
// (so it passes the allowlist gate) but is `pub` (too broad). The
// allowlisted mint's required shape (`pub(super)`) is still enforced.
// Diagnostic: `mint fn `issue_for_actor` visibility is`. A `pub` mint lets
// any caller fabricate a token from a raw DID.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/non_self_clone.rs
// ALLOWLIST rule G — a non-allowlisted associated fn `dup` that returns
// Self with NO `&self` and no raw-DID param. Such an associated fn
// fabricates a token from nothing; it is NOT a legitimate clone path. The
// allowlist rejects it purely by NAME (`dup` is not in
// issue_for_actor/reissue/as_did). Diagnostic: `unexpected inherent fn
// `dup``. The file also carries the one correct `pub(super)
// issue_for_actor` mint so the mint-absent check (G.4) does not fire —
// isolating the unexpected-fn diagnostic.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
    // Self-returning, no raw-DID param, NO `&self` — an illegitimate
    // associated fabrication path. Rejected by name under the allowlist.
    #[allow(dead_code)]
    pub(in crate::context) fn dup() -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/forge_aliased.rs
// ALLOWLIST rule G — BLACK-G01: RETURN-TYPE-ALIASED forgery. This is the
// CRITICAL bypass the new allowlist exists to close. The forgery declares
// a return-type alias `type OwnedCap = OwnedIdentityDid;` and a mint fn
// `forge_aliased(did: DID) -> OwnedCap`. An OPEN classify-by-return-type
// rule inspects the return TEXT (`OwnedCap`), sees neither `Self` nor
// `OwnedIdentityDid`, and SKIPS the fn entirely — so a
// `pub(in crate::context)` handler could mint a token for ANY DID. The
// closed allowlist rejects `forge_aliased` purely because its NAME is not
// allowlisted, regardless of how the return type is hidden. Diagnostic:
// `unexpected inherent fn `forge_aliased``. The alias itself ALSO trips
// rule (F.2) (`is a `type` alias OF the capability type`). A correct
// `issue_for_actor` is included so the mint-absent check (G.4) stays
// quiet, isolating the forgery + alias diagnostics.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
// The return-type alias: `OwnedCap` IS `OwnedIdentityDid`. Banned by F.2.
#[allow(dead_code)]
type OwnedCap = OwnedIdentityDid;
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
    // The forgery: returns the ALIAS `OwnedCap`, not `Self`. An open
    // return-type classifier skips this; the allowlist rejects it by name.
    #[allow(dead_code)]
    pub(in crate::context) fn forge_aliased(did: DID) -> OwnedCap {
        OwnedCap { inner: [0; 32] }
    }
}

// @file: context/supervisor/forge_impl_trait.rs
// ALLOWLIST rule G — `-> impl Sized` forgery. The mint fn `forge2(did:
// DID) -> impl Sized` hides the capability type behind an opaque
// `impl Trait` return, so NO return-type text classifier can see it. The
// allowlist rejects `forge2` by NAME. Diagnostic: `unexpected inherent fn
// `forge2``. A correct `issue_for_actor` keeps G.4 quiet.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
    // Opaque return type — hides the cap type from any return classifier.
    #[allow(dead_code)]
    pub(in crate::context) fn forge2(did: DID) -> impl Sized {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/didid_param_mint.rs
// ALLOWLIST rule G — a `DidId`-param mint. `DidId` is a (hypothetical
// future) alias of `DID`; a parameter typed `DidId` is a raw-DID-typed
// param. The forgery name-squats as a non-allowlisted `mint_didid`, so the
// allowlist rejects it by NAME. Diagnostic: `unexpected inherent fn
// `mint_didid``. This case also exercises `_takes_raw_did`'s `\w*` tail:
// a trailing `\b` would NOT match `DidId` (since `Did` is followed by the
// word char `I`), which would have reopened a raw-DID mint path under a
// future `DID`->`DidId` rename. A standalone `type DidId = DID;` makes the
// alias concrete. A correct `issue_for_actor` keeps G.4 quiet.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
#[allow(dead_code)]
type DidId = DID;
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
    // Mint from a `DidId` (alias of DID). Name-squats outside the
    // allowlist; rejected by name. Its `DidId` param also proves the
    // `\w*`-tail raw-DID match.
    #[allow(dead_code)]
    pub(in crate::context) fn mint_didid(id: DidId) -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/other_bypass.rs
// Still under the required supervisor module tree, but NOT at the
// `identity_capability.rs` path. The location check should flag this.

// BYPASS 6: wrong STRUCT name-visibility. The struct MUST be
// `pub(in crate::context)`; `pub(crate)` is too broad (nameable beyond
// the context module tree). Check (B) flags this with a
// `struct visibility is 'pub(crate)'` diagnostic. (This file is also at
// the wrong location, so check (A) fires too — both are independent.)
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

// @file: context/supervisor/forge_trait.rs
// COVERAGE GAP G03 (FIX-A) — CUSTOM-TRAIT MINT. A custom trait whose method
// CONSTRUCTS the cap evades BOTH the forbidden-trait blocklist (rule D —
// `Forger` is not Clone/From/etc.) AND the inherent-impl allowlist (rule G
// inspects only INHERENT impls, where trait_name is None). The extended
// rule D collects trait-impl methods and FAILs any whose return type is
// Self/OwnedIdentityDid. Diagnostic: `forbidden trait-impl mint `forge`
// (trait `Forger`)`. A correct inherent `issue_for_actor` keeps the
// mint-absent check (G.4) quiet, isolating the trait-mint diagnostic.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
trait Forger {
    fn forge(d: DID) -> Self;
}
// The custom-trait mint: a trait method returning Self that constructs the
// cap from a raw DID. Not on the forbidden-trait blocklist, not an inherent
// fn — the extended rule D is what damns it (returns Self).
impl Forger for OwnedIdentityDid {
    fn forge(_d: DID) -> Self {
        Self { inner: [0; 32] }
    }
}
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/forge_macro.rs
// COVERAGE GAP G02 (FIX-B) — MACRO-HIDDEN MINT. tree-sitter does NOT expand
// macros, so a `macro_rules!` that emits an `impl OwnedIdentityDid { fn
// forge(did: DID) -> Self {…} }` hides the mint from the AST walk. Rule B
// FAILs (1) the macro_rules DEFINITION in any file because it touches the
// cap type, AND (2) any macro whose body synthesizes an
// `impl …OwnedIdentityDid`. Diagnostic: `macro_rules! definition whose body
// synthesizes an `impl …OwnedIdentityDid``. A correct inherent
// `issue_for_actor` keeps G.4 quiet.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
// The macro-hidden mint: its body defines `impl OwnedIdentityDid { fn
// forge … }`. Invisible to the AST walk; rejected at the macro level.
macro_rules! hidden_mint {
    () => {
        impl OwnedIdentityDid {
            fn forge(_d: DID) -> Self {
                Self { inner: [0; 32] }
            }
        }
    };
}
hidden_mint!();
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
}

// @file: context/supervisor/forge_path.rs
// COVERAGE GAP G04 (FIX-C) — `#[path]` ESCAPE. The scanner walks only
// `crates/scp-runtime/src/`. A `#[path = "…/…"] mod x;` whose target climbs
// OUT of src/ pulls an external file into the crate where an in-module mint
// would be legal but invisible to this gate. Rule C resolves the `#[path]`
// target relative to the declaring file's directory and FAILs if it escapes
// the scanned src root. From `.../context/supervisor/`, `../../../../` rises
// above src/ into the staging root, so this target escapes. Diagnostic:
// `#[path …]` … ESCAPES the scanned source root`. A correct inherent
// `issue_for_actor` keeps G.4 quiet. (The legitimate production `#[path]`
// — `key_package_actor_tests.rs`, a SIBLING inside src/ — resolves UNDER
// src and is NOT flagged; the escape predicate is false-fail-free for it.)
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    inner: [u8; 32],
}
struct Did([u8; 32]);
// The escaping `#[path]`: target climbs above src/ into the staging root.
#[allow(dead_code)]
#[path = "../../../../external_forge.rs"]
mod external_forge;
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(_: &Did) -> Self {
        Self { inner: [0; 32] }
    }
}
