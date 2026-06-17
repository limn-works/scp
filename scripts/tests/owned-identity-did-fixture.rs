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

// BYPASS H1 (FIX-1 / BLACK-G07) — FREE-FUNCTION CONSTRUCTION in the DECLARING
// file. Rust field privacy is MODULE-scoped, not impl-scoped: the private
// `inner`/`did` field is reachable from ANY item in the declaring module, so
// a FREE FN can mint a token via a struct literal `OwnedIdentityDid { … }`
// WITHOUT going through an allowlisted inherent constructor. This PASSES rules
// (A)-(G) (they only inspect `impl OwnedIdentityDid` blocks + decls), COMPILES
// (the field is in-module-reachable), and is callable from handler code in
// `crate::context::actor::handlers` → forges a token for ANY DID, defeating
// cross-identity isolation. Rule H scans EVERY cap-constructing
// `struct_expression` in the declaring file and HARD FAILs this one because
// its enclosing fn `forge_token` is NOT in {issue_for_actor, reissue}.
// Diagnostic names the fn: `… in fn `forge_token` …`. (The block's correct
// `issue_for_actor` inherent constructor — whose `Self { … }` literal IS
// allowlisted — keeps rule H from false-failing the legitimate mint, proving
// rule H allows the two inherent constructors while rejecting the free fn.)
#[allow(dead_code)]
pub(in crate::context) fn forge_token(_did: Did) -> OwnedIdentityDid {
    OwnedIdentityDid { inner: [0; 32] }
}

// BYPASS H2 (FIX-1 / BLACK-G07) — HELPER-STRUCT METHOD CONSTRUCTION in the
// DECLARING file. A method on a DIFFERENT (helper) struct constructs the cap
// via a struct literal. Same module-scoped-privacy bypass: rule G's inherent
// allowlist inspects only `impl OwnedIdentityDid` blocks, so a method in
// `impl TokenForger { … }` is invisible to it. Rule H catches it because the
// constructing `struct_expression`'s enclosing fn `mint_via_helper` is not an
// allowlisted constructor AND its enclosing impl does not target the cap.
// Diagnostic names the fn: `… in fn `mint_via_helper` …`.
struct TokenForger;
#[allow(dead_code)]
impl TokenForger {
    fn mint_via_helper(&self, _did: Did) -> OwnedIdentityDid {
        OwnedIdentityDid { inner: [0; 32] }
    }
}

// BYPASS H3 (FIX-1 escapable-scope class) — CLOSURE-INSIDE-MINT. The cap
// literal is constructed inside a CLOSURE whose nearest enclosing
// `function_item` is the allowlisted inherent `issue_for_actor`. The fn's OUTER
// shape is the EXACTLY-CORRECT mint (`pub(super)`, raw-`Did` param, returns
// `Self`), so rule G PASSES it and `in_allowlisted` is True — isolating the new
// escapable-scope arm. Rule H walks from the literal to its nearest
// `function_item` and — before this fix — stepped PAST the `closure_expression`
// (a distinct expression node, NOT a `function_item`) to land on the allowlisted
// `issue_for_actor`, so the construction PASSED. But the closure captures the
// module-private `inner`/`did` field legally (Rust field privacy is
// module-scoped) and can be RETURNED / stored and invoked LATER by handler code
// with an attacker-chosen DID — forging a token and defeating cross-identity
// isolation. The enclosing fn name is no longer the boundary on WHO mints. Rule
// H now HARD FAILs when an escapable scope (here `closure_expression`) sits
// between the literal and the allowlisted fn. Diagnostic substring `inside a
// `closure_expression`` is unique to this closure-in-constructor case.
#[allow(dead_code)]
impl OwnedIdentityDid {
    pub(super) fn issue_for_actor(_d: &Did) -> Self {
        let mint = |inner| Self { inner };
        mint([0; 32])
    }
}

// BYPASS H4 (FIX-1 escapable-scope class) — REISSUE CLOSURE FACTORY. The real
// forgery shape from the finding: `reissue` returns a `Box<dyn Fn(Did) ->
// OwnedIdentityDid>` whose closure body constructs the cap from an
// attacker-supplied DID. The fn's OUTER shape is a CORRECT `reissue` (`&self`,
// no raw-`DID` param, `pub(in crate::context)`), so rule G PASSES it (rule G
// does not constrain `reissue`'s return type) and `in_allowlisted` is True. The
// struct literal sits inside a `closure_expression` inside a `Box::new(...)`
// call inside the allowlisted `reissue`; the nearest-`function_item` walk steps
// past the closure to `reissue` and (pre-fix) PASSED — handing handler code a
// callable that mints a token for ANY DID. Rule H now detects the intervening
// `closure_expression` and HARD FAILs. The diagnostic carries `within the
// allowlisted constructor `reissue`` which is unique to this reissue-factory
// case.
#[allow(dead_code)]
impl OwnedIdentityDid {
    pub(in crate::context) fn reissue(&self) -> Box<dyn Fn(Did) -> OwnedIdentityDid> {
        Box::new(|_d: Did| OwnedIdentityDid { inner: [0; 32] })
    }
}

// BYPASS H5 (FIX-1 escapable-scope class) — ASYNC BLOCK IN CONSTRUCTOR. The cap
// literal is constructed inside an `async { … }` block whose nearest enclosing
// `function_item` is the allowlisted inherent `reissue` (correct `&self` /
// no-raw-DID / `pub(in crate::context)` shape, so rule G PASSES it and
// `in_allowlisted` is True). An async block is an `async_block` node, NOT a
// `function_item`, so the nearest-`function_item` walk stepped PAST it (pre-fix)
// and the construction PASSED. The async future can be RETURNED / spawned and
// polled later by handler code — a deferred-execution forgery in the same class
// as the closure case. Rule H now detects the intervening `async_block` and HARD
// FAILs. The diagnostic substring `inside a `async_block`` is unique to this
// async-block-in-constructor case.
#[allow(dead_code)]
impl OwnedIdentityDid {
    pub(in crate::context) fn reissue(&self) -> impl core::future::Future<Output = Self> {
        async { Self { inner: [0; 32] } }
    }
}

// BYPASS H6 (FIX-1 nested-fn name-launder) — NESTED `issue_for_actor` INSIDE
// `reissue`. The cap literal is built inside a NESTED `fn issue_for_actor`
// declared lexically INSIDE the real allowlisted `reissue`, which escapes as a
// `fn`-pointer. Pre-fix, the literal's nearest enclosing `function_item` was the
// INNER nested fn — its NAME (`issue_for_actor`) is in CONSTRUCTING_FNS, its
// nearest enclosing `impl_item` (walking PAST the outer fn) is the real cap
// impl, and it is inherent — so `in_allowlisted` was True. The escapable-scope
// check then ran `_escapable_scope_between(literal, fn_node=inner_fn)` and
// stopped AT the inner fn (it IS `fn_node`, the boundary), so the
// `function_item` escapable arm never fired for it; the nested fn is ALSO
// invisible to rule G (which only inspects fns that are DIRECT children of the
// impl's `declaration_list` — a nested fn's parent is a `block`). It slipped
// BOTH rules and the construction PASSED — forging any DID and handing handler
// code an escaping `fn` pointer. The `is_impl_method` structural guard in
// `_construction_hit_reason` now requires `fn_node` be a TRUE impl method (parent
// chain `function_item -> declaration_list -> impl_item`); the nested fn's parent
// is a `block`, so the guard is False, `in_allowlisted` falls through, and the
// "outside the allowlisted constructors" branch HARD FAILs naming the inner fn.
// The substring `in fn `issue_for_actor` outside` is produced ONLY by this case
// (the allowlisted name `issue_for_actor` can never be the enclosing fn of a
// rejected free-fn / helper-method construction).
#[allow(dead_code)]
impl OwnedIdentityDid {
    pub(in crate::context) fn reissue(&self) -> fn(Did) -> OwnedIdentityDid {
        fn issue_for_actor(_d: Did) -> OwnedIdentityDid {
            OwnedIdentityDid { inner: [0; 32] }
        }
        issue_for_actor
    }
}

// BYPASS H7 (FIX-1 nested-fn name-launder, symmetric) — NESTED `reissue` INSIDE
// `issue_for_actor`. The mirror of H6: a NESTED `fn reissue` declared inside the
// real allowlisted `issue_for_actor`, escaping as a `fn` pointer. Same pre-fix
// bypass mechanics (inner fn's name is allowlisted, its nearest `impl_item` is
// the cap impl, it is the escapable-scope boundary so the `function_item` arm
// never fires, and rule G is blind to it). The same `is_impl_method` guard
// rejects it. The substring `in fn `reissue` outside` is unique to this case.
#[allow(dead_code)]
impl OwnedIdentityDid {
    pub(super) fn issue_for_actor(_d: &Did) -> Self {
        fn reissue(_d: &Did) -> OwnedIdentityDid {
            OwnedIdentityDid { inner: [0; 32] }
        }
        reissue(_d)
    }
}

// BYPASS I1 (FIX — rule I, nested-mod inherent cap-impl) — A SECOND inherent
// `impl OwnedIdentityDid` hosting an allowlisted-NAMED `issue_for_actor`,
// hidden inside a nested `mod forge_surface` in the DECLARING file. Pre-fix
// this PASSED exit 0: the per-file inherent allowlist (G) saw an allowlisted
// name (`issue_for_actor`), and the construction scan (H) saw an inline
// `Self { … }` whose nearest enclosing `function_item` is that allowlisted
// `issue_for_actor` in an inherent cap impl (`in_allowlisted` True). A
// literal-free module-level wrapper could then re-export this nested mint to
// all of `crate::context`. The canonical production cap impl is TOP-LEVEL, so
// rule I HARD FAILs ANY cap inherent-impl nested under a `mod` in the
// declaring file — the in-file analogue of the `#[path]`-include escape. The
// substring `inherent impl `impl OwnedIdentityDid` is nested under a `mod`` is
// produced ONLY by a nested-mod inherent cap impl. (The nested `Self { … }`
// ALSO trips the rule-I construction arm with a `Self`-labelled diagnostic;
// BYPASS I2 below isolates the construction arm with an explicit-name label.)
mod forge_surface {
    use super::*;
    #[allow(dead_code)]
    impl OwnedIdentityDid {
        pub(super) fn issue_for_actor(_d: &Did) -> Self {
            Self { inner: [0; 32] }
        }
    }
}

// BYPASS I2 (FIX — rule I, nested-mod cap construction, non-allowlisted name) —
// A nested-mod impl whose method constructs the cap via an EXPLICIT-NAME
// `OwnedIdentityDid { … }` struct literal. Same nesting bypass as I1; this case
// isolates the rule-I CONSTRUCTION arm by labelling the literal with the
// explicit type name (not `Self`), so its diagnostic substring
// `` `OwnedIdentityDid { … }` cap construction is nested under a `mod` `` is
// unique to the explicit-name nested-mod construction (distinct from I1's
// `Self`-labelled construction). The enclosing fn `forge_nested` is also
// non-allowlisted, so rule G fires an `unexpected inherent fn` diagnostic too —
// additive, not relied upon by this assertion.
mod forge_surface_two {
    use super::*;
    #[allow(dead_code)]
    impl OwnedIdentityDid {
        pub(super) fn forge_nested(_d: &Did) -> Self {
            OwnedIdentityDid { inner: [0; 32] }
        }
    }
}

// BYPASS J1 (FIX — rule J, declaring-file LITERAL-FREE by-value cap-return
// wrapper) — A free fn at the declaring file's module level that returns the
// cap BY VALUE by CALLING the `pub(super)` mint — NO struct literal of its own.
// Pre-fix this PASSED exit 0: rule H is a struct-literal scanner (this fn has
// no literal), and rule G only inspects INHERENT methods on the cap (this is a
// free fn). It compiles and re-exports the mint to all of `crate::context`.
// Rule J flags any fn whose return type mentions the cap by value, except the
// two top-level inherent constructors and `#[cfg(test)]` items. The substring
// `fn `forge_by_value_wrapper` returns OwnedIdentityDid BY VALUE` is unique to
// this case.
#[allow(dead_code)]
pub(in crate::context) fn forge_by_value_wrapper(_d: &Did) -> OwnedIdentityDid {
    OwnedIdentityDid::issue_for_actor(Did([0; 32]))
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
// COVERAGE GAP CTM-1 (custom-trait mint) — A custom trait whose method
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
// COVERAGE GAP MHM-1 (macro-hidden mint) — tree-sitter does NOT expand
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

// @file: context/supervisor/enum_form.rs
// FIX-1 (BLACK-G05 follow-up) — ENUM FORM is REJECTED. The capability type
// MUST be a `struct`. An `enum OwnedIdentityDid { Owned(DID) }` is a HARD
// FAIL (rule F.3) because the mint guarantee rests on the single field being
// PRIVATE — a Rust enum's variants AND their fields are ALWAYS exactly as
// visible as the enum itself, so a `pub(in crate::context)` enum lets ANY
// `crate::context` code write `OwnedIdentityDid::Owned(attacker_did)` — a
// mint with NO `issue_for_actor`. The OLD field-privacy check (E) did
// `if kind != "struct": continue` and SKIPPED enums entirely, so this enum
// (with the 3 allowlisted fns and no public struct field) PASSED the gate.
// Rule F.3 now FAILs it. Diagnostic: `is declared as an `enum``. A correct
// inherent `issue_for_actor` is present so the mint-absent check (G.4) does
// not also fire — isolating the enum-form diagnostic. (The enum form CANNOT
// actually honor the private-field invariant; the mint here is cosmetic, to
// prove the gate rejects the enum on shape alone, before any mint analysis.)
#[allow(dead_code)]
pub(in crate::context) enum OwnedIdentityDid {
    Owned(Did),
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(d: &Did) -> Self {
        Self::Owned(Did(d.0))
    }
}

// @file: context/supervisor/reissue_wrong_vis.rs
// FIX-2 — `reissue` / `as_did` VISIBILITY is bounded. The accessor/clone fns
// are allowlisted by NAME (rule G) and shape-checked (`&self`, no raw-DID),
// but their VISIBILITY was previously unvalidated: a `pub fn reissue(&self)
// -> Self` PASSED. Such a fn over-exposes the clone beyond the
// `pub(in crate::context)` boundary the struct itself is held to (a `pub`
// clone would leak to downstream crates; `pub(crate)` past the context
// module tree). Rule G now asserts `reissue`/`as_did` visibility is
// inherited-private or `pub(in crate::context)` — rejecting `pub` and
// `pub(crate)`. Here `reissue` is `pub` (too broad). Diagnostic:
// `allowlisted fn `reissue` visibility is`. A correct `pub(super)
// issue_for_actor` keeps G.4 quiet and passes the allowlist gate, isolating
// the reissue-visibility diagnostic.
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
    // Over-exposed clone: `pub` lets downstream crates clone a held token.
    // Allowlisted by name + correct `&self` + no raw-DID, but the VISIBILITY
    // is what rule G now damns.
    #[allow(dead_code)]
    pub fn reissue(&self) -> Self {
        Self { inner: self.inner }
    }
}

// @file: context/supervisor/union_form.rs
// FIX-1 (union follow-up) — UNION FORM is REJECTED (rule F.4). The capability
// type MUST be a `struct`. A `union OwnedIdentityDid { did: ManuallyDrop<DID> }`
// is a HARD FAIL: a union field's visibility cannot be made private
// INDEPENDENT of the union, and union construction (`OwnedIdentityDid { did:
// … }`) is SAFE Rust — so ANY `crate::context` handler could forge the cap
// with NO `issue_for_actor`, exactly the bypass F.3 closes for enums. Before
// rule F.4 a `union_item` was NEVER collected by the decl walk (the walk took
// only struct/enum/type kinds), so EVERY decl-keyed check (B/E/F.3/G) silently
// SKIPPED the union while its inherent fns still passed the name allowlist —
// the gate waved a forgeable mint through. Diagnostic: `is declared as a
// `union``. A cosmetic `pub(super) issue_for_actor` is present so the
// mint-absent check (G.4) does not also fire — isolating the union-form
// diagnostic on shape alone, before any mint analysis. (The union form CANNOT
// honor the private-field invariant; the mint is cosmetic.)
#[allow(dead_code)]
pub(in crate::context) union OwnedIdentityDid {
    did: std::mem::ManuallyDrop<Did>,
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(d: &Did) -> Self {
        Self {
            did: std::mem::ManuallyDrop::new(Did(d.0)),
        }
    }
}

// @file: context/supervisor/generic_form.rs
// FIX-1 (GEN-01) — GENERIC FORM is REJECTED (rule F.5). The capability type
// MUST be a NON-GENERIC `struct`. A `struct OwnedIdentityDid<T = DID> { did: T }`
// PASSED the old gate: the decl walk keyed on the type NAME and never inspected
// `type_parameters`, so the generic struct satisfied location (A), struct
// name-visibility (B), no-forbidden-derives (C), private-field (E), and the
// inherent allowlist (G) — every check — while the generic parameter loosens
// the private-field TYPE (`did: T`, defaulting to `DID`) and invites a
// reviewer-introduced refactor that erodes the private-field invariant the
// `pub(super)` mint guarantee rests on. It is not an ACTIVE forgery (the field
// stays private, the mint stays `pub(super)`), but the struct-only assertion is
// supposed to be airtight. Rule F.5 now HARD FAILs the generic form on shape
// alone — tree-sitter exposes the `<…>` as the `type_parameters` field on the
// `struct_item`. Diagnostic: `MUST be a non-generic`. A cosmetic `pub(super)
// issue_for_actor` is present so the mint-absent check (G.4) does not also fire,
// isolating the generic-form diagnostic. The `issue_for_actor` is shaped to
// satisfy the allowlist (raw-DID param, no `&self`, returns `Self`).
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid<T = Did> {
    did: T,
}
struct Did([u8; 32]);
impl OwnedIdentityDid {
    #[allow(dead_code)]
    pub(super) fn issue_for_actor(d: &Did) -> Self {
        Self { did: Did(d.0) }
    }
}

// @file: context/supervisor/use_alias_impl.rs
// FIX (use-alias rename-evasion, rule F.2-use) — IMPORT-ALIAS OF THE CAP.
// Rust has exactly TWO type-renaming mechanisms: `type X = T` (banned by rule
// F.2 via `cap_aliases`) and `use … as X` (this hole). A
// `use self::OwnedIdentityDid as UseAlias;` makes `UseAlias` a SECOND name for
// the capability, so the `impl UseAlias { fn forge … -> Self { Self { did } } }`
// below mints any DID while its impl target tail is `UseAlias` ≠
// `OwnedIdentityDid`: rule G (inherent allowlist — `_impl_for_owned_identity_did`
// returns None for tail `UseAlias`), rule H (construction scan —
// `_struct_expr_constructs_cap` for `Self { … }` checks the enclosing impl
// targets the cap by tail, which `UseAlias` is not), and `_impl_targets_cap`
// ALL miss it. The forgery COMPILES and is handler-reachable (the private `did`
// field is module-scoped). Pre-fix this PASSED exit 0. Rule F.2-use bans the
// import alias outright — symmetric to F.2, with the same whole-scan-tree scope
// — so the diagnostic `use … as UseAlias` is an import alias` fires. The alias
// NAME `UseAlias` is unique to this case.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
struct Did([u8; 32]);
use self::OwnedIdentityDid as UseAlias;
impl UseAlias {
    #[allow(dead_code)]
    pub(in crate::context) fn forge(did: Did) -> Self {
        Self { did }
    }
}

// @file: context/supervisor/use_alias_group.rs
// FIX (use-alias, USE-GROUP form) — the `use_as_clause` nested inside a
// `use_list`: `use self::{OwnedIdentityDid as UseGroupAlias};`. tree-sitter
// shapes the clause's `path` as a bare `identifier` (not a `scoped_identifier`)
// here, and the clause lives several levels below the `use_declaration`; the
// collector's `walk` recurses into the list and still finds + bans it. This
// proves the use-group spelling (and the multi-import
// `use foo::{Bar, OwnedIdentityDid as Alias}` shape) is caught, not only the
// top-level qualified-path spelling. The accompanying `impl UseGroupAlias`
// forgery is the same rename-evasion as above. The alias NAME `UseGroupAlias`
// is unique to this case.
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
struct Did([u8; 32]);
use self::{OwnedIdentityDid as UseGroupAlias};
impl UseGroupAlias {
    #[allow(dead_code)]
    pub(in crate::context) fn forge(did: Did) -> Self {
        Self { did }
    }
}

// @file: context/supervisor/subtree_by_value_leak.rs
// BYPASS J2 (FIX — rule J, SUBTREE non-declaring-file by-value cap-return
// wrapper) — A free fn in ANOTHER supervisor-subtree file (NOT the declaring
// file) that returns the cap BY VALUE by calling the `pub(super)` mint. Because
// the mint is `pub(super)` (reachable across the whole `supervisor` module
// tree), this re-export compiles and is handler-reachable from any
// supervisor-subtree caller — yet the declaring-file-pinned rules (G/H, scoped
// to `identity_capability.rs`) never look here. Pre-fix this PASSED exit 0.
// Rule J is the ONE rule that scans the WHOLE subtree: it flags this fn's
// by-value cap return. The substring `fn `leak_token` returns OwnedIdentityDid
// BY VALUE` is unique to this subtree-leak case. (No cap declaration is needed
// in this file — rule J keys on the RETURN TYPE's tail identifier, not on a
// local decl; the AST gate does not resolve types.)
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) fn leak_token(_d: &Did) -> OwnedIdentityDid {
    crate::context::supervisor::identity_capability::OwnedIdentityDid::issue_for_actor(Did([0; 32]))
}

// @file: context/supervisor/cfg_test_by_value_ok.rs
// NEGATIVE CONTROL J3 (FIX — rule J cfg(test) exemption) — A `#[cfg(test)]`-gated
// fn that returns the cap BY VALUE. Rule J EXEMPTS `#[cfg(test)]` items (the real
// `#[cfg(test)] mod tests` in the declaring file mints via
// `OwnedIdentityDid::issue_for_actor(...)` and the handle.rs test mints are
// `#[cfg(test)]`-gated too — all MUST keep passing). This fn MUST NOT contribute
// any rule-J diagnostic. The self-test asserts only that REQUIRED substrings are
// PRESENT, so this negative is verified out-of-band: the orchestrator greps the
// self-test diagnostics and confirms `test_only_by_value_mint` NEVER appears. If
// the cfg(test) exemption regressed, this fn's by-value return would surface a
// rule-J diagnostic naming `test_only_by_value_mint`, and the out-of-band check
// would catch it. (The fn is INSIDE a `#[cfg(test)] mod` so `_inside_cfg_test`
// walks its ancestor chain to the test-gated module and exempts it.)
struct Did([u8; 32]);
#[cfg(test)]
mod fixture_tests_by_value {
    use super::*;
    #[allow(dead_code)]
    pub(in crate::context) fn test_only_by_value_mint(_d: &Did) -> OwnedIdentityDid {
        crate::context::supervisor::identity_capability::OwnedIdentityDid::issue_for_actor(
            Did([0; 32]),
        )
    }
}

// @file: context/supervisor/cfg_test_fn_by_value_ok.rs
// NEGATIVE CONTROL J3b (FIX — rule J cfg(test) exemption, ATTRIBUTE-ON-FN form) —
// Same intent as J3, but the `#[cfg(test)]` is placed DIRECTLY on the fn rather
// than on an enclosing `mod`. `_inside_cfg_test` only walks ANCESTORS, so a
// fn-level attribute is invisible to it; the exemption relies on the additional
// `_has_preceding_cfg_test(fn)` check (the `#[cfg(test)]` attribute is a preceding
// sibling of the `function_item`). This fn MUST NOT contribute any rule-J
// diagnostic naming `test_only_fn_by_value_mint`; if the fn-level exemption
// regressed, the out-of-band grep over the self-test diagnostics would catch it.
struct Did2([u8; 32]);
#[cfg(test)]
#[allow(dead_code)]
pub(in crate::context) fn test_only_fn_by_value_mint(_d: &Did2) -> OwnedIdentityDid {
    crate::context::supervisor::identity_capability::OwnedIdentityDid::issue_for_actor(Did2(
        [0; 32],
    ))
}

// @file: context/supervisor/k01_assoc_type_projection.rs
// BYPASS K01 (FIX — rule K, mint-call containment) — ASSOC-TYPE PROJECTION
// return disguise. A fn returns the cap via an ASSOCIATED-TYPE PROJECTION
// (`<Cz as Carry>::O` where `Carry::O = OwnedIdentityDid`), so rule J — which
// keys on the cap tail identifier appearing in the RETURN-TYPE TEXT — sees only
// `<Cz as Carry>::O` (no `OwnedIdentityDid` tail) and MISSES it. The forgery
// COMPILES, exit 0 pre-K, and is handler-reachable. But it MUST CALL the sole
// arbitrary-DID mint `issue_for_actor` to fabricate the token — rule K detects
// THAT call regardless of the disguised return type. The mint reference is
// spelled `self::OwnedIdentityDid::issue_for_actor`, UNIQUE to this fixture, so
// the diagnostic substring discriminates K01 from K02/K03.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
trait Carry {
    type O;
}
struct Cz;
impl Carry for Cz {
    type O = OwnedIdentityDid;
}
#[allow(dead_code)]
pub(in crate::context) fn forge1(d: Did) -> <Cz as Carry>::O {
    self::OwnedIdentityDid::issue_for_actor(d)
}

// @file: context/supervisor/k02_trait_method_projection.rs
// BYPASS K02 (FIX — rule K, mint-call containment) — TRAIT-METHOD PROJECTION
// mint. A trait method's return type is a PROJECTION (`Self::T` where the impl
// sets `type T = OwnedIdentityDid`), so rule J's return-type-text scan sees
// `Self::T`, not the cap tail, and MISSES the mint. Rule J ALSO does not flag
// this via its trait-fn path (that path keys on `_returns_self` / raw-DID
// params, and the projection return is neither a literal `Self` nor `-> Self`).
// The method still CALLS `issue_for_actor` to mint — rule K flags that call.
// The mint reference here is spelled `mods::OwnedIdentityDid::issue_for_actor`,
// UNIQUE to this fixture.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
mod mods {
    pub(in crate::context) use super::OwnedIdentityDid;
}
trait Mk {
    type T;
    fn mk(d: Did) -> Self::T;
}
struct MkP;
impl Mk for MkP {
    type T = OwnedIdentityDid;
    #[allow(dead_code)]
    fn mk(d: Did) -> Self::T {
        mods::OwnedIdentityDid::issue_for_actor(d)
    }
}

// @file: context/supervisor/k03_opaque_return.rs
// BYPASS K03 (FIX — rule K, mint-call containment) — OPAQUE `impl Sized`
// RETURN. A fn returns `impl Sized`, which hides the cap type ENTIRELY from any
// return-type classifier (the return text is `impl Sized` — no cap tail at
// all). Rule J cannot see the cap in the return type and MISSES it. The fn body
// CALLS `issue_for_actor` to mint the token it returns — rule K flags that
// call. The mint reference is spelled with the full canonical path
// `crate::context::supervisor::identity_capability::OwnedIdentityDid::issue_for_actor`,
// UNIQUE to this fixture.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) fn forge3(d: Did) -> impl Sized {
    crate::context::supervisor::identity_capability::OwnedIdentityDid::issue_for_actor(d)
}

// @file: context/supervisor/k04_use_rename.rs
// BYPASS K04 (FIX — rule K, use-alias rename residual) — `use …::issue_for_actor
// as MintRename;` renames the MINT fn so a later bare `MintRename(d)` call would
// dodge an identifier-keyed mint-reference scan (the call is spelled
// `MintRename`, not `issue_for_actor`). Rule K bans the import alias outright —
// the mint can only ever be NAMED `issue_for_actor` — so the rename surfaces as
// a mint reference at the `use … as` site. Note the bare `MintRename(d)` call in
// the body does NOT itself trip rule K (its identifier is `MintRename`), which is
// exactly why banning the alias is load-bearing. The alias NAME `MintRename` is
// UNIQUE to this fixture.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
use self::OwnedIdentityDid::issue_for_actor as MintRename;
#[allow(dead_code)]
pub(in crate::context) fn forge4(d: Did) -> OwnedIdentityDid {
    MintRename(d)
}

// @file: context/supervisor/supervisor.rs
// NEGATIVE CONTROL K-NEG-1 (FIX — rule K exemption b) — the ONE legitimate mint
// call site. A `build_actor_deps` method on `impl Supervisor` that calls
// `issue_for_actor` MUST PASS: this mirrors the real
// `Supervisor::build_actor_deps` (the actor-spawn mint site). Rule K exempts a
// mint reference ONLY when it lives in the real build-site FILE
// (`BUILD_SITE_REL` = `…/supervisor/supervisor.rs`, which this `@file:` block
// deliberately targets) AND its nearest enclosing `function_item` is named
// `build_actor_deps` AND its enclosing `impl_item` targets `Supervisor`. This
// fn MUST NOT contribute any rule-K diagnostic; the out-of-band forbidden-
// substring check (FORBIDDEN_FIXTURE_SUBSTRINGS) greps the self-test diagnostics
// and FAILS if `bsite_mint_ok::OwnedIdentityDid::issue_for_actor` ever appears —
// i.e. if the exemption regressed. (Distinct from the cfg(test) exemptions: this
// is PRODUCTION code that legitimately mints.)
// NOTE: the raw-DID type here is spelled `DID` to mirror the REAL production
// type (`owning_did: &DID` on `Supervisor::build_actor_deps`). The fix-3
// per-call mint-arg check is BINDING-based: it recognizes the owning parameter
// by its TYPE tail-identifier `DID`, so the build-site fixtures must use the
// production spelling to exercise that path (a fixture-local `Did` would have
// zero `DID`-typed params and wrongly dissolve the legit exemption).
struct DID([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}
mod bsite_mint_ok {
    pub(in crate::context) use super::OwnedIdentityDid;
}
struct Supervisor;
struct ActorDeps {
    owned_identity: OwnedIdentityDid,
}
impl Supervisor {
    // The real `Supervisor::build_actor_deps` returns `Result<ActorDeps, _>`,
    // NOT the cap by value — it ENCAPSULATES the minted token in `ActorDeps`.
    // The fixture mirrors that: the fn returns `ActorDeps` (not the cap), so
    // rule J (by-value cap return) does NOT fire, and rule K's build-site
    // exemption (b) must keep the EXEMPT mint CALL silent. The mint reference
    // is spelled `bsite_mint_ok::OwnedIdentityDid::issue_for_actor` — a path
    // UNIQUE to this fixture. Rule K's diagnostic echoes the reference spelling
    // in its `ref_text`; the forbidden-substring check (FORBIDDEN_FIXTURE_
    // SUBSTRINGS) greps the self-test diagnostics and FAILS if
    // `bsite_mint_ok::OwnedIdentityDid::issue_for_actor` ever appears — i.e. if
    // the build-site exemption (b) regressed and this EXEMPT call started
    // surfacing a diagnostic.
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(self: &Self, d: DID) -> ActorDeps {
        let owned_identity = bsite_mint_ok::OwnedIdentityDid::issue_for_actor(d);
        ActorDeps { owned_identity }
    }
}

// NEGATIVE CONTROL ESC-NEG-1 (KEYSTONE) — a SHARED `&OwnedIdentityDid` borrow
// parameter (read-only) MUST PASS. This is the legit `SupervisorHandle`
// per-identity shape (`fn …(identity: &OwnedIdentityDid)`). The keystone
// escape-position rule flags `&mut`/`*mut`/interior-mut, NOT a plain shared `&`,
// so this fn MUST NOT contribute any escape-position diagnostic. Its UNIQUE fn
// name `shared_borrow_ok` is in FORBIDDEN_FIXTURE_SUBSTRINGS — it appears in a
// diagnostic ONLY if the keystone over-flagged a read-only shared borrow.
#[allow(dead_code)]
pub(in crate::context) fn shared_borrow_ok(_identity: &OwnedIdentityDid) {}

// NEGATIVE CONTROL ESC-NEG-2 (KEYSTONE) — the legit `ActorDeps { owned_identity:
// OwnedIdentityDid }` PLAIN by-value owning struct field MUST PASS. A plain
// (non-`&mut`, non-wrapper) struct field is the capability's legit home (rule J
// / the keystone's by-value channel), NOT an escape. The `ActorDeps` struct
// above already has this field; this is asserted via the forbidden-substring
// negative control on the field-bearing struct's UNIQUE marker `PlainFieldOk`.
#[allow(dead_code)]
pub(in crate::context) struct PlainFieldOk {
    owned_identity: OwnedIdentityDid,
}

// BYPASS K01 (FIX 2 nested-mod-shadow + KEYSTONE out-param) — a nested `mod`
// hosting a SHADOW `struct Supervisor` whose `build_actor_deps` mints via an
// out-param. Pre-fix the shadow's `impl Supervisor` string-tail-matched
// `Supervisor` and lived in `supervisor.rs`, so the build-site exemption (b)
// trusted its body and the mint call PASSED (exit 0); the cap exfiltrated via
// the `&mut Option<…>` out-param (rule J sees only return types). Fix 2 requires
// the exempt `impl Supervisor` be TOP-LEVEL (not nested under a `mod`), so the
// shadow is NOT exempt → the mint reference is flagged by rule K. Fix 1
// (keystone) INDEPENDENTLY flags the `&mut Option<…Cap…>` out-param. The mint
// reference spelling `k01_shadow_mint::OwnedIdentityDid::issue_for_actor` is
// UNIQUE to this fixture, pinning the rule-K nested-mod-shadow assertion.
#[allow(dead_code)]
mod k01_shadow {
    use super::DID;
    mod k01_shadow_mint {
        pub(in crate::context) use super::super::OwnedIdentityDid;
    }
    struct Supervisor;
    impl Supervisor {
        fn build_actor_deps(
            &self,
            out: &mut Option<super::OwnedIdentityDid>,
            d: DID,
        ) {
            *out = Some(k01_shadow_mint::OwnedIdentityDid::issue_for_actor(d));
        }
    }
}

// BYPASS K02 (FIX 3 per-call mint-arg) — a SECOND top-level `impl Supervisor`
// whose `build_actor_deps` mints an ATTACKER DID from a CONSTRUCTED `Did(…)`
// LITERAL, not its own `owning_did` parameter. Pre-fix the build-site exemption
// trusted the ENTIRE BODY of any `Supervisor::build_actor_deps` in
// `supervisor.rs`, so this attacker-DID mint inherited the exemption (exit 0).
// Fix 3 constrains the exempt mint's sole argument to a bare parameter (or its
// `.clone()`); a constructed `Did(…)` literal is NOT a parameter, so the call is
// NOT exempt → rule K flags it. The mint spelling
// `k02_attacker_mint::OwnedIdentityDid::issue_for_actor` is UNIQUE to this
// fixture, pinning the per-call-arg assertion.
mod k02_attacker_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    // On `Supervisor::build_actor_deps` in `supervisor.rs`, top-level — so it
    // REACHES the per-call mint-arg check (fix 3). The mint's sole argument is a
    // CONSTRUCTED `Did(…)` literal, NOT the `_owning_did` parameter, so the arg
    // check returns False → the call is NOT exempt → rule K flags it. This is
    // the assertion that the build-site exemption no longer trusts the WHOLE
    // body: an attacker-DID mint in the real fn is rejected.
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, _owning_did: DID) {
        // Mints an ATTACKER DID literal, not `_owning_did`.
        let _ =
            k02_attacker_mint::OwnedIdentityDid::issue_for_actor(DID([9; 32]));
    }
}

// BYPASS K02b (FIX 3 at-most-one mint call) — a third `impl Supervisor`-shaped
// `build_actor_deps` that mints the SAME `owning_did` parameter TWICE. The FIRST
// mint is exempt (bare-param arg, build-site, top-level impl); the SECOND
// exempt-shaped mint in the SAME fn is flagged because the build-site exemption
// permits AT MOST ONE mint call per `build_actor_deps`. The diagnostic carries
// the UNIQUE phrase `SECOND exempt-shaped reference`, pinning the single-call
// assertion. (The impl target is `Supervisor` and the fn is `build_actor_deps`
// in `supervisor.rs`, top-level — so the FIRST call is genuinely exempt and the
// at-most-one count is what catches the second.)
mod k02b_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    // Named `build_actor_deps` on a `Supervisor`-tail impl in `supervisor.rs`,
    // top-level — so the FIRST mint of the bare `owning_did` param is genuinely
    // exempt (build-site exemption b). The SECOND mint of the SAME param in the
    // SAME fn is flagged by the AT-MOST-ONE check (fix 3). Uses the DISTINCT
    // `k02b_mint::…` spelling so the flagged second mint's diagnostic does NOT
    // collide with the K-NEG-1 `bsite_mint_ok::…` forbidden substring.
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> ActorDeps {
        let _first = k02b_mint::OwnedIdentityDid::issue_for_actor(owning_did);
        let owned_identity =
            k02b_mint::OwnedIdentityDid::issue_for_actor(owning_did);
        ActorDeps { owned_identity }
    }
}

// BYPASS G02 (FIX 3 per-call mint-arg — SHADOW-REBIND) — a top-level
// `impl Supervisor` whose `build_actor_deps` SHADOWS its own `owning_did`
// parameter with a `let owning_did = make_evil_did();` BEFORE the mint, then
// mints the bare `owning_did`. Pre-fix the per-call arg check was NAME-based
// (the arg identifier had to be IN the set of param names); a `let` shadow of
// the param name kept the name ∈ param_names, so the mint of the ATTACKER local
// inherited the exemption (exit 0). Fix 3 is BINDING-based and additionally
// disqualifies the exemption when a `let`/assignment re-binds the owning param
// name LEXICALLY BEFORE the mint, so the shadowed mint is NOT exempt → rule K
// flags it. The mint spelling `g02_shadow_mint::OwnedIdentityDid::issue_for_actor`
// is UNIQUE to this fixture, pinning the no-shadow assertion.
mod g02_shadow_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    // On `Supervisor::build_actor_deps` in `supervisor.rs`, top-level, with the
    // sole `DID`-typed parameter `owning_did` — so it REACHES the per-call
    // mint-arg check. A `let owning_did = make_evil_did();` shadow precedes the
    // mint, so the bare `owning_did` argument resolves to an ATTACKER local, not
    // the caller-supplied parameter. The no-shadow arm (fix 3) refuses the
    // exemption → rule K flags the mint.
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> ActorDeps {
        let owning_did = make_evil_did();
        let owned_identity =
            g02_shadow_mint::OwnedIdentityDid::issue_for_actor(owning_did);
        ActorDeps { owned_identity }
    }
}
#[allow(dead_code)]
fn make_evil_did() -> DID {
    DID([7; 32])
}

// BYPASS G03 (FIX 3 per-call mint-arg — ADDED DID PARAM) — a top-level
// `impl Supervisor` whose `build_actor_deps` declares a SECOND `DID`-typed
// parameter (`attacker: DID`) and mints from IT, not the genuine `owning_did`.
// Pre-fix the per-call arg check accepted ANY param name, so an attacker param
// was IN the set of param names and the mint of `attacker` inherited the
// exemption (exit 0). Fix 3 requires EXACTLY ONE non-`self` `DID`-typed
// parameter; a second `DID` param makes the owning binding ambiguous, so the
// exemption is refused outright → rule K flags the mint. The mint spelling
// `g03_added_param_mint::OwnedIdentityDid::issue_for_actor` is UNIQUE to this
// fixture, pinning the single-DID-param assertion.
mod g03_added_param_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    // On `Supervisor::build_actor_deps` in `supervisor.rs`, top-level, but with
    // TWO `DID`-typed parameters (`owning_did` and `attacker`). The single-DID-
    // param requirement (fix 3) fails (2 ≠ 1), so NO mint in this body can be
    // exempt — including the `attacker.clone()` mint of the attacker DID.
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: DID,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            g03_added_param_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// BYPASS A-MATCH-ARM (FIX — pattern-binding shadow via `match`) — a top-level
// `impl Supervisor` whose `build_actor_deps` re-binds its `owning_did` parameter
// through a `match` ARM PATTERN (NOT a `let`/assignment), then mints the bare
// (now attacker-controlled) `owning_did` inside the arm body. Pre-fix
// `_shadows_before` walked only `let_declaration` + `assignment_expression`, so a
// `match make_evil_did() { owning_did => issue_for_actor(owning_did.clone()) }`
// re-bind slipped: the bare `owning_did` resolved to attacker data yet the arg
// check saw an un-shadowed param name → exempt (exit 0). The fix treats a
// `match_arm` pattern binding `owning_did` that ENCLOSES the mint as a shadow, so
// the exemption is refused → rule K flags the mint. Spelling
// `a_match_arm_mint::…` is UNIQUE.
mod a_match_arm_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> ActorDeps {
        match make_evil_did() {
            owning_did => {
                let owned_identity =
                    a_match_arm_mint::OwnedIdentityDid::issue_for_actor(owning_did.clone());
                ActorDeps { owned_identity }
            }
        }
    }
}

// BYPASS A-IF-LET (FIX — pattern-binding shadow via `if let`) — a top-level
// `impl Supervisor` whose `build_actor_deps` re-binds `owning_did` through an
// `if let` CONDITION PATTERN (a `let_condition` node, NOT a `let_declaration`),
// then mints the bare `owning_did` in the if-body. The `let_condition` pattern
// shadow ENCLOSES the mint; the fix treats it as a rebind → not exempt → rule K
// flags it. Spelling `a_if_let_mint::…` is UNIQUE.
mod a_if_let_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> Option<ActorDeps> {
        if let owning_did = make_evil_did() {
            let owned_identity =
                a_if_let_mint::OwnedIdentityDid::issue_for_actor(owning_did.clone());
            return Some(ActorDeps { owned_identity });
        }
        None
    }
}

// BYPASS A-WHILE-LET (FIX — pattern-binding shadow via `while let`) — the
// `while let` spelling of the `let_condition` shadow. Same node type
// (`let_condition`) as the `if let` case, so catching this proves the
// `while let` head too. Spelling `a_while_let_mint::…` is UNIQUE.
mod a_while_let_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> Option<ActorDeps> {
        while let owning_did = make_evil_did() {
            let owned_identity =
                a_while_let_mint::OwnedIdentityDid::issue_for_actor(owning_did.clone());
            return Some(ActorDeps { owned_identity });
        }
        None
    }
}

// BYPASS A-FOR-PATTERN (FIX — pattern-binding shadow via `for`) — a top-level
// `impl Supervisor` whose `build_actor_deps` re-binds `owning_did` through a
// `for` LOOP PATTERN (a `for_expression` `pattern` field), then mints the bare
// `owning_did` in the loop body. The `for` binder ENCLOSES the mint; the fix
// treats it as a rebind → not exempt → rule K flags it. Spelling
// `a_for_pattern_mint::…` is UNIQUE.
mod a_for_pattern_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> Option<ActorDeps> {
        for owning_did in core::iter::once(make_evil_did()) {
            let owned_identity =
                a_for_pattern_mint::OwnedIdentityDid::issue_for_actor(owning_did.clone());
            return Some(ActorDeps { owned_identity });
        }
        None
    }
}

// BYPASS A-CLOSURE-PARAM (FIX — pattern-binding shadow via closure param) — a
// top-level `impl Supervisor` whose `build_actor_deps` re-binds `owning_did`
// through a CLOSURE PARAMETER (`closure_expression` `parameters` field), then
// mints the bare `owning_did` in the closure body — invoking the closure with an
// attacker DID. The closure-param binder ENCLOSES the mint; the fix treats it as
// a rebind → not exempt → rule K flags it. (The escapable-scope guard ALSO fires
// on the intervening closure; either independently dissolves the exemption — the
// mint is flagged regardless.) Spelling `a_closure_param_mint::…` is UNIQUE.
mod a_closure_param_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> ActorDeps {
        let _ = owning_did;
        let owned_identity = (|owning_did: DID| {
            a_closure_param_mint::OwnedIdentityDid::issue_for_actor(owning_did.clone())
        })(make_evil_did());
        ActorDeps { owned_identity }
    }
}

// BYPASS B-CLOSURE-LAUNDERED (FIX — escapable-scope guard) — a top-level
// `impl Supervisor` whose `build_actor_deps` mints its OWN un-shadowed
// `owning_did` (so the per-call arg check WOULD pass) but does so INSIDE a
// `closure_expression` that the fn RETURNS. The closure's nearest enclosing
// `function_item` is still `build_actor_deps`, so pre-fix the mint inherited the
// build-site exemption (exit 0) — yet the returned closure can be invoked LATER
// by handler code with the captured token, the same deferred-execution threat
// rules H/I guard at construction sites. The escapable-scope guard
// (`_escapable_scope_between`) detects the intervening `closure_expression`
// between the mint and `build_actor_deps` → not exempt → rule K flags it. The
// closure captures `owning_did` (no closure PARAMETER shadows it, isolating the
// escapable-scope arm from the closure-param-shadow case above). Spelling
// `b_closure_launder_mint::…` is UNIQUE.
mod b_closure_launder_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: DID,
    ) -> Box<dyn Fn() -> OwnedIdentityDid> {
        Box::new(move || {
            b_closure_launder_mint::OwnedIdentityDid::issue_for_actor(owning_did.clone())
        })
    }
}

// BYPASS C-DID-TYPE-ALIAS (FIX — DID-type-alias defeats sole-DID-param count) —
// a `type GoodId = DID;` alias on the OWNING parameter plus a second, literal-
// `DID` ATTACKER parameter. The per-call mint-arg check counts the sole non-
// `self` param whose TYPE tail is the literal `DID`; pre-fix the alias hid the
// owning param's `DID`-ness, leaving `attacker: DID` as the only literal-`DID`
// param — it was pinned as the owning binding and the attacker DID was minted
// (exit 0). The fix BANS any `type X = …DID` in the subtree, so the alias itself
// is flagged (the count never even runs on this fn). The alias NAME `GoodId` is
// UNIQUE to this fixture.
type GoodId = DID;
mod c_did_type_alias_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: GoodId,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            c_did_type_alias_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// BYPASS C-DID-USE-ALIAS (FIX — DID-import-alias defeats sole-DID-param count) —
// a `use super::DID as ImportedId;` import alias on the OWNING parameter plus a
// second, literal-`DID` ATTACKER parameter. Same threat as the `type` form: the
// alias hides the owning param's `DID`-ness so the attacker param is the only
// literal-`DID` param. The fix BANS any `use …DID as X` in the subtree; the
// alias is flagged outright. The alias NAME `ImportedId` is UNIQUE to this
// fixture. (`DID` is re-imported via `super::DID` so the `use … as` path tail is
// the literal `DID`.)
use super::DID as ImportedId;
mod c_did_use_alias_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: ImportedId,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            c_did_use_alias_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// BYPASS A-SHORTHAND-LET (FIX 1 — struct-pattern field-SHORTHAND shadow via
// `let`) — a top-level `impl Supervisor` whose `build_actor_deps` re-binds its
// `owning_did` parameter through a `let Foo { owning_did } = …;` struct-pattern
// field SHORTHAND, then mints the bare (now attacker-controlled) `owning_did`.
// A shorthand field binds the local via a `shorthand_field_identifier` node
// (NOT an `identifier`); pre-fix `_pattern_binds` matched only `identifier`, so
// the shorthand shadow slipped the shadow guard and the attacker DID was
// wrongly exempted (gate exit 0). Fix 1 matches BOTH binder leaf types, so the
// shorthand `let` rebind is recognized as a shadow → not exempt → rule K flags
// it. Spelling `a_shorthand_let_mint::…` is UNIQUE.
struct ShorthandSrc {
    owning_did: DID,
}
#[allow(dead_code)]
fn make_evil_shorthand() -> ShorthandSrc {
    ShorthandSrc {
        owning_did: DID([3; 32]),
    }
}
mod a_shorthand_let_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> ActorDeps {
        let ShorthandSrc { owning_did } = make_evil_shorthand();
        let owned_identity =
            a_shorthand_let_mint::OwnedIdentityDid::issue_for_actor(owning_did);
        ActorDeps { owned_identity }
    }
}

// BYPASS A-SHORTHAND-MATCH (FIX 1 — struct-pattern field-SHORTHAND shadow via
// `match` arm) — a top-level `impl Supervisor` whose `build_actor_deps` re-binds
// `owning_did` through a `match … { Foo { owning_did } => … }` arm-pattern field
// SHORTHAND, then mints the bare `owning_did` in the arm body. Same
// `shorthand_field_identifier`-binder evasion as the `let` form, exercised via
// the `match_arm` `_PATTERN_BINDER_FIELDS` path: pre-fix the shorthand binder in
// the arm pattern was not recognized, so the shadow slipped and the attacker DID
// was exempted (exit 0). Fix 1 recognizes the shorthand binder → shadow → not
// exempt → rule K flags it. Spelling `a_shorthand_match_mint::…` is UNIQUE.
mod a_shorthand_match_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> ActorDeps {
        match make_evil_shorthand() {
            ShorthandSrc { owning_did } => {
                let owned_identity =
                    a_shorthand_match_mint::OwnedIdentityDid::issue_for_actor(owning_did);
                ActorDeps { owned_identity }
            }
        }
    }
}

// BYPASS F5-GENERIC (FIX 2 — generic `build_actor_deps` launders the literal-
// `DID` count) — a top-level `impl Supervisor` whose `build_actor_deps` is
// GENERIC (`<D: Into<DID>>`), takes the owning param as `&D`, and adds a literal-
// `DID` ATTACKER param. The per-call mint-arg check counts the sole non-`self`
// param whose TYPE tail is the literal `DID`; pre-fix `&D` had tail `D` ≠ `DID`,
// so the ATTACKER `DID` param was the only literal-`DID` param and was pinned as
// the owning binding — the attacker DID was minted (exit 0). Fix 2 refuses the
// exemption outright when `build_actor_deps` is declared generic (carries
// `type_parameters`), because the literal-`DID`-param count is UNSOUND under
// generics → rule K flags the mint. Spelling `f5_generic_mint::…` is UNIQUE.
mod f5_generic_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps<D: Into<DID>>(
        &self,
        owning_did: &D,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            f5_generic_mint::OwnedIdentityDid::issue_for_actor(attacker);
        ActorDeps { owned_identity }
    }
}

// BYPASS TI-IMPL (FIX — owning-param TYPE INDIRECTION via `impl Trait`) — a
// top-level `impl Supervisor` whose `build_actor_deps` spells the OWNING param as
// `impl Into<DID> + Clone` (anonymous-generic `impl Trait` in argument position,
// a `bounded_type` whose `_param_type_tail` is None — NO `type_parameters` node,
// so the generic-`<D>` ban CANNOT see it) and adds a literal-`DID` `attacker`
// param, minting `attacker`. Pre-fix the build-site exemption counted params
// whose TYPE tail was literally `DID` and required that count == 1: the owning
// `impl Into<DID>` was NOT counted (tail None), so the ATTACKER became the sole
// counted `DID` param and was wrongly pinned as the owning binding — minting the
// attacker. The POSITIVE assertion requires EXACTLY ONE non-`self` parameter
// whose tail is literally `DID`; the `attacker` param makes the non-`self` count
// 2 (and the owning tail is None ≠ `DID`), so the exemption is refused → rule K
// flags the mint. Spelling `ti_impl_mint::…` is UNIQUE.
mod ti_impl_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: impl Into<DID> + Clone,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            ti_impl_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// BYPASS TI-DYN (FIX — owning-param TYPE INDIRECTION via `&dyn Trait`) — the
// trait-object spelling of the same indirection: the OWNING param is
// `&dyn AsRef<DID>` (a `reference_type` wrapping a trait object; after the `&`
// peel its `_param_type_tail` is None), plus a literal-`DID` `attacker` param,
// minting `attacker`. Same pre-fix defeat (owning tail None → attacker is the
// sole counted `DID`). The positive assertion refuses it (non-`self` count 2,
// owning tail ≠ `DID`) → rule K flags the mint. Spelling `ti_dyn_mint::…` is
// UNIQUE.
mod ti_dyn_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: &dyn AsRef<DID>,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            ti_dyn_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// BYPASS TI-PROJ (FIX — owning-param TYPE INDIRECTION via ASSOC-TYPE PROJECTION)
// — the OWNING param is an associated-type projection `<Self as OwnId>::T` (a
// `scoped_type_identifier` whose tail is `T` ≠ `DID`), plus a literal-`DID`
// `attacker` param, minting `attacker`. Pre-fix the owning param's tail `T` was
// not counted as `DID`, so the attacker became the sole counted `DID` param. The
// positive assertion refuses it (non-`self` count 2, owning tail `T` ≠ `DID`) →
// rule K flags the mint. Spelling `ti_proj_mint::…` is UNIQUE. (`OwnId` is an
// undeclared trait in the fixture — irrelevant: the gate is a STRUCTURAL scan,
// not a type-checker, so the projection's tail-identifier is all that matters.)
mod ti_proj_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
trait OwnId {
    type T;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: <Self as OwnId>::T,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            ti_proj_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// BYPASS TI-WRAP (FIX — owning-param TYPE INDIRECTION via NEWTYPE WRAPPER) — the
// OWNING param is `&DidWrap` where `DidWrap` is a plain NEWTYPE `struct
// DidWrap(DID)` (after the `&` peel, tail `DidWrap` ≠ `DID`), plus a literal-`DID`
// `attacker` param, minting `attacker`. The wrapper is spelled as a NEWTYPE (NOT
// a `type DidWrap = DID;` alias): a module-level `type … = DID` alias is
// INDEPENDENTLY banned by the DID-type-alias rule, so using a newtype here
// ISOLATES the type-indirection rule under test (the failure must come from the
// owning-param positive assertion, not the alias ban). Pre-fix the owning tail
// `DidWrap` was not counted as `DID`, so the attacker became the sole counted
// `DID` param. The positive assertion refuses it (non-`self` count 2, owning tail
// `DidWrap` ≠ `DID`) → rule K flags the mint. Spelling `ti_wrap_mint::…` is
// UNIQUE.
struct DidWrap(DID);
mod ti_wrap_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        &self,
        owning_did: &DidWrap,
        attacker: DID,
    ) -> ActorDeps {
        let _keep = owning_did;
        let owned_identity =
            ti_wrap_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// BYPASS NESTED-FN-DIRECT (FIX 1 — direct-impl-method ban) — a nested
// `fn build_actor_deps(owning_did: &DID)` declared lexically INSIDE the REAL
// `Supervisor::build_actor_deps` body, minting `owning_did.clone()` DIRECTLY.
// Pre-fix this passed every mint-call-exemption check: its nearest
// `function_item` is named `build_actor_deps`; its nearest `impl_item` is the
// real top-level `impl Supervisor`; it is not generic / nested-mod-shadowed;
// there is NO intervening escapable scope (the nested fn IS `fn_node`, the
// boundary); it has exactly one non-`self` `&DID` param and mints that bare
// `owning_did` — so `_mint_ref_exempt_build_actor_deps` returned True and the
// mint PASSED (exit 0). But the nested fn's `owning_did` is INSIDER-CONTROLLED
// at the nested fn's call site (`build_actor_deps(&DID([9; 32]))`, a plain
// `call_expression` the gate never inspects), NOT the trusted supervisor-
// supplied DID. The construction path already rejects a nested constructor via
// its `is_impl_method` guard; the mint-call exemption was the PARALLEL path that
// lacked it. Fix 1 requires the exempt fn's parent chain be
// `function_item -> declaration_list -> impl_item`; a nested fn's parent is a
// `block`, so the guard is False → the nested mint is NOT exempt → rule K flags
// it. The mint spelling `nested_fn_direct_mint::OwnedIdentityDid::issue_for_actor`
// is UNIQUE to this fixture, pinning the direct-impl-method assertion. (The OUTER
// `build_actor_deps` does not itself mint — it only declares + calls the nested
// fn — so the ONLY rule-K reference in this block is the nested mint.)
mod nested_fn_direct_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    // The REAL top-level `Supervisor::build_actor_deps` in `supervisor.rs`. Its
    // body declares a NESTED `fn build_actor_deps` that mints its own param. The
    // nested fn passes the name/impl/scope/param checks but is NOT a direct impl
    // method, so fix 1 refuses its exemption and rule K flags the nested mint.
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, _owning_did: DID) -> ActorDeps {
        fn build_actor_deps(owning_did: &DID) -> OwnedIdentityDid {
            nested_fn_direct_mint::OwnedIdentityDid::issue_for_actor(owning_did.clone())
        }
        let owned_identity = build_actor_deps(&DID([9; 32]));
        ActorDeps { owned_identity }
    }
}

// BYPASS SECOND-SELF-PARAM (FIX 2 — positional + count-bounded self-exclusion) —
// a top-level `impl Supervisor` whose `build_actor_deps` carries a SECOND
// `self`-spelled parameter at index ≥ 1: `(self: &Arc<Self>, attacker: DID,
// self: &Handle)`. tree-sitter is error-tolerant, so it tags BOTH `self`-spelled
// params as receiver-shaped. The PRIOR self-exclusion dropped EVERY receiver-
// shaped param regardless of position/count, leaving `attacker: DID` as the
// "sole non-`self` param" → wrongly pinned as the owning binding → the
// `attacker` mint inherited the exemption (rustc rejects this spelling, so it is
// not live-exploitable, but the gate must NOT depend on rustc). Fix 2 enforces
// the receiver invariant STRUCTURALLY: a receiver-shape at value-index ≥ 1 (the
// trailing `self: &Handle`) is malformed → REFUSE the exemption (fail-closed) →
// rule K flags the mint. The mint spelling
// `second_self_param_mint::OwnedIdentityDid::issue_for_actor` is UNIQUE to this
// fixture, pinning the positional-self assertion. (The production
// `build_actor_deps(self: &Arc<Self>, owning_did: &DID)` has exactly ONE
// receiver-shape in first position and stays exempt — asserted by K-NEG-1.)
mod second_self_param_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(
        self: &Arc<Self>,
        attacker: DID,
        self: &Handle,
    ) -> ActorDeps {
        let owned_identity =
            second_self_param_mint::OwnedIdentityDid::issue_for_actor(attacker.clone());
        ActorDeps { owned_identity }
    }
}

// NEGATIVE CONTROL RENAMED-FIELD-OK (FIX 1) — a top-level `impl Supervisor`
// whose `build_actor_deps` destructures an UNRELATED struct via a RENAMED field
// whose field NAME is LITERALLY `owning_did`: `let RenamedSrc { owning_did: other
// } = …;`. This deliberately places the token `owning_did` in the FIELD-NAME
// position (a `field_identifier` node) while the actually-bound local is `other`
// (an `identifier` node). The distinction is the whole point of fix 1: a binder
// is spelled either `identifier` (`Foo(x)` / `Foo { f: x }` renamed field) or
// `shorthand_field_identifier` (`Foo { owning_did }` shorthand, where the field
// NAME is ALSO the bound local). A RENAMED field's NAME is a `field_identifier`,
// which is NEITHER binder leaf type, so it binds NOTHING — only the renamed-to
// `other` (`identifier`) is bound. An over-broad matcher that wrongly treated
// `field_identifier` as a binder would see `owning_did` "shadowed" here and
// wrongly dissolve the exemption. Because `_pattern_binds` matches ONLY
// `identifier`/`shorthand_field_identifier`, the field-name `owning_did` binds
// nothing, the genuine `owning_did` PARAMETER stays un-shadowed, and the exempt
// mint MUST stay EXEMPT (PASS). Proves fix 1 added NO false positive on the
// renamed-field spelling even when the field NAME collides with the owning
// param's name. The UNIQUE exempt mint spelling
// `renamed_field_ok::OwnedIdentityDid::issue_for_actor` is in
// FORBIDDEN_FIXTURE_SUBSTRINGS — it appears in a diagnostic ONLY if the renamed-
// field destructure wrongly dissolved the legit build-site exemption.
struct RenamedSrc {
    owning_did: u8,
}
#[allow(dead_code)]
fn make_renamed_src() -> RenamedSrc {
    RenamedSrc { owning_did: 0 }
}
mod renamed_field_ok {
    pub(in crate::context) use super::OwnedIdentityDid;
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, owning_did: DID) -> ActorDeps {
        let RenamedSrc { owning_did: other } = make_renamed_src();
        let _ = other;
        let owned_identity =
            renamed_field_ok::OwnedIdentityDid::issue_for_actor(owning_did);
        ActorDeps { owned_identity }
    }
}

// NEGATIVE CONTROL BODY-LOCAL-DID-ALIAS-OK (FIX 3) — a free function in the
// supervisor SUBTREE whose body declares a body-local `type BodyLocalDidAliasOk
// = DID;` and a body-local `use super::DID as BodyLocalUseAliasOk;`. A body-local
// alias inside a free-function body has NO scope over any parameter SIGNATURE
// (signatures resolve types in the enclosing MODULE scope, never inside a fn
// body), so it can NEVER launder the build-site param count — banning it was an
// over-broad false-positive. Fix 3 excludes body-local aliases from BOTH the
// `type X = …DID` ban and the `use …DID as X` ban via `_is_body_local`, so this
// fn MUST PASS (produce NO DID-alias diagnostic). The UNIQUE markers
// `BodyLocalDidAliasOk` and `BodyLocalUseAliasOk` are in
// FORBIDDEN_FIXTURE_SUBSTRINGS — either appears in a diagnostic ONLY if a
// body-local alias was wrongly flagged (the fix regressed). NOTE: the MODULE-
// level DID-alias threat stays caught — the C-DID-TYPE-ALIAS / C-DID-USE-ALIAS
// bypass fixtures above (module-level `type GoodId = DID;` / `use super::DID as
// ImportedId;`) still FAIL, asserting the real threat is unaffected.
#[allow(dead_code)]
fn body_local_did_alias_ok(owning_did: DID) -> DID {
    type BodyLocalDidAliasOk = DID;
    use super::DID as BodyLocalUseAliasOk;
    let _local: BodyLocalDidAliasOk = DID([0; 32]);
    let _imported: BodyLocalUseAliasOk = owning_did;
    _local
}

// @file: context/supervisor/k02_static_sink.rs
// BYPASS K02-SINK (KEYSTONE — `static`/`const` by-value sink) — a module-level
// `static mut` holding the cap BY VALUE in an `Option<…>`. Pre-keystone a static
// sink was an exfil channel rules J (return) and K (mint call) never scanned: a
// handler could `mem::take(&mut SINK)` an owned token out. The keystone's
// static/const arm flags ANY cap occurrence in a `static`/`const` not solely
// behind a SHARED `&`. The UNIQUE marker `K02_STATIC_SINK` pins this case.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
#[allow(dead_code)]
static mut K02_STATIC_SINK: Option<OwnedIdentityDid> = None;

// @file: context/supervisor/k_neg_cfg_test_ok.rs
// NEGATIVE CONTROL K-NEG-2 (FIX — rule K exemption c) — a `#[cfg(test)]` fn that
// CALLS `issue_for_actor`. A test-only mint reference is not in the production
// binary and can never be a handler-reachable forgery, so rule K exempts it
// (reusing the rule-J `_inside_cfg_test` / `_has_preceding_cfg_test` checks).
// This mirrors the real `#[cfg(test)] mod tests` mints in the declaring file and
// the `#[cfg(test)]` handle.rs test mints — all MUST keep passing. This fn MUST
// NOT contribute any rule-K diagnostic. The mint reference is spelled
// `cfgtest_mint_ok::OwnedIdentityDid::issue_for_actor` — a path UNIQUE to this
// fixture; the forbidden-substring check FAILS if that spelling appears in the
// self-test diagnostics, catching a regressed cfg(test) exemption.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
mod cfgtest_mint_ok {
    pub(in crate::context) use super::OwnedIdentityDid;
}
#[cfg(test)]
mod fixture_tests_mint_ref {
    use super::*;
    #[allow(dead_code)]
    pub(in crate::context) fn cfg_test_mint_ref_ok(d: Did) -> OwnedIdentityDid {
        cfgtest_mint_ok::OwnedIdentityDid::issue_for_actor(d)
    }
}

// @file: context/supervisor/k03_paste_glob.rs
// BYPASS K03 (FIX 4 glob + reassembly-macro + KEYSTONE out-param) — the
// token-split mint forgery. A glob `use …identity_capability::*;` drags the cap
// into the module under its bare name, a `paste!` macro INVOCATION reassembles
// the mint identifier `[<issue _for_actor>]` from split tokens (which
// tree-sitter never rejoins), and the result is exfiltrated via a `&mut
// Option<…Cap…>` out-param. Pre-fix all three slipped: the glob hid the cap name
// from rule G/H/K recognition, the split tokens hid the mint from the
// identifier-keyed scan, and the out-param hid the cap from rule J (return-only).
// Fix 4 INDEPENDENTLY flags (a) the glob import `use …identity_capability::*`
// and (b) the `paste!` reassembly-macro invocation; fix 1 (keystone) flags the
// `&mut Option<…>` out-param. The glob/macro/out-param all carry distinct
// diagnostics asserted below.
struct Did([u8; 32]);
use crate::context::supervisor::identity_capability::*;
#[allow(dead_code)]
fn k03_leak(out: &mut Option<OwnedIdentityDid>, d: Did) {
    paste::paste! {
        *out = Some(OwnedIdentityDid::[<issue _for_actor>](d));
    }
}

// @file: context/supervisor/keystone_mut_param.rs
// BYPASS ESC1 (KEYSTONE — `&mut OwnedIdentityDid` out-param). The plainest
// escape: a fn parameter typed `&mut OwnedIdentityDid`. A holder of the `&mut`
// can overwrite / move out an owned token. Rule J (return-only) and rule K
// (mint-call) never see it. The keystone flags the `&mut Cap` param. The UNIQUE
// fn name `mut_out_param_escape` pins this shape.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
#[allow(dead_code)]
pub(in crate::context) fn mut_out_param_escape(_out: &mut OwnedIdentityDid) {}

// @file: context/supervisor/keystone_interior_mut.rs
// BYPASS ESC2 (KEYSTONE — interior-mutability wrapper field). A struct field
// `Mutex<OwnedIdentityDid>` hands out an owned token to anyone holding a SHARED
// `&` to the struct (via `.lock()`), defeating the `&OwnedIdentityDid`
// read-only-borrow contract. The keystone flags the cap inside an interior-mut
// wrapper ANYWHERE (here a struct field). The UNIQUE field-bearing struct marker
// `InteriorMutHolder` pins this shape; the `&mut Vec<…Cap…>` param below
// (ESC3) exercises the `&mut`-wrapping-a-collection path in the SAME file.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
#[allow(dead_code)]
pub(in crate::context) struct InteriorMutHolder {
    cell: std::sync::Mutex<OwnedIdentityDid>,
}
// BYPASS ESC3 (KEYSTONE — `&mut Vec<…Cap…>` out-param). The cap behind a `&mut`
// INSIDE a collection generic — a holder can `.push()` / drain owned tokens. The
// keystone propagates the `&mut` escape context into the `Vec<…>` args. The
// UNIQUE fn name `mut_vec_out_param` pins this shape.
#[allow(dead_code)]
pub(in crate::context) fn mut_vec_out_param(_out: &mut Vec<OwnedIdentityDid>) {}

// @file: context/supervisor/bare_list_mint_use.rs
// BYPASS FIX5 (bare `use_list` member of the mint, no `as`). A
// `use self::{issue_for_actor};` imports the mint under its bare name with NO
// `as` rename — enabling a later bare `issue_for_actor(d)` call. Pre-fix
// `_is_mint_reference` deferred EVERY use-path member to the `as`-rename ban
// (which only catches `as`), so a bare list member slipped through. Fix 5 now
// flags a BARE `use_list`/`scoped_use_list` member of the mint as a reference
// (the `as` form is still deferred to the rename ban). The diagnostic is the
// standard rule-K mint-reference; the UNIQUE module path
// `bare_list_src::issue_for_actor` (the imported path) and the surrounding
// context make this assertion isolable via the `issue_for_actor` reference text.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
mod bare_list_src {
    pub(in crate::context) use super::OwnedIdentityDid::issue_for_actor;
}
use bare_list_src::{issue_for_actor};

// @file: context/supervisor/file_pin_forgery_in_subtree.rs
// BYPASS FIX6 (POSITIVE FILE-PIN, in-subtree) — a fake `impl Supervisor { fn
// build_actor_deps { …issue_for_actor… } }` planted in a supervisor-SUBTREE file
// that is NOT the real build-site `supervisor.rs`. The build-site exemption is
// pinned to `BUILD_SITE_REL` (= `…/supervisor/supervisor.rs`); a same-named
// `Supervisor::build_actor_deps` in this DIFFERENT subtree file is NOT exempt,
// so rule K flags its mint reference. This is the POSITIVE assertion that the
// file pin holds: drop the pin and this forgery PASSES. The mint spelling
// `file_pin_mint::OwnedIdentityDid::issue_for_actor` is UNIQUE to this fixture.
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
}
mod file_pin_mint {
    pub(in crate::context) use super::OwnedIdentityDid;
}
struct Supervisor;
struct ActorDeps {
    owned_identity: OwnedIdentityDid,
}
impl Supervisor {
    #[allow(dead_code)]
    pub(in crate::context) fn build_actor_deps(&self, d: Did) -> ActorDeps {
        // NOT exempt: this is not the real `supervisor.rs` build-site file.
        let owned_identity = file_pin_mint::OwnedIdentityDid::issue_for_actor(d);
        ActorDeps { owned_identity }
    }
}
