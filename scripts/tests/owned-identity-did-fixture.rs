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
struct Did([u8; 32]);
#[allow(dead_code)]
pub(in crate::context) struct OwnedIdentityDid {
    did: Did,
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
    pub(in crate::context) fn build_actor_deps(self: &Self, d: Did) -> ActorDeps {
        let owned_identity = bsite_mint_ok::OwnedIdentityDid::issue_for_actor(d);
        ActorDeps { owned_identity }
    }
}

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
