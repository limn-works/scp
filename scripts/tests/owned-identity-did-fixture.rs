// ---------------------------------------------------------------------------
// Self-test fixtures for scripts/check-owned-identity-did.py.
//
// This file is deliberately NOT compiled by cargo — it lives under
// `scripts/tests/` and is consumed only by the CI definition-shape checker.
// DO NOT add `mod owned_identity_did_fixture;` anywhere. This is never built.
//
// HARNESS FORMAT
// --------------
// The file is a sequence of independent fixtures. Each fixture is one
// self-contained `identity_capability.rs` candidate, introduced by a
// sentinel line of the form:
//
//     // @file: <name> [REJECT]
//     // @file: <name> [ACCEPT]
//     // @file: <name> [REJECT] mod=<stub-key>
//
// The block runs from one `// @file:` line to the next (or EOF). At
// self-test time the scanner writes each block's body to a temp staging
// tree at the REQUIRED path
// `crates/scp-runtime/src/context/supervisor/identity_capability.rs`, plus a
// sibling `supervisor/mod.rs`. By default the mod.rs stub carries a real
// `#![deny(unsafe_code)]` so the A5 presence check is satisfied and is NEVER
// the cause of a [REJECT]. A trailing `mod=<stub-key>` token selects an
// alternate mod.rs stub (see `_MOD_RS_STUBS` in the checker) to exercise the
// A5 deny-parse false-pos / false-neg guards. Then it scans in ISOLATION:
//
//   - `[REJECT]` fixtures MUST be rejected (scan exits non-zero) — each is
//     a minimal forgery of one definition-shape invariant.
//   - `[ACCEPT]` fixtures MUST be accepted (scan exits zero).
//
// The kernel asserts the DEFINITION shape via a POSITIVE FROZEN-SHAPE
// WHITELIST: it enumerates the file's module-level items and rejects any item
// KIND that is not on the permitted list (use / one struct / one inherent
// impl / one cfg(test) mod tests), then asserts the exact struct + impl shape.
// It does NOT inspect call sites, build sites, or mint arguments —
// construction confinement is the type system's job. So there are NO
// build-site / shadow / attribute-macro / glob-use / metavariable-macro
// fixtures here: that entire class of USE-SITE analysis was deleted. The
// fixtures below instead probe DEFINITION-side evasions the positive whitelist
// closes by construction: `type` aliases, path-qualified impls, and
// comment-interleaved derives.
// ---------------------------------------------------------------------------

// @file: positive [ACCEPT]
// The real struct shape: `pub(in crate::context)` struct, single private
// `did` field, exactly the three allowlisted inherent methods with their
// required visibilities and signatures, plus a `#[cfg(test)] mod tests`
// that only CALLS the allowlisted API (never struct-literal-constructs).
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }

    pub(in crate::context) fn reissue(&self) -> Self {
        Self {
            did: self.did.clone(),
        }
    }

    #[allow(dead_code)]
    #[must_use]
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_token_exposes_did_by_reference() {
        let did = DID("did:example:alice".to_owned());
        let token = OwnedIdentityDid::issue_for_actor(did.clone());
        assert_eq!(token.as_did(), &did);
    }
}

// @file: positive_deny_extra_lints [ACCEPT] mod=deny_extra_lints
// A5 false-pos guard: supervisor/mod.rs carries
// `#![deny(unsafe_code, missing_docs)]` (extra lints). The real-parse deny
// check MUST still be satisfied by the extra-lints form.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: positive_test_mod_struct_literal [ACCEPT]
// A4 location-exemption positive: the `#[cfg(test)] mod tests` body itself
// struct-literal-constructs `OwnedIdentityDid { .. }`. The construction check is
// LOCATION-BASED and NAME-AGNOSTIC — a struct literal inside the non-production
// cfg(test) module is exempt by LOCATION (not by its type name), so this MUST be
// accepted. Pairs with the production rule: the same literal outside any
// allowlisted method body or the test module would be rejected by location.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction_in_cfg_test_is_exempt() {
        let token = OwnedIdentityDid {
            did: DID("did:example:test".to_owned()),
        };
        assert_eq!(token.as_did(), &DID("did:example:test".to_owned()));
    }
}

// @file: pub_struct_visibility [REJECT]
// Struct name-visibility is `pub` — too broad. MUST be exactly
// `pub(in crate::context)`.
use scp_identity::DID;

pub struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: pub_crate_struct_visibility [REJECT]
// Struct name-visibility is `pub(crate)` — too broad. MUST be exactly
// `pub(in crate::context)`.
use scp_identity::DID;

pub(crate) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: public_field [REJECT]
// The single field carries a visibility modifier (`pub`). The field MUST
// be private so no struct-literal construction is possible outside the
// module.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    pub did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: forbidden_derive [REJECT]
// A forbidden derive (`Clone`) on the struct leaks the capability. The
// positive whitelist permits NO derive on the struct.
use scp_identity::DID;

#[derive(Clone)]
pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: derive_separated_by_doc_comment [REJECT]
// F1 — comment-interleaving evasion. A `#[derive(Clone)]` is separated from
// the struct by a `///` doc-comment. A contiguous-adjacency attribute scan
// would stop at the doc-comment and MISS the derive; the grammar-based scan
// SKIPS interleaved comments and still rejects the derive.
use scp_identity::DID;

#[derive(Clone)]
/// This doc comment is interleaved between the derive and the struct.
/// A naive adjacency walk would treat the derive as not belonging here.
pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: manual_impl_clone [REJECT]
// A manual `impl Clone for OwnedIdentityDid` — a SECOND impl item (trait
// impl), rejected by the module-item whitelist.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl Clone for OwnedIdentityDid {
    fn clone(&self) -> Self {
        Self { did: self.did.clone() }
    }
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: manual_impl_clone_path_qualified [REJECT]
// Path-qualified trait impl `impl Clone for self::OwnedIdentityDid`. The
// final-segment normalization recognizes the target as OwnedIdentityDid and
// the module-item whitelist rejects it as a second (trait) impl — without any
// name-matching on `self::`.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl Clone for self::OwnedIdentityDid {
    fn clone(&self) -> Self {
        Self { did: self.did.clone() }
    }
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: second_inherent_method [REJECT]
// SOLE-MINTER violation: a second inherent method `forge` that constructs
// a token from a raw `DID`. The closed inherent-method allowlist rejects it.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
    pub(in crate::context) fn forge(did: DID) -> Self {
        Self { did }
    }
}

// @file: second_inherent_impl_path_qualified [REJECT]
// A SECOND inherent impl, path-qualified as `impl self::OwnedIdentityDid`,
// with a delegating minter body. The module-item whitelist rejects it as a
// second inherent impl (final-segment match) regardless of `self::`
// qualification — closing the path-qualified second-impl smuggle.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

impl self::OwnedIdentityDid {
    fn forge(did: DID) -> Self {
        Self { did }
    }
}

// @file: issue_for_actor_widened [REJECT]
// The mint `issue_for_actor` is widened from `pub(super)` to `pub(crate)`,
// letting non-supervisor code mint a token from an arbitrary DID.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(crate) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: reissue_widened [REJECT]
// `reissue` is widened to `pub` — broader than the capability struct's own
// name-visibility, exposing the clone path beyond `crate::context`.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: as_did_widened [REJECT]
// `as_did` is widened to `pub(crate)` — broader than the capability
// struct's own name-visibility.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(crate) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: reissue_extra_param [REJECT]
// F3 — `reissue` carries an EXTRA parameter beyond `&self`. The exact
// parameter-list assertion (`&self` and nothing else) rejects it WITHOUT
// resolving the param type. This is the plain spelling.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self, owner: DID) -> Self {
        Self { did: owner }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: reissue_extra_param_aliased [REJECT]
// F3 (aliased) — a `type Owner = DID;` alias plus
// `fn reissue(&self, o: Owner)`. The exact `&self`-only parameter assertion
// rejects the extra param without resolving `Owner`; additionally the
// module-level `type Owner` alias is itself rejected by the item-kind
// whitelist. Two independent rejections — either suffices.
use scp_identity::DID;

type Owner = DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self, o: Owner) -> Self {
        Self { did: o }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: extra_constructor_free_fn [REJECT]
// A free fn in the file struct-literal-constructs `OwnedIdentityDid`
// outside the allowlisted methods. The module-item whitelist rejects a free
// `function_item` by KIND (literal-name independent).
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

fn back_door(did: DID) -> OwnedIdentityDid {
    OwnedIdentityDid { did }
}

// @file: type_alias_free_fn_minter [REJECT]
// F2 — alias minter: `type Cap = OwnedIdentityDid;` plus
// `fn forge(did: DID) -> Cap { Cap { did } }`. The denylist-by-name design
// could not see `Cap` as the capability; the item-kind whitelist rejects BOTH
// the `type_item` alias AND the free `function_item` by kind, never by name.
use scp_identity::DID;

type Cap = OwnedIdentityDid;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

pub(in crate::context) fn forge(did: DID) -> Cap {
    Cap { did }
}

// @file: lone_type_alias [REJECT]
// A module-level `type` alias alone (no minter). Even a harmless-looking
// alias is rejected by the item-kind whitelist — `type_item` is not a
// permitted module-level kind, so no alias can be introduced to later be used
// as an evasion surface.
use scp_identity::DID;

type Cap = OwnedIdentityDid;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: module_level_const [REJECT]
// A module-level `const` item — rejected by the item-kind whitelist.
use scp_identity::DID;

const TWELVE: u8 = 12;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: module_level_static [REJECT]
// A module-level `static` item — rejected by the item-kind whitelist.
use scp_identity::DID;

static GREETING: &str = "hi";

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: module_level_macro_rules [REJECT]
// A module-level `macro_rules!` definition — rejected by the item-kind
// whitelist (a macro could expand to a hidden constructor).
use scp_identity::DID;

macro_rules! mint {
    () => {};
}

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: module_level_trait [REJECT]
// A module-level `trait` item — rejected by the item-kind whitelist.
use scp_identity::DID;

trait Sneaky {}

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

// @file: second_inherent_impl [REJECT]
// A SECOND inherent `impl OwnedIdentityDid` block (plainly spelled). All
// inherent methods must live in a single block.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

impl OwnedIdentityDid {
    pub(in crate::context) fn extra(&self) {}
}

// @file: tests_mod_without_cfg_test [REJECT]
// A `mod tests` that does NOT carry `#[cfg(test)]` — it would be compiled in
// production. Only a cfg(test) test module is permitted.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}

mod tests {
    pub(in crate::context) fn helper() {}
}

// @file: deny_unsafe_commented_out [REJECT] mod=deny_commented
// F4 — A5 false-neg guard. The body is the real, valid shape, but the
// supervisor/mod.rs stub has `#![deny(unsafe_code)]` COMMENTED OUT. The
// real-parse deny check must NOT be satisfied by a commented-out attribute,
// so this fixture (whose ONLY defect is the missing deny) must be REJECTED.
use scp_identity::DID;

pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }
    pub(in crate::context) fn reissue(&self) -> Self {
        Self { did: self.did.clone() }
    }
    pub(in crate::context) const fn as_did(&self) -> &DID {
        &self.did
    }
}
