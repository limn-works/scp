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
//
// The block runs from one `// @file:` line to the next (or EOF). At
// self-test time the scanner writes each block's body to a temp staging
// tree at the REQUIRED path
// `crates/scp-runtime/src/context/supervisor/identity_capability.rs`
// (a sibling `supervisor/mod.rs` carrying `#![deny(unsafe_code)]` is
// synthesized automatically), then scans it in ISOLATION:
//
//   - `[REJECT]` fixtures MUST be rejected (scan exits non-zero) — each is
//     a minimal, single forgery of one definition-shape invariant.
//   - `[ACCEPT]` fixtures MUST be accepted (scan exits zero) — the real
//     struct shape.
//
// The kernel checks the DEFINITION shape only. It does NOT inspect call
// sites, build sites, or mint arguments — construction confinement is the
// type system's job (`pub(super)` constructor + private field +
// `deny(unsafe_code)`). So there are NO build-site / shadow / attribute-
// macro / glob-use / metavariable-macro fixtures here: that entire class
// of analysis was deleted.
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
// A forbidden derive (`Clone`) on the struct leaks the capability.
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

// @file: manual_impl_clone [REJECT]
// A manual `impl Clone for OwnedIdentityDid` — a forbidden trait impl that
// duplicates the capability without the blessed constructor.
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

// @file: second_inherent_method [REJECT]
// SOLE-MINTER violation: a second inherent method `forge` that constructs
// a token from a raw `DID`. The type system permits this (it is inside the
// module); the gate's closed inherent-method allowlist rejects it.
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

// @file: extra_constructor_free_fn [REJECT]
// A free fn in the file struct-literal-constructs `OwnedIdentityDid`
// outside the allowlisted methods — a second construction path. (The field
// is private so this would not actually compile from another module, but a
// same-file free fn CAN see the private field; the gate forbids any
// constructor outside the three allowlisted methods.)
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

// @file: second_inherent_impl [REJECT]
// A SECOND inherent `impl OwnedIdentityDid` block. All inherent methods
// must live in a single block; a second block is a place to smuggle an
// extra constructor.
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
