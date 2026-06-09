//! Capability proof type — see ADR-049 §"`OwnedIdentityDid` via module
//! visibility" and spec §9.4.1 four-point criterion.
//!
//! `OwnedIdentityDid` is the unforgeable token that proves the bearer's
//! identity owns a particular [`ContextActor`]. The mechanism uses **module
//! visibility (`pub(super)`) for actual compile-time enforcement** — not
//! `pub(crate)`, which would let any handler in `scp-runtime` fabricate a
//! token. This module is declared `mod identity_capability;` (PRIVATE)
//! inside `supervisor/mod.rs`; handler code in
//! `crate::context::actor::handlers/` cannot reach the constructor's path
//! at all. The compiler refuses; this is real type-system enforcement, not
//! enforcement-by-CI.
//!
//! # EXPLICIT NON-DERIVES
//!
//! Adding any of the following defeats the capability boundary:
//!
//! - `Clone` / `Copy` — leaks the capability to additional code paths.
//! - `Serialize` / `Deserialize` — smuggles it across trust boundaries
//!   (network, snapshot, log).
//! - `Default` / `From` / `Into` — fabrication without the
//!   supervisor-blessed constructor.
//! - `Hash` / `PartialEq` / `Eq` — identity set-semantics are not a use
//!   case; the capability is by-value only at call sites.
//! - `Borrow` / `AsRef` / `Deref` — erodes the `&OwnedIdentityDid`
//!   contract.
//! - `Debug` / `Display` — accidental logging of identity tokens.
//!
//! Defense-in-depth: the CI gate `scripts/check-owned-identity-did.py`
//! mechanically enforces every clause above (location, visibility,
//! forbidden derives, forbidden manual impls, forbidden public fields,
//! `type` alias ban). Any change here is also audited there.
//!
//! See also `#![deny(unsafe_code)]` at `supervisor/mod.rs` — prevents an
//! unsafe `Send` impl or `transmute` that could fabricate a token.

use scp_identity::DID;

/// Proof that the bearer's identity owns this actor.
///
/// Construction is `pub(super)` — only supervisor-module code may issue
/// the token. Handler code in `actor/handlers/` cannot reach the
/// constructor's path; the compiler refuses.
///
/// The token is held by-value inside `ActorDeps` and passed by reference
/// (`&OwnedIdentityDid`) to `SupervisorHandle` methods that touch
/// per-identity state. There is no `&DID`-keyed surface; the only identity
/// an actor can read is the one that owns it.
///
/// The `dead_code` allow on the field is intentional: commit 5 lands the
/// type-system shape; commits 6+ wire up `ActorDeps`, `SupervisorHandle`,
/// and the spawn site that consumes `as_did()`. The unit tests in this
/// file exercise the constructor and accessor immediately; production
/// callers come online in subsequent commits without further changes here.
pub(super) struct OwnedIdentityDid {
    #[allow(dead_code)] // read via as_did(); spawn-site consumer lands in commit 6
    did: DID,
}

impl OwnedIdentityDid {
    /// Issue a capability proof for an actor's owning identity. Visible
    /// only to supervisor-module code (callers in `supervisor/spawn_actor.rs`
    /// and similar). Future commits add the spawn site that calls this.
    #[allow(dead_code)] // used by the actor-spawn site landing in commit 6
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }

    /// Read-only access to the inner DID. The returned reference cannot
    /// reconstruct the proof — `OwnedIdentityDid` has no `From<&DID>` and
    /// no public constructor. Handlers may use this to build outgoing
    /// envelopes that need the owning identity's DID string.
    #[allow(dead_code)] // consumed by SupervisorHandle methods landing in commit 6
    #[must_use]
    pub const fn as_did(&self) -> &DID {
        &self.did
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn issued_token_exposes_did_by_reference() {
        let did = DID("did:example:alice".to_owned());
        let token = OwnedIdentityDid::issue_for_actor(did.clone());
        // `as_did` returns a reference — the token retains ownership.
        assert_eq!(token.as_did(), &did);
    }

    /// Compile-time witness that `OwnedIdentityDid` is `Send + Sync`.
    /// `ActorDeps` is moved into a `tokio::spawn`'d task, so every field
    /// (including the capability token) MUST be `Send`. This test never
    /// runs; it only needs to compile.
    #[test]
    fn token_is_send_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OwnedIdentityDid>();
    }
}
