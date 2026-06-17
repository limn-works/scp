//! Capability proof type — see ADR-049 §5 (`OwnedIdentityDid`: unforgeable
//! by constructor visibility + private field) and spec §9.4.1 four-point
//! criterion.
//!
//! `OwnedIdentityDid` is the unforgeable token that proves the bearer's
//! identity owns a particular [`ContextActor`]. The unforgeability
//! guarantee — *a value of `OwnedIdentityDid` for a given DID can only
//! come into existence via supervisor-module code* — rides on TWO
//! mechanisms, both of which are real type-system enforcement, not
//! enforcement-by-CI:
//!
//! 1. **The constructor `issue_for_actor` is `pub(super)`** — only
//!    supervisor-module code can mint a token from a raw [`DID`]. Handler
//!    code in `crate::context::actor::handlers/` cannot reach the
//!    constructor's path at all; the compiler refuses.
//! 2. **The single field `did` is PRIVATE** (no `pub` / `pub(crate)` /
//!    `pub(super)`) — so no struct-literal `OwnedIdentityDid { did }` is
//!    possible outside this module either.
//!
//! The struct's *name-visibility* is `pub(in crate::context)`. This is
//! deliberately wider than the constructor: actor-module code in
//! `crate::context::actor` must be able to *name* the type so that
//! [`crate::context::actor::deps::ActorDeps`] can hold the token by-value
//! and handlers can take `&OwnedIdentityDid`. Widening the name to
//! `pub(in crate::context)` is SAFE precisely because (1) + (2) + the
//! non-derives below mean nameable ≠ constructible: actor code can hold a
//! field or accept a reference, but has NO path to *mint* a token. The
//! struct MUST NEVER be `pub` or `pub(crate)` — either would let code
//! outside `crate::context` (or downstream crates) name the type in
//! places the capability model does not intend.
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
//! # Enforcement is the compiler's, not a bespoke CI gate
//!
//! There is NO source-text CI scanner over this file. The sole-minter
//! guarantee is enforced entirely by the language and the compiler:
//!
//! - **The type system.** The `did` field is private, so no external
//!   struct-literal `OwnedIdentityDid { did }` can construct a token. The
//!   constructor `issue_for_actor` is `pub(super)`, so only supervisor-
//!   module code can mint a token from a raw [`DID`]. Together these make
//!   the type *nameable* throughout `crate::context` but *constructible*
//!   only from supervisor-module code.
//! - **`#![deny(unsafe_code)]`** at `supervisor/mod.rs` — blocks an unsafe
//!   `Send` impl or a `transmute` that could fabricate a token while
//!   bypassing visibility.
//! - **`#![deny(non_local_definitions)]`** at `supervisor/mod.rs` — turns a
//!   nested `impl OwnedIdentityDid { .. }` written inside a method body
//!   (which Rust would otherwise apply globally, creating a SECOND minter
//!   from inside the module) into a hard COMPILE error. This closes the one
//!   forgery vector the visibility rules alone do not: an in-module second
//!   constructor smuggled into a function body.
//! - **Code review** of this small, frozen file for the EXPLICIT NON-DERIVES
//!   above and for the absence of any second arbitrary-`DID` constructor.
//!   Adding a derive or a new minter is a visible diff to a tiny file with a
//!   single struct and a single inherent impl; review catches it.
//!
//! A bespoke external scanner was deliberately NOT used. Its only residual
//! threat model is an insider editing this file — but such an insider could
//! equally edit the scanner or its CI wiring, so a scanner adds no marginal
//! security over the type system + the two compiler lints + review. See
//! ADR-049 §5 and spec §9.4.1.

use scp_identity::DID;

/// Proof that the bearer's identity owns this actor.
///
/// The struct's name-visibility is `pub(in crate::context)` — nameable
/// throughout `crate::context` so that
/// [`crate::context::actor::deps::ActorDeps`] can hold the token by-value
/// and handlers can take `&OwnedIdentityDid`. It is NOT `pub` or
/// `pub(crate)`: those would leak the name beyond the capability model's
/// intended scope.
///
/// The mint guarantee — *a token for a given DID only exists if
/// supervisor-module code created it* — does NOT rely on the struct's
/// name-visibility. It rides on two narrower facts:
///
/// - `issue_for_actor` is `pub(super)`: only supervisor-module code can
///   mint a token from a raw [`DID`]. Actor / handler code cannot reach
///   the constructor's path; the compiler refuses.
/// - The single field `did` is PRIVATE: no struct-literal
///   `OwnedIdentityDid { did }` is possible outside this module, so a
///   wider name-visibility grants the power to *name* the type but not to
///   *construct* one.
///
/// The token is held by-value inside `ActorDeps` (minted fresh at
/// actor-spawn time in `Supervisor::build_actor_deps`, one per actor for
/// ITS context's owning identity) and passed by reference
/// (`&OwnedIdentityDid`) to `SupervisorHandle` methods that touch
/// per-identity state. There is no `&DID`-keyed surface; the only identity
/// an actor can read is the one that owns it.
pub(in crate::context) struct OwnedIdentityDid {
    did: DID,
}

impl OwnedIdentityDid {
    /// Issue a capability proof for an actor's owning identity. Visible
    /// only to supervisor-module code (the actor-spawn site in
    /// `Supervisor::build_actor_deps`). This `pub(super)` constructor is
    /// the mint: it is the ONLY way a token for a not-already-held DID
    /// comes into existence. Do NOT widen its visibility — doing so lets
    /// non-supervisor code fabricate a token for an arbitrary DID and
    /// defeats cross-identity isolation.
    pub(super) const fn issue_for_actor(did: DID) -> Self {
        Self { did }
    }

    /// Re-issue a token for the SAME owning identity by cloning `self`'s
    /// already-attested DID.
    ///
    /// Used by [`crate::context::actor::deps::ActorDeps::clone_for_spawn`],
    /// which structurally must duplicate an existing `&ActorDeps` borrow
    /// into an owned bundle for the spawned actor task (the borrow stays
    /// live for post-spawn finalization). Because `clone_for_spawn` holds
    /// only a `&ActorDeps` — i.e. a token that was ALREADY minted by the
    /// supervisor for this context's owning identity — it cannot re-derive
    /// from a raw `DID`; it can only reissue the token it already holds.
    ///
    /// This is NOT a forgery vector: possession of `&self` already proves
    /// the supervisor attested ownership of `self.did`. `reissue` takes no
    /// `DID` parameter, so it cannot mint a token for a DID the caller
    /// does not already hold a token for. It is strictly weaker than
    /// `issue_for_actor` (which can mint from any raw DID and is therefore
    /// `pub(super)`-gated); `reissue` only clones an existing capability.
    pub(in crate::context) fn reissue(&self) -> Self {
        Self {
            did: self.did.clone(),
        }
    }

    /// Read-only access to the inner DID. The returned reference cannot
    /// reconstruct the proof — `OwnedIdentityDid` has no `From<&DID>` and
    /// no public constructor. Handlers may use this to build outgoing
    /// envelopes that need the owning identity's DID string.
    #[allow(dead_code)] // consumed by SupervisorHandle per-identity methods landing in PR-3b
    #[must_use]
    pub(in crate::context) const fn as_did(&self) -> &DID {
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

    #[test]
    fn reissue_clones_the_same_owning_did() {
        // `reissue` duplicates the already-attested DID — it cannot
        // forge a token for a different identity because it takes no
        // `DID` parameter. The clone is for the SAME owner.
        let did = DID("did:example:bob".to_owned());
        let token = OwnedIdentityDid::issue_for_actor(did.clone());
        let cloned = token.reissue();
        assert_eq!(cloned.as_did(), &did);
        // The original is still usable — reissue borrows, not moves.
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
