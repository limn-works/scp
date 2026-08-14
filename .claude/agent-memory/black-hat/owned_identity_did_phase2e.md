# OwnedIdentityDid capability token (ADR-049 §5, Phase 2E) — FORGE REVIEW: CLEAN

Branch feat/actor-2e-owned-identity. Token proves "actor owns identity X". Phase 2E widened
struct name-vis pub(super)→pub(in crate::context) + module identity_capability→pub(in crate::context)
so sibling `actor` module (ActorDeps) can NAME it. Kept constructor `issue_for_actor` pub(super),
field `did` PRIVATE. Added `reissue(&self)` (clones held DID, no DID param).

## Module hierarchy (load-bearing)
- crate::context::actor and crate::context::supervisor are SIBLINGS (both children of context).
- issue_for_actor `pub(super)` (super=supervisor) → visible to supervisor + descendants, NOT to actor. Correct boundary.
- Widening struct NAME to pub(in crate::context) does NOT open construction: struct-literal needs the
  PRIVATE field `did` visible at the site; field privacy is module-private to identity_capability,
  independent of name-vis. Nameable ≠ constructible.

## Forge probes RUN (compiler-verified, all blocked)
- actor-module `OwnedIdentityDid { did }` → E0451 private field.
- actor-module `OwnedIdentityDid::issue_for_actor(did)` → E0624 private associated fn.
- downstream scp-core naming `scp_runtime::context::supervisor::identity_capability::OwnedIdentityDid`
  → E0603 private module (can't even name it).
- reissue: &self only, clones self.did, no DID param → cannot escalate to a different identity.
- No derives, no From/Into/Default/Deserialize, no manual trait impls. forbid(unsafe_code) at lib + deny at supervisor/mod.rs.
- Mint site build_actor_deps: token DID == owning_did == KP-store scope (internally consistent). owning_did
  provenance (watchdog min, export roster member) is pre-existing, unchanged by this diff.

## CI gate scripts/check-owned-identity-did.py — passes + self-test passes (11 modes)
- Checks A(location) B(struct pub(in crate::context)) C(derives) D(manual impls) E(private fields)
  F(no type alias) G.1(issue_for_actor pub(super)) G.2(ctor exists) G.3(reissue &self no DID).
- RESIDUAL GAP (LOW, defense-in-depth): G.1 name-matches only `issue_for_actor`, G.3 only `reissue`.
  A NEW inherent fn with a different name returning Self from a raw DID at pub(in crate::context)
  would NOT be caught by the gate (compiler still allows it only inside supervisor module though, since
  Self construction needs the private field → only identity_capability module can build Self). So the
  TYPE SYSTEM still blocks it from actor/downstream; gate is the only thing that wouldn't flag a future
  supervisor-internal second-mint fn. Currently only 3 inherent fns exist (issue_for_actor/reissue/as_did). Safe today.

## NIT: as_did() is full `pub` returning &DID. Not a forge vector (DID is public, obtainable elsewhere;
   &DID cannot reconstruct token — no From<&DID>). Slightly wider than needed but harmless.
