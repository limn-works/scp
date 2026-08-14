---
name: spending-ucan-revocation-904f6d3dc
description: Adversarial audit of scope-matched spending-UCAN revocation (commit 904f6d3dc, spec §19.5) — what broke, what held
metadata:
  type: project
---

# Spending-UCAN revocation (commit 904f6d3dc, spec §19.5 / 72817f104)

Union gate: per-context Class-S `revoked_spending_ucan_cids` ∪ charged-DID global set
(durable `identity/{did}/revoked_spending_ucans/{cid}` store → supervisor-wide
`ArcSwap<HashMap<DID,HashSet<String>>>` cache). verify-before-revoke =
`verify_spending_ucan_genuine` (sig + iss==aud + key-scope, NO nonce/expiry).

## Real findings
- **BLACK-SPEND-1 (MED/HIGH): anti-bloat claim false.** Self-issued spending UCANs
  are free to mint (iss==aud, self-sign). verify-before-revoke only requires a valid
  self-sig, so a context MEMBER can self-issue+revoke unbounded context-scoped tokens →
  each CID inserted into context Class-S set, which is serialized WHOLE per persist +
  in signed export digest (§23.16.8) → O(N²) persist/digest DoS. No size cap anywhere
  (store/mod, revoked_spending_ucans.rs, handlers/economy.rs). Global variant bloats
  durable DID store + slows every startup `load_all` (scans ALL identity/ keys).
- **BLACK-SPEND-2 (MED): cross-context authz escalation.** `BridgeRevocationAuthorizer`
  (scp-ffi/common/src/resolvers.rs:776) allows revoker == issuer OR context-creator of
  the `context_id` arg. For a GLOBAL token, ANY single context's creator revokes it
  instance-wide → blocks victim spending in every OTHER context. Multi-tenant node =
  cross-tenant DoS. Authority (per-context creator) mismatched to effect (instance-wide).
- **BLACK-SPEND-3 (trust boundary): `revoker_did` is unauthenticated caller string** at
  FFI; authz `revoker==issuer` → claim victim DID to revoke victim token (needs genuine
  encoded token). Local-trust at FFI; a network-exposed multi-tenant API would need to bind it.
- LOW: hydrate writes ArcSwap WITHOUT write_lock (supervisor.rs:9048) vs revoke's locked
  RMW (3560-3567) — startup-only race. LOW: durable-before-cache window; LOW: gate snapshot staleness.

## What resisted (verified closed)
- The target bug (revoke global in A, spend in B): CLOSED. Shared supervisor-wide cache,
  keyed by DID; union checked in all 4 spend paths (messaging/lifecycle/tools_helpers/saga).
  charged DID == token iss enforced by validate step A (iss==aud==actor_did).
- CID malleability: CLOSED. base64 0.22 URL_SAFE_NO_PAD strict (RequireNone pad, no
  trailing bits) + sig over raw header.payload text → encoded string canonical → stable CID.
- Forged CID into store: blocked by verify-before-revoke sig.
- Revoke-parent/child-survives: closed (verify_delegation_chain uses same union checker per parent).
- Restart loses revoke: closed (durable-first + hydrate in restore_on_startup, fail-closed `?`).
- Key collision wrong-DID revoke: impossible (sanitize_key_component is reject-filter, identity on accepted).
- No spend-gate call site passes None where it should pass the DID set — all 4 thread it.

## FINAL STATE re-verify (tip 188af5ad2, +4 fix rounds) — COMPLETE
My round-1 findings were fixed:
- BLACK-SPEND-2/3 (cross-context creator + unauthenticated revoker): global revoke now issuer-only
  (SCP-ECON-12067, supervisor apply_global_spending_revocation); context revoke gated issuer-OR-scope-creator
  + current-member (SCP-ECON-12069) + empty-revoker reject (SCP-ECON-12068, handlers/economy.rs).
- BLACK-SPEND-1 (bloat): spec now honest — global store expiry-GC'd (revocation_moot_after_secs,
  prune on record/hydrate, load_for_did bounded re-derive); per-context set accepted-unbounded convergent,
  principled bound deferred to #2072 (observed/granted-tokens = separate mechanism, NOT this feature).
- New fail-closed poison flag GlobalRevocationHydration (Arc<AtomicU8>: NotConfigured/NeedsHydration/
  Hydrated/Failed). Gate chokepoint = ContextRevocationChecker.global_scope_status_unknown (required field,
  no Default → both gate sites economy+saga MUST set it). Shared into every ActorDeps mechanically
  (required non-Option field, no Default; build_actor_deps + clone_for_spawn). hydrate reordered to run
  FIRST in restore_on_startup. Invariant 2b: write_lock spans load_for_did+store (incremental) and
  load_all+store (hydrate). All six §19.5 invariants (1a/1b/2a/2b/3a/3b) map to wired code.
- scp-node wired: self_host from_encrypted_handle → Some store (was None). 3 native FFI build+inject+
  restore_on_startup→hydrate. WASM N/A (no revoke path). Retain-on-upgrade serde default u64::MAX.

MINOR NIT (not a gap): self_host.rs:644 comment names `DurableProviders::from_handle` but production uses
`from_encrypted_handle`; from_handle returns store=None. Doc rot risk (fail-open if followed). Functional path correct.

## Adjacent (not this feature)
- broadcast subscribe UCAN validated with all-Noop resolvers incl NoopRevocationChecker
  (broadcast.rs:153) — broadcast-auth UCANs not revocation-checked. Pre-existing.
