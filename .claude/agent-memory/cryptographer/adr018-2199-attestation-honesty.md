---
name: adr018-2199-attestation-honesty
description: SCP #2199 — KeyDestructionAttestation destroyed-flags gated on observed DisposalOutcome (kill the hardcoded-true lie); crypto soundness review
metadata:
  type: project
---

# #2199 KeyDestructionAttestation honesty gating (SOUND)

Kills the hardcoded `mls_group_destroyed = sender_keys_destroyed = true`. Now
gated on observed pre-disposal presence.

**Why:** a fabricated `true` is a nullifier-class false guarantee (worse than
honest absence) — a verifier reads these flags as provenance (spec's
KeyDestructionAttestation, memory_scope.rs:144, "ADR-018 AC7").

**How it works:** `ContextCryptoState::dispose_secrets` (state.rs:2172) now
returns `DisposalOutcome{mls_group_destroyed, sender_keys_destroyed}` computed
BEFORE nulling: `mls_group_present = self.mls_group.is_some()`;
`sender_keys_present = sender_key.is_some() || !sender_key_store.is_empty()`.
`#[must_use]`. Rollback/shutdown paths `let _ =` discard (no attestation built).

**Truth condition is SOUND:**
- `destroy_group` (scp-mls group.rs:991) is total: drops group (tree secrets,
  epoch schedules, ratchet), takes signer, resets provider, sets destroyed.
  Ok | idempotent Err(GroupDestroyed) both = gone. No partial-failure branch.
- `mls_group_destroyed` spec meaning = "tree secrets, epoch key schedules,
  application key material" — NOT the Ed25519 signer. destroy_group releases all
  of those. So flag is honest per its OWN definition despite #82.
- **#82 freed-not-zeroized signer:** destroy_group FREES signer Vec<u8> (heap)
  but does NOT overwrite. NOT overclaimed: (a) signer isn't in the flag's
  claimed set; (b) level=SoftwareOnly already discloses "memory dumps/swap may
  have retained the key". Doc comments correctly document the caveat, no
  zeroization overclaim. "destroyed" is the right word given the spec's scoped
  meaning.
- `sender_keys_destroyed` is STRONGER: SenderKey is ZeroizeOnDrop([u8;32])
  (sender_keys/mod.rs:83), so drop actually zeroizes. Asymmetry (sender=zeroized,
  mls-group=only-freed) is real but both honest.

**Live prod attestation build:** only `finalize_close` (ttl_close_helpers.rs:906)
— builds truthful attestation post-disposal from observed outcome, tracing::info!
only (durable event-log recording deferred to #2215). The old fabricated build
(fresh ContextParams::default() FAKE scope + pre-disposal initiate_close minting
hardcoded true) was DELETED from uniffi bridge.rs:~10935.

**KeyDestructionOrchestrator/CloseOrchestrator now test-only in prod** (bridge
block deleted; grep shows no non-test caller outside key_destruction.rs). The
`disposal: DisposalOutcome` param threading keeps the type honest by
construction but the orchestrator itself is dead-in-prod — a #2148-era
observability path, not a #2199 regression.

**TTL path (ttl.rs:750):** was unconditional set of both STEP bits (even
crypto==None); now gated on outcome. None-on-destruction-required is unreachable
in prod (Ephemeral/Summary always Encrypted); if hit, warns + leaves bits UNSET
(honest incomplete) instead of fabricating. No FS gap: None = gone-or-never-had,
nothing survives. No retry-spin: state already transitioned to Expired (terminal).

**Broadcast:** dispose_secrets returns {false,false}, no attestation built.
Correct — Broadcast is always Full memory-scope, no MLS group.

**Minor open items (non-blocking):** SenderKey derives Clone+Serialize — a
serialized snapshot copy on disk survives in-memory zeroize (pre-existing whole-
disposal concern, out of #2199 scope; finalize deletes context state). Within
actor model no live clones at disposal (synchronous handler, sole owner).
