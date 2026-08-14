# ADR-056 canonical-context-id keying (branch chore/ctxid-digest @04f24646e)

CLEAN review (Jun 2026). ADR-056: a context's canonical identity IS its 32-byte
digest; the id string is `hex(digest)`. Resolution = DECODE not re-hash.

## The chokepoint (state.rs ~2072)
`pub fn context_id_to_bytes(&str) -> [u8;32]`: if `len()==64 && all (is_ascii_digit
|| b'a'..=b'f')` → hex::decode → [u8;32] (belt-and-suspenders nested `if let Ok`,
fallthrough keeps fn total, no panic/unwrap). Else → `scp_protocol::context::context_id_bytes`
(pure SHA-256). Guard is strict lowercase (uppercase 64-hex hashes, not decodes —
keeps test labels on fallback). Total/deterministic; for non-64-hex labels
chokepoint == raw, so every non-real-id behavior is byte-for-byte unchanged.

## Routing-vs-keying split (the load-bearing distinction)
- KEYING (MLS group / sender key / event log / access keys): `context_id_to_bytes`
  (decode for real id). All runtime + all 4 FFI sites route through it.
- ROUTING (relay slot): two primitives, BOTH pure-SHA-256-based, NOT the keying digest:
  - encrypted: `context_routing_id` = SHA-256("scp:context-routing:"||id) (domain-sep)
  - broadcast: `broadcast_routing_id` = `context_id_bytes` = SHA-256(id) (NO domain sep)
- a969122b6 FIX: broadcast publish (`apply_broadcast_publish`/`apply_guarded`) was
  routing `send_message` under the keying digest. On main keying-digest incidentally
  == SHA-256(id); ADR-056 decode broke that equality → blob stored at slot projection
  (`scp_node::projection::compute_routing_id` = SHA-256(lowercase id)) never reads →
  `host_site CommitCountMismatch{committed:0}`. Fixed: routes under broadcast_routing_id.
  Verified read-side compute_routing_id == SHA-256(id) for lowercase 64-hex. seal_reserved
  keys off in-cell BroadcastContext (NOT id bytes), so the swap only touched the routing slot.

## Invariant proven end-to-end
`PerContextState.context_id = context_id_to_bytes(id)` (lifecycle_helpers create/import/restore),
builder keys crypto under same, §6.2.4 saga compares wire `target_context_id` (raw digest)
== state.context_id. For real id: handle.id == hex(state.context_id). Provider DashMap keyed
by [u8;32] directly; sender_key_store keyed by hex(keying-bytes) == id string for real ids.
All deposit (node.rs add_member) + lookup (join_from_welcome/sync/decrypt + FFI event-log)
key under chokepoint → aligned.

## Recovery / standing
- recovery_send_notification_direct (supervisor ~3569): rerouted to chokepoint. Reached for
  ANY unregistered ctx incl. REAL 64-hex member ctxs during revoke_ucans/rotate_key_packages
  compromise recovery (not just synthetic identity-private-state). inner.epoch hardcoded 0 is
  safe (plaintext, not AAD-bound; AAD binds sender-key epoch from real crypto state).
- standing reconnect (supervisor ~9087): generate_standing_context_id = "standing-"+hex (73
  chars, never bare 64-hex) → always SHA-256 fallback → byte-identical to pre-change. Reconnect
  publish only ever sees standing ids; decode branch never hit. No regression.

## Tests — all mutation-resistant, non-tautological
Every regression test seeds under DIGEST + asserts `assert_ne!(chokepoint, raw)` precondition
(distinguishes paths) + before/after digest emptiness (or TransportFailed-vs-CryptoFailed for
recovery). Resolver tests (canonical_context_id_tests) pin both branches incl. uppercase/63/65
hash-fallback. seal/open guards switched context_id_bytes→context_id_to_bytes; modified open
negative test now rejects at AEAD layer (hex(ctx_id) decodes back to ctx_id so guard passes) —
correct, comment accurate; new seal_rejects mirror added. NOTE: open neg test dropped its
error-message assertion (weaker) but dedicated guard test covers the guard path — acceptable.

## Resolved prior latent finding
supervisor.rs:12709 signed_import_export_with_member helper now keys via context_id_to_bytes,
matching import_context recompute. Callers pass spawn_live_context = hex(ctx_id_bytes) (real
64-hex). Prior STALE comment fixed. No longer a mismatch even on success path.

## Sweeps
Zero production raw-`context_id_bytes` keying calls remain in scp-runtime (only chokepoint
fallback + builder wrapper) or scp-ffi (all 0). All other raw calls are #[cfg(test)] fixtures
or test preconditions. No missed call sites.

VERDICT: No defects. Diff is internally consistent, spec-conformant (§6.2.4:276), and the
routing/keying split is correct on every path.
