# ADR-056 Canonical Context Identity = digest (PR-A rev8, 295bc3154) -- 2026-06-29 -- ZERO FINDINGS

Context identity = 32-byte digest; id string = hex(digest). Resolution = DECODE not RE-HASH.
Single chokepoint `context_id_to_bytes(&str)->[u8;32]` at scp-runtime state.rs:2072 (pub, reached
cross-crate as `scp_core::context::state::context_id_to_bytes`). Branch: 64-char all-lowercase-hex
=> hex::decode to digest; else SHA-256(id) via raw `scp_protocol::context::context_id_bytes`
(unchanged for synthetic labels). Total/panic-free (fallthrough keeps it total).

## The bug fixed (real fail-open)
Recovery direct path `recovery_send_notification_direct` (supervisor.rs:3555) previously keyed via
RAW primitive on the false premise only synthetic `identity-private-state` reached it. FALSE: reached
for ANY unregistered context incl REAL 64-hex member ctxs during revoke_ucans(seq1)/rotate_key_packages/
mls_update(seq0) compromise recovery. Raw primitive double-hashed real id => seal keyed slot no member
listens on => revocation/rotation notifications SILENTLY UNDELIVERED. Now keys via chokepoint (line 3583).
Registered-actor twin `recovery_send_notification` (trust_recovery_helpers.rs:322) also keys via
chokepoint => same slot. routing_id stays `context_routing_id` (separate domain-sep namespace, correct).

## Verified clean
- ALL production runtime keying sites rerouted to chokepoint: builder.rs:766 (local wrapper ->
  context_id_to_bytes; the create-ctx keying site), messaging/governance/governance_logic/key_destruction/
  ttl/lifecycle/class_s/mod, reconnect-publish (supervisor.rs:9087). FFI: 4 event-log + 6 test-harness
  sites (pyo3+napi+uniffi) -> `scp_core::context::state::context_id_to_bytes`.
- MLS seal/open consistency gate (provider.rs:1581/1675) updated raw->chokepoint. REQUIRED: old gate
  `context_id_bytes(ctx_str)==context_id` would FAIL-CLOSED every real-ctx send (double-hash never == digest).
  New gate still fails closed on genuine mismatch (test open_rejects_...:4540). AAD still binds RAW string.
- ONLY remaining production raw `context_id_bytes` sites: state.rs:2088 (the chokepoint's own fallback) +
  scp-protocol mod.rs:130 `broadcast_routing_id` (§5.14 routing, NOT keying) + `context_routing_id` body.
  All other hits are #[cfg(test)] or `let _ =` routing-surface exercise (persistence_sdk.rs:330, benign).
- Tests mutation-resistant: builder.rs:967 drives REAL create crypto, asserts export under decoded digest
  non-empty AND under SHA256(id) empty. state.rs canonical_context_id_tests pin all branches incl
  lowercase-strictness (uppercase 64hex hashes) + 63/65 length boundary. supervisor.rs:14124 recovery
  regression asserts TransportFailed (digest slot found) not CryptoFailed (raw slot empty).
- Doc rewrite (scp-protocol mod.rs) accurate: raw primitive relabeled "raw routing/synthetic-label ONLY",
  CRITICAL warns against keying real ctx, steers to chokepoint. No new pub capability (raw stays pub for
  routing+fallback; chokepoint pub by design for FFI cross-crate).

## Posture call (source-text gate removal)
Net-new grep CI gate REMOVED -- regex pseudo-lexer can't soundly track #[cfg(test)] (lifetimes vs char
literals, block comments, multiline strings) = perpetual fail-open class. Replaced by chokepoint+tests now,
ContextDigest newtype (#1931) for compile-time enforcement later. ACCEPTABLE: consistent with OwnedIdentityDid
gate drop (PR#1826) precedent + project's compiler-over-source-text preference. Interim window relies on
review discipline; bounded by the forthcoming newtype. #1933 verify-sync gap out of scope.

No injection/auth/secret/leak surface in this change. Aliasing decode-vs-hash branch collision = 2^-256
CSPRNG coincidence, not attacker-controllable, value-agnostic registry (pre-existing namespace property).
