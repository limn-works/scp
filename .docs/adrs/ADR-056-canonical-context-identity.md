# ADR-056: Canonical Context Identity = 32-Byte Digest

**Status:** Accepted
**Date:** 2026-06-28
**Phase:** Phase 2 (contexts) / Phase 6 (production readiness)
**Related:** ADR-008 (`create_context` two-phase commit — keys the creation crypto), ADR-011 (event log — keyed by the context digest), ADR-049 §3 (actor-per-context; the `PerContextState` that holds `context_id`), spec §6.2.4 (Cross-Context Tool Invocation Saga — the wire `target_context_id`), §5.15.8 (standing-pair `derived_context_id`), §18.4.1 (`generate_context_id`)

## Context

A context is addressed two different ways in the system, and the two MUST agree byte-for-byte:

- **As a 32-byte digest.** The MLS group, sender keys, and event log are all keyed by a `[u8; 32]`. The §6.2.4 cross-context tool saga puts this same digest on the wire as `target_context_id` (`<64-hex>` in the JCS envelope, `Fixed32` in the receipt signature preimage) and the *Target-context binding* clause makes B reject any invocation whose asserted `target_context_id` does not equal the verified executing context. The spec is explicit: "`target_context_id` is ALWAYS the raw 32-byte context-id digest — 64-hex on the wire, `Fixed32` in the signature preimage … never a `"standing-"`-prefixed string" (§6.2.4:276).
- **As a string id.** `generate_context_id` (`scp-ffi/common`, §18.4.1) mints a context id as `hex(32 CSPRNG bytes)` — a 64-character lowercase-hex **string**. This string is what the SDK, FFI bridges, and `ContextHandle` carry around, and what `PerContextState.context_id` is derived from.

The defect (#1924): the runtime resolved the string id to keying bytes by **hashing** it — `state.context_id = SHA-256(handle.id)`. For a real context id, `handle.id` is *already* `hex(digest)`, so `SHA-256(hex(digest))` is a **double hash** that has nothing to do with the underlying digest the wire/saga compares against. The MLS group, sender keys, and event log were keyed under `SHA-256(id)`; the §6.2.4 saga compared `target_context_id` (the raw digest) against `state.context_id` (the double-hash) and never matched. The two views coincided **only in fixtures** that happened to construct contexts from non-hex labels, masking the divergence; with real `generate_context_id` ids the §6.2.4 saga is **uncommittable in production**.

This is a bug in the *resolution* of an id string to keying bytes, not in the protocol. The crypto layer already keys off the digest; §6.2.4:276 already mandates the raw digest on the wire. Nothing upstream said "hash the id" — the double-hash was an implementation accident.

## Decision

A context's **canonical identity IS its 32-byte digest.** The id STRING is `hex(digest)`. Resolution from string to keying bytes is **decode, not re-hash**:

- `state.context_id = hex::decode(id)` for a real 64-hex id — the digest is recovered verbatim, never re-hashed.
- The invariant `handle.id == hex(state.context_id)` holds for every real context.

All resolution funnels through a **single chokepoint** in `crates/scp-runtime/src/context/state.rs`:

```rust
// `pub` (not `pub(crate)`): the FFI bridges reach it cross-crate as
// `scp_core::context::state::context_id_to_bytes`.
pub fn context_id_to_bytes(context_id: &str) -> [u8; 32]
```

with the resolution rule:

- **If `context_id` is a canonical context id** — exactly 64 characters, all lowercase hexadecimal — it is `hex::decode`d into the `[u8; 32]` digest. This is the single branch that makes the redirect blanket-safe: every real context id hits it and resolves to its digest.
- **Otherwise** `context_id` is not a real context id — a synthetic namespace (`"identity-private-state"`, §9.12 PSK rotation), a standing-pair display id (`"standing-" + hex`, which carries the prefix and so is never bare 64-hex), or an arbitrary test label (`"ctx-…"`). These fall through to `SHA-256(id)` via the raw primitive, producing **byte-for-byte the same value as before this change** — they were never 64-hex, so their behavior is unchanged.

The 64-hex guard is strict (length 64 **and** all `0-9a-f`): `hex::decode` alone would also accept uppercase, but `generate_context_id` emits only lowercase, so requiring lowercase keeps an uppercase 64-char test label on the hashing fallback rather than silently decoding it.

### Derivation

No new hashing is introduced. `generate_context_id` *already* mints `hex(32 CSPRNG bytes)` — the id string is already the hex of the digest, so the digest is recovered by decoding, with zero added cryptographic operations. Standing contexts derive their digest through `derive_standing_context_digest` (§5.15.8 / standing-pair work, tracked under the standing-context conformance follow-on); this ADR does not alter that derivation — a standing display id carries the `"standing-"` prefix and therefore takes the hashing fallback unchanged.

### The double-hash trap (invariant)

Canonical context ids are **decoded, never re-hashed.** `scp_protocol::context::context_id_bytes` stays a **pure SHA-256 primitive** whose sole production call site is the resolver's own fallback inside `context_id_to_bytes` (synthetic / non-64-hex labels such as `"identity-private-state"` reach `SHA-256(id)` *through* that fallback, never via a direct raw-primitive keying call). Earlier, the supervisor's recovery-direct send path (`recovery_send_notification_direct`) called the raw primitive directly on the rationale that only the synthetic `"identity-private-state"` pseudo-context reached it; that premise was false — the path is reached for any unregistered context, including real 64-hex member contexts during `revoke_ucans` / `rotate_key_packages` compromise recovery — so it was rerouted through the chokepoint. Re-applying the raw primitive to a real `hex(digest)` id is precisely the bug this ADR fixes.

The chokepoint is a **cross-layer** convention, not a runtime-only one. The FFI bridges (PyO3 / NAPI / UniFFI) resolve context-id keying via `scp_core::context::state::context_id_to_bytes` — the same chokepoint, reached through the `scp_core` facade re-export — so an event-log query or Merkle inclusion/absence proof keys the identical digest slot the manager wrote under. (Four FFI event-log sites and six FFI test-harness keying sites originally called the raw `context_id_bytes` re-export, double-hashing every real id and addressing an empty slot — a fail-open caught in adversarial review and rerouted to the chokepoint.)

### Enforcement

The invariant is enforced by:

- **The single chokepoint resolver** `context_id_to_bytes` as the one source of truth — every real-context keying call routes through it, so the decode-not-re-hash discipline lives in exactly one place.
- **A mutation-resistant unit test** that asserts context creation keys its crypto under the DECODED digest and NOT under `SHA-256(id)` — `create_context_keys_crypto_under_decoded_digest_not_sha256` in `crates/scp-runtime/src/context/builder.rs` — plus the `canonical_context_id_tests` in `state.rs` that pin the resolver's decode/hash branching.

The **principled, sound, permanent** mechanical enforcement is a `ContextDigest` newtype that only the chokepoint can mint, making a raw-primitive keying call a **compile error** — the raw primitive's bytes can never reach a keying call site. That work is tracked as issue #1931.

A source-text (grep/awk) CI gate scanning `scp-runtime` and `scp-ffi` for raw-primitive keying calls was implemented and then **removed**: a regex pseudo-lexer cannot soundly tokenize Rust to track `#[cfg(test)]` scope (lifetimes collide with char-literal stripping, block comments corrupt brace counts, multi-line strings escape line regexes), so the gate was a perpetual fail-open class — each fix surfaced a new bypass. Consistent with the project's preference for compiler/type-system enforcement over source-text gates (cf. the ADR-2E `OwnedIdentityDid` gate, likewise dropped for compiler enforcement in PR #1826), the gate was dropped in favor of the chokepoint + tests above and the forthcoming `ContextDigest` newtype.

## Rationale

- The crypto layer already keys off the digest. Aligning `state.context_id` to the digest makes creation, send/receive, governance, TTL, key-destruction, and export/import all key under the *same* bytes, which is the precondition for any cross-context comparison to succeed.
- §6.2.4:276 already mandates the raw digest on the wire and in the receipt preimage. Making `state.context_id` the digest is **conformance to an existing spec requirement, not new design.**
- #107 / §5.15.8 already established that a context's digest (not its display string) is the cryptographic identity for standing pairs; this ADR generalizes that to all contexts and names the single resolver that enforces it.

## Rejected alternative

**Option B — re-spec the wire to carry `SHA-256(id)`.** Make the §6.2.4 wire `target_context_id` be the double-hash so the runtime's `SHA-256(id)` keying becomes "correct." Rejected:

- It contradicts §6.2.4:276, which fixes `target_context_id` as the raw 32-byte digest (64-hex / `Fixed32`).
- It breaks the standing-pair `derived_context_id` (§5.15.8), whose digest is the cryptographic group id, not a hash of a display string.
- It double-hashes the crypto layer: the MLS group / sender keys / event log would then be keyed by `SHA-256(hex(digest))` rather than the digest, severing them from every other component that addresses the group by its digest.

The fix flows the correct direction (code conforms to spec); Option B would flow code accidents up into the wire protocol — a phantom-provenance inversion of the artifact-flow invariant.

## Consequences

- **Positive:** the registry stays value-agnostic (it keys on whatever 32 bytes the resolver returns); the §6.2.4 saga becomes **committable** with real `generate_context_id` ids; creation, messaging, governance, TTL, key-destruction (ephemeral close no longer fails open under a phantom group), and export/import all key under one canonical digest; the single chokepoint plus the digest-keying unit test (and the forthcoming `ContextDigest` newtype, #1931) make the invariant mechanically enforced rather than documented.
- **Cost:** one resolver function; every keying call site routes through the chokepoint (already the case for the historical `context_id_to_bytes` sites).
- **Deferred / tracked separately:** full standing-context (§5.15.8) conformance — the `derive_standing_context_digest` length-prefix migration and the standing-pair creation wiring — is a separate follow-on (#1929 / standing-context work); this ADR governs only the canonical-id resolution and leaves standing display ids on the unchanged hashing fallback.
- **No migration burden:** SCP is pre-release with no deployed contexts; the resolution is corrected outright with no back-compat shim, per the no-migration-pre-release stance.
