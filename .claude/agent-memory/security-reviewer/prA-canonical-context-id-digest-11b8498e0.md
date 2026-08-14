# PR-A canonical-context-id = digest (Model A / ADR-055, #1924) — 11b8498e0 — ZERO FINDINGS / SECURITY-NEUTRAL

Reviewed 598a56c37..11b8498e0 (10 files, scp-runtime context + crypto/mls + scp-ffi/common).

## What changed
`state::context_id_to_bytes(id)` now delegates to NEW `decode_canonical_context_id(id)`:
`if id.len()==64 && all bytes ∈ [0-9a-f] { hex::decode -> [u8;32] } else { SHA-256(id) fallback }`.
Was previously always `scp_protocol::context::context_id_bytes(id)` = SHA-256. So a real
context (id = hex(digest)) now DECODES to its digest instead of double-hashing. ADR-055 /
§6.2.4:276: canonical context identity IS the 32-byte digest; id string = hex(digest).

## Why security-neutral (4 lenses)
1. **Caller-chosen digest is NOT a new attack.** `generate_context_id` (scp-ffi/common/src/context_id.rs:50)
   = OsRng 32 bytes hex-encoded — id/digest is CSPRNG-random, caller can't pick/grind at create.
   Registry (supervisor.rs:3912-3917) keys by id STRING, first-writer-wins under write_lock,
   dup-id create => CreationFailed. Matching id w/o MLS keys grants nothing (encryption-as-access-control).
   Old world: SHA-256(arbitrary_string) — caller ALSO influenced deterministically. 1:1 preimage swap
   at a public deterministic chokepoint; blast radius unchanged.
2. **§9.16.1 AAD preserved.** seal (provider.rs:1607) passes RAW ctx_str into encrypt_sender_layer;
   open (:1757) passes RAW context_id_str. decode_canonical_context_id used ONLY in fail-closed
   consistency guard (:1588 seal, :1682 open) checking resolve(str)==supplied_bytes BEFORE crypto.
   Never feeds AAD. Test seal_open_binds_raw_context_id_string_not_hex (:4490) proves raw bound;
   guard now passes hex(digest) (legit canonical id) then AEAD rejects on AAD mismatch one layer deeper.
3. **Guard strict, no evasion.** decode only on len==64 && all-lowercase-hex. generate_context_id
   emits lowercase only => every real id decodes, every non-id (synthetic "identity-private-state",
   "standing-"+hex, uppercase, 63/65-char) falls to byte-identical SHA-256. Decode branch reachable
   only by the hex-of-the-very-digest-it-resolves-to (round-trip identity). ALL ~11 keying sites +
   4 lifecycle import/restore + builder::context_id_bytes route through the ONE chokepoint — no
   split-brain (creation-vs-live-state was the bug this fixes).
4. **No fail-open.** Total fn (clippy denies panic/unwrap): if-let-Ok guards => hypothetical hex
   reject falls through to SHA-256, never zero/garbage key. For validated 64-lc-hex both decode +
   try_from infallible. Err msgs "hash"->"resolve", no internals leaked.

## Deliberate carve-out (sound)
supervisor.rs:3536 spending-nonce seal for synthetic "identity-private-state" PSK pseudo-context
(§9.12 step 6) calls raw scp_protocol::context::context_id_bytes DIRECTLY. Byte-identical for that
non-64-hex input (can never hit decode branch); purely documentary. Registry-keying comment at
:3887 updated: id string and hex(state.context_id) now coincide for real contexts (round-trip),
old production-divergence warning no longer applies; registry still keys by string in every case.

## Positive patterns
Single chokepoint discipline; fail-closed guard tightened (hash->resolve) while AAD stays raw-string;
strict lowercase guard forecloses hex::decode leniency. Good tests (decode-not-rehash, AEAD-layer
rejection, near-64 lengths, uppercase-hashes).
