---
name: native-aad-1909
description: #1909 native sender-layer AAD now binds raw context_id string (§9.16.1); confused-deputy / cross-context analysis verdict GO
metadata:
  type: project
---

# #1909 — native sender-layer AAD binds raw context_id string (commit 84b029e88)

**Verdict: GO.** Empirically verified fail-closed. The change aligns native `seal`/`open`
sender-layer AES-256-GCM AAD with WASM + spec §9.16.1 (raw context_id string, BE32 len-prefix),
replacing the old hex(SHA-256(id)) binding. Fixes a latent native↔WASM interop break.

**Confused-deputy concern (open takes both 32-byte id AND context_id_str) is NOT exploitable:**
- Production callers derive BOTH from ONE trusted local string. Send: `build_encrypted_envelope`
  (messaging_helpers.rs:118) sets `inner.context_id = context_id` and `context_id_bytes = hash(context_id)`.
  Receive: `deliver_incoming` (messaging_helpers.rs:1409) computes `context_id_bytes(context_id)` from
  the same `&str`. The string is the node's OWN subscription context id (NAPI ctx.context_id.clone()),
  never from the wire envelope — only `envelope.encrypted_blob` comes from the wire.
- `seal` HAS a fail-closed assert: `context_id_bytes(inner.context_id) == *context_id` (provider.rs ~1582).
- `open` LACKS the symmetric assert, but it doesn't matter: divergence only ever causes a legit message
  to FAIL (DoS at most), never a forge. AEAD fails closed on any AAD mismatch.

**Probes run (all pass, fail-closed):**
1. open(correct id, WRONG string) → "authentication tag verification failed". Old hex string also fails.
2. open(foreign id, correct string) → "no MLS group for this context" (MLS rejects before AAD).
3. seal(inner.context_id not hashing to id) → rejected, no ciphertext emitted.
4. cross-context relocation (relay moves A-blob to bob's ctx-B sub) → MLS "group ID differs" — AAD
   not even reached. MLS group binding is primary cross-context isolation; AAD string is defense-in-depth.

**Why it holds:** cross-context isolation is enforced THREE ways before AAD: (a) MLS group id, (b) sender-key
store keyed by hex(id), (c) AAD string. An attacker can't choose the (id,string) pair — the local node binds
both from its own subscription. Relay only chooses which subscription receives a blob.

**Minor (non-blocking) defense-in-depth suggestion:** add the same `context_id_bytes(context_id_str) == *context_id`
assert to `open` that `seal` already has, to fail fast on a future buggy caller rather than relying on AEAD.
Not a vuln — purely robustness against internal misuse.

AAD builder: `build_sender_aad` (scp-protocol/src/crypto/sender_keys/encrypt.rs) — byte-exact `as_bytes()`,
len-prefixed, NO normalization/casing. WASM imports the SAME helper, so seal/open symmetry is exact iff
both pass the same raw string (they do).
