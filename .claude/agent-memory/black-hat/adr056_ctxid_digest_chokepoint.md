# ADR-056 canonical-context-id-as-digest (branch ctxid-digest, top a600b02dd)

Splits the old incidental equality `state.context_id == SHA-256(id)`. New rule:
`context_id_to_bytes(id)` (state.rs:2072) DECODES a 64-lowercase-hex id to its 32-byte
digest, else falls back to `SHA-256(id)` (scp_protocol::context::context_id_bytes).
Transport routing stays on `context_routing_id` (domain-sep) / `broadcast_routing_id`
(= `SHA-256(id)`, NOT chokepoint).

## Verdict after full seam trace: COULD NOT BREAK. Change is sound.

### Why the 4 attack classes fail:
1. Addressing/equivocation: EVERY production keying site converted to chokepoint
   (send/recv build_encrypted_envelope+deliver_incoming, builder create, import/restore,
   key_destruction, ttl, governance consequence log, recovery registered+direct,
   reconnection-driver, FFI event_log ×3 read + FFI testing ×6 + node.rs). Only remaining
   raw-primitive PRODUCTION call = the chokepoint's own fallback (state.rs:2088). All other
   raw-primitive hits are #[cfg(test)] with "ctx-*" labels or are the local var named
   context_id_bytes (already chokepoint-resolved upstream).
2. Broadcast split is CORRECT: publish routes `broadcast_publish_routing_id`=SHA-256(id)
   (broadcast_helpers.rs:386) matching node `compute_routing_id`=SHA-256(lowercase(id)).
   Broadcast payload sealed under author key, NOT context-id-derived → independent of split.
   The a969122b6 commit fixed exactly this (was wrongly routing publish via chokepoint).
3. Recovery direct + registered BOTH key via chokepoint, BOTH route relay via
   context_routing_id → symmetric (trust_recovery_helpers.rs:349 vs supervisor:3606).
4. §6.2.4 saga: target_hex=hex::encode(wire 32-byte digest) == registered id-string hex(D)
   for real ctx; registry keyed by STRING (value-agnostic). caller_hex same. Committable.

### Chokepoint evasion (finding #2) — none:
- Guard `len()==64 && all(is_ascii_digit || a-f)` is EXACT lowercase-hex. Uppercase hashes
  (test :2315), 63/65 hash (:2329), Unicode/whitespace fail charset (ASCII byte iter).
- decode-branch vs SHA-256-branch collision needs SHA-256 PREIMAGE of a chosen digest =
  infeasible. Synthetic label decoding as real digest impossible (not 64-lc-hex).

### MLS seal/open guard (provider.rs:1581/1675): now `context_id_to_bytes(ctx_str)==context_id`
instead of `context_id_bytes(...)`. AAD still binds RAW string (§9.16.1). Still effectively
1 string per slot (preimage-resistance). Native↔WASM AAD interop preserved (both bind raw str).
WASM keys crypto by the string itself (in-proc map), no digest derivation, ADR-034 no Supervisor.

### Pre-existing (NOT introduced here), low: broadcast_routing_id=SHA-256(id) un-normalized
vs node compute_routing_id=SHA-256(lowercase(id)). Diverges only for uppercase ids; real
generate_context_id ids are lowercase. Same on main.

Tests are mutation-resistant (seed under digest, assert empty under SHA-256(id)): builder,
key_destruction, ttl, recovery-direct, broadcast-routing all distinguish decode-vs-hash via
real 64-hex fixtures (old "ctx-*" tests coincide and can't catch regression).
