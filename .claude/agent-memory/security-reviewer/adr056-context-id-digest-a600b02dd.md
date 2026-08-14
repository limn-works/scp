# ADR-056 Canonical Context Identity = 32-byte digest (branch ctxid-digest, HEAD a600b02dd) -- 2026-06-29 -- ZERO FINDINGS

Reviewed `git diff origin/main...HEAD` (22 files). #1924 fix: runtime keyed crypto under `SHA-256(id)` but id is ALREADY `hex(digest)`, so it double-hashed -> MLS/sender-key/event-log keyed at wrong slot; §6.2.4 saga `target_context_id` (raw digest) never matched -> uncommittable in prod (masked only by non-hex test fixtures).

CHOKEPOINT `context_id_to_bytes` (state.rs:2072): if len==64 && all lowercase-hex -> hex::decode to [u8;32] digest; else SHA-256(id) via raw primitive. TOTAL/panic-free (if-let-chain falls through to fallback; clippy denies unwrap). `pub` for cross-crate FFI reach via scp_core facade.

KEYING vs ROUTING separation is the crux and is CORRECT:
- KEYING (MLS seal/open, sender keys, event-log storage/merkle root, key-destruction) -> chokepoint digest. All ~20 runtime keying sites + 6 FFI event-log/test-harness sites converted from raw `context_id_bytes` to `state::context_id_to_bytes`.
- ROUTING (relay addressing) -> SHA-256-based primitives UNCHANGED: broadcast=`broadcast_routing_id`(=`context_id_bytes`=SHA-256(id)); encrypted=`context_routing_id`(domain-sep SHA-256) or per-member pseudonyms; outer-envelope routing_id zeroed for privacy.

THREE COMMITS:
1. 295bc3154 recovery_send_notification_direct: keying via chokepoint (was raw primitive -- false premise that only synthetic identity-private-state reached it; revoke_ucans/rotate_key_packages dispatch REAL 64-hex unregistered member contexts). inner.epoch hardcoded 0 is safe (plaintext, NOT AAD-bound; AAD binds sender-key epoch from real crypto state; recipient ignores inner.epoch). routing stays context_routing_id.
2. a969122b6 broadcast publish: was routing send_message via `context_id_to_bytes` (keying digest) -- ADR-056 broke the old incidental equality digest==SHA-256(id), storing blob at slot no subscriber/projection reads -> scp-node host_site CommitCountMismatch{committed:0}. Fixed to `broadcast_routing_id`. VERIFIED read-side `scp-node/projection.rs:79 compute_routing_id`=SHA-256(lowercase(id)) == broadcast_routing_id for real lowercase 64-hex id. Symmetry restored.
3. a600b02dd real-64-hex key-destruction regression tests.

SEAL/OPEN GUARD (provider.rs:1581/1675): now `context_id_to_bytes(ctx_str) != *context_id => Err(CryptoFailed)`. Fails CLOSED, typed error, no material leak. Negative test for hex(ctx_id) now passes the resolve guard (hex IS canonical) and rejection moves one layer deeper to AEAD AAD mismatch -- still proves §9.16.1 (AAD binds raw string). Dedicated guard-rejection covered by `open_rejects_context_id_str_that_does_not_resolve_to_context_id`.

KEY DESTRUCTION forward secrecy REAL: key_destruction.rs:88 + ttl.rs helper both route via chokepoint. New tests (key_destruction.rs / ttl.rs / supervisor.rs recovery_direct) all seed MLS group+sender key under the DIGEST of a real 64-hex id, drive the PRODUCTION path with the STRING id, assert export_crypto_state(digest) non-empty before / empty after. Mutation-resistant: a regression to raw SHA-256(id) leaves digest slot populated -> assertion fails. ttl test drives real `try_ttl_expiry_cleanup`, not just the helper.

INPUT HANDLING (join/import attacker-influenced id): NO aliasing. hex injective (distinct 64-hex -> distinct digest). To hit an existing context's digest slot you must present its exact hex(digest) (already know it) OR find a non-64-hex SHA-256 second-preimage of a victim's 32-byte digest (infeasible). No panic surface (total fn). No cross-context key reuse.

AUTHORIZATION UNAFFECTED: grep confirms zero capability/UCAN/membership/governance predicate changes. governance_logic/class_s/governance-handler edits are event-log STORAGE-slot keying only (+ test arg resolution). builder.rs:766 local `context_id_bytes` helper now delegates to chokepoint -> creation keys digest == state.context_id (pinned by `create_context_keys_crypto_under_decoded_digest_not_sha256`).

Remaining raw `context_id_bytes` calls: chokepoint's own fallback (state.rs:2088), broadcast_routing_id primitive, and #[cfg(test)] modules only. Compile-time `ContextDigest` newtype enforcement deferred to #1931 (source-text gate correctly REJECTED as non-convergent fail-open class).
