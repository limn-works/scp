---
name: adr056-canonical-context-digest
description: ADR-056 review — context-id keying funnels through context_id_to_bytes chokepoint (decode 64-hex→digest, else SHA-256); routing stays SHA-256. Branch ctxid-digest @ a969122b6/295bc3154. ZERO findings.
metadata:
  type: project
---

# ADR-056 canonical context identity = 32-byte digest — security review (2026-06-29) ZERO FINDINGS

Branch ctxid-digest, HEAD a969122b6 (broadcast routing fix) + 295bc3154 (recovery routing fix).

**Mechanism:** single chokepoint `context_id_to_bytes(id)` at scp-runtime/src/context/state.rs:2072 (now `pub`, was `pub(crate)`). If id is EXACTLY 64 chars all-lowercase `[0-9a-f]` → `hex::decode` to 32-byte digest; else `SHA-256(id)` via raw `scp_protocol::context::context_id_bytes`. Total fn, no unwrap (length+charset guard, fallible-with-fallthrough). KEYING (MLS group, sender keys, event log, seal/open AAD-consistency, key destruction, store key) routes through chokepoint. ROUTING is separate: `context_routing_id`=domain-sep SHA-256 (encrypted), `broadcast_routing_id`=SHA-256(id) (broadcast).

**KEY INSIGHT — pre-existing state framing:** On origin/main, `context_id_to_bytes` was ITSELF just `SHA-256(id)` (identical to raw primitive). So on main the whole keying surface was INTERNALLY CONSISTENT (creation+send+recv+destroy+broadcast-publish+projection all under SHA-256(id)). The genuinely-broken-on-main defect was §6.2.4 xctx-saga UNCOMMITTABILITY (wire carries raw digest per §6.2.4:276, runtime keyed under double-hash SHA-256(hex(digest)) → target-binding never matched). The three "fail-opens" (recovery/broadcast/key-destruction) are RISKS THIS CHANGE INTRODUCES (by making chokepoint decode to digest) and CLOSES ATOMICALLY in the same series — NOT relocated pre-existing bugs. ADR's "closes three fail-opens" framing is generous but net result is correct + self-consistent.

**Verified closed:**
1. key_destruction.rs:88 now `state::context_id_to_bytes`. destroy_mls_group (provider.rs:813) does `if let Some=contexts.remove(id)` → SILENT no-op + Ok(()) on empty slot. Once live group keys under digest, destroy MUST decode too, else forward-secrecy fail-open (attestation reports KeysDestroyed while real group survives). Closed.
2. broadcast publish (broadcast_helpers.rs:apply_guarded) routes send_message slot under NEW `broadcast_publish_routing_id`=`broadcast_routing_id`=SHA-256(id), matching scp_node projection compute_routing_id. NOT the keying digest (would store blob at unread slot → host_site CommitCountMismatch{committed:0}). Closed.
3. recovery_send_notification_direct (supervisor.rs:3569) keys via chokepoint (decoded digest for real 64-hex member ctx during revoke_ucans/rotate_key_packages compromise recovery), routes via context_routing_id. Symmetric with registered handler trust_recovery_helpers.rs:322 (also chokepoint). inner.epoch hardcoded 0 is SAFE: signed plaintext, NOT AAD-bound; AAD binds sender-key epoch from real crypto state; recipient ignores inner.epoch. Closed.

**Aliasing (item 3):** decode branch fires only on 64-lowercase-hex; hex::decode injective → a crafted id IS its own digest, cannot alias another context's digest without being byte-identical. Cross-branch collision (64-hex id == SHA-256(synthetic_label)) = 256-bit preimage, infeasible; synthetic/standing labels never bare-64-hex → always hash. No cross-context key reuse, no panic/DoS.

**seal/open guard (provider.rs:1581/1675):** consistency check `context_id_to_bytes(ctx_str) != *context_id → CryptoFailed`. Sound, symmetric, fails closed, no material leaked. AAD still binds RAW ctx_str per §9.16.1 (native↔WASM interop).

**Error surfaces:** TransportFailed vs CryptoFailed distinction is mutation-resistant test discriminator (seal-success-under-digest vs no-MLS-group). Open-guard rejection = generic typed CryptoFailed, no leak.

**Authorization UNAFFECTED:** purely id→bytes resolution + 2 routing corrections. No UCAN/capability/membership/governance check touched (confirmed by fork over governance_logic/ttl/lifecycle/class_s/governance handlers/mod/node/uniffi-bridge).

**FFI:** all 4 event-log + 6 test-harness keying sites (scp-ffi/src + napi + uniffi) rerouted from raw `scp_core::context::context_id_bytes` to `scp_core::context::state::context_id_to_bytes` (facade re-export of chokepoint). All remaining raw `context_id_bytes(` calls in runtime/ffi are tests, the resolver's own fallback (state.rs:2088), or routing. builder.rs:704 has local shadow delegating to chokepoint.

**Tests:** canonical_context_id_tests (state.rs:2253) pin all 6 branches; create_context_keys_crypto_under_decoded_digest_not_sha256 (builder.rs); broadcast_publish_routes_under_sha256_routing_id_not_keying_digest; recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive (mutation-resistant TransportFailed-vs-CryptoFailed).

Mechanical enforcement deferred to ContextDigest newtype (#1931); source-text grep gate correctly REMOVED (non-convergent pseudo-lexer fail-open class, per ADR-2E OwnedIdentityDid precedent).
