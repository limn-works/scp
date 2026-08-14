# ADR-056 keying/routing split — branch chore/fuzz-pin-nightly @a969122b6 (broadcast+recovery routing fixes)

CLEAN review (Jun 2026). The two follow-up commits (a969122b6 broadcast, 295bc3154 recovery) correctly
fix the keying-vs-routing split that ADR-056 broke when it made `context_id_to_bytes(64-hex id) = decoded
digest != SHA-256(id)`.

## The mechanism (verified correct + total)
- `context_id_to_bytes` (state.rs:2072): guard `len()==64 && all(is_ascii_digit || b'a'..=b'f')` = exactly
  [0-9a-f]. 64 lowercase-hex ALWAYS decodes to 32B, both `if let Ok` are belt-and-suspenders, fallthrough
  to `scp_protocol::context::context_id_bytes` (raw SHA-256) keeps fn total. No panic/unwrap. Empty/odd/
  uppercase/non-hex all hit fallback (unchanged from pre-ADR-056).
- KEYING (MLS group, sender key, event log, seal/open) → `context_id_to_bytes` (digest for real id).
- ROUTING (relay slot) → distinct primitives, NOT the keying digest:
  - broadcast: `broadcast_routing_id` = `context_id_bytes` = raw SHA-256(id), no domain sep (§5.14.6).
    Read side `scp_node::projection::compute_routing_id` = SHA-256(lowercase id). MATCH for real (lowercase)
    ids. broadcast_helpers.rs:360 apply_broadcast_publish now routes send_message under routing_id, fixing
    host_site CommitCountMismatch{committed:0}.
  - encrypted send: outer routing_id ZEROED (pseudonym fanout §9.10.4); digest only feeds crypto.seal.
  - recovery: `context_routing_id` = domain-sep SHA-256("scp:context-routing:"||id); digest only feeds seal.

## Recovery direct path (supervisor.rs:3583 recovery_send_notification_direct)
- Now keys via `context_id_to_bytes` (was raw `context_id_bytes` on main → double-hash fail-open for real
  unregistered member ctxs from revoke_ucans/rotate_key_packages). Matches registered-actor
  trust_recovery_helpers::recovery_send_notification (also `state::context_id_to_bytes`). Both paths key
  same slot. inner.epoch hardcoded 0 is safe (plaintext, not AAD-bound; AAD binds sender-key epoch from
  real crypto state in seal; recipient ignores inner.epoch).
- standing-reconnect publish (9086): `"standing-"+hex` id (len 73, leading 's') → SHA-256 fallback,
  behavior-preserving vs main's raw context_id_bytes. Correct fallthrough.

## seal/open defense check (provider.rs:1581/1664)
- Switched guard from `context_id_bytes(ctx_str)!=*context_id` to `context_id_to_bytes(...)`. Consistent
  with callers. For TEST_CTX_STR="h9-ceiling-ctx" (non-64-hex) both equal; guard passes. For real ids the
  decoded digest matches.

## Tests verified MUTATION-RESISTANT (fail if fix reverted)
- builder.rs:967 create_context_keys_crypto_under_decoded_digest_not_sha256: asserts crypto state IS under
  digest AND empty under SHA-256(id). Revert→delegate to raw→fails.
- broadcast_helpers.rs:907 broadcast_publish_routes_under_sha256_routing_id_not_keying_digest: asserts
  routing == SHA-256(id) AND != digest. Revert→fails.
- supervisor.rs:14116 recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive: seeds MLS+sender
  under digest, drives direct path; expects TransportFailed("transport not configured") NOT CryptoFailed.
  With raw primitive seal hits with_context "no MLS group" / line-1581 guard → CryptoFailed. Verified
  NotConfiguredTransportProvider.send_message returns that exact TransportFailed; with_context returns
  CryptoFailed on missing key. Sound.
- provider.rs:4483 seal_open negative case now `.expect_err` WITHOUT error-string assert (hex(real digest)
  now passes the top-of-open guard, AEAD rejects one layer deeper). Slightly weaker but NOT spurious:
  positive case proves same blob opens with raw string, so only the AAD mismatch can fail negative. The
  dedicated guard test (4537 open_rejects_..._resolve...) keeps the strict error-string assert. Acceptable.

## Resolved my prior LOW finding
- supervisor.rs:12702 signed_import_export_with_member: was keyed under raw context_id_bytes with a STALE
  "import path's own derivation" comment (latent success-path mismatch). NOW fixed to context_id_to_bytes
  + comment corrected. Matches import_context.

## No bulk-conversion misses
- grep'd all context_id_bytes( in runtime/ffi/testing. Remaining sites: the fallback inside the chokepoint,
  the chokepoint's own unit tests, builder.rs:766 local wrapper (delegates to chokepoint), and
  export_import.rs literal "ctx-*" non-64-hex TEST ids (both fns equal → no mismatch; production
  export_import takes ctx bytes as a param, rerouted at lifecycle_helpers callers). All FFI bridges
  (pyo3/napi/uniffi) + scp-testing node.rs deposit/lookup both key via chokepoint — aligned.
- Cross-crate export verified: runtime `pub mod state`, scp-core/src/lib.rs:91 `pub use scp_runtime::context::state`.
  FFI `scp_core::context::state::context_id_to_bytes` resolves.

## Latent (PRE-EXISTING, NOT this diff)
- projection.rs:79 compute_routing_id lowercases before hashing; write-side broadcast_routing_id/
  context_id_bytes does NOT normalize. Diverges only for mixed-case ids; real generate_context_id ids are
  lowercase so harmless. Not introduced here.
