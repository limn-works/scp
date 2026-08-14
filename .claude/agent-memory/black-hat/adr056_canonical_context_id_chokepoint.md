# ADR-056 canonical context-id chokepoint (PR @7ce298ab2)

Canonical context identity = 32-byte digest; id string = hex(digest). Resolution
is DECODE-not-rehash via single chokepoint `context_id_to_bytes` in
`crates/scp-runtime/src/context/state.rs:2072`. Raw `scp_protocol::context::
context_id_bytes` is SHA-256 primitive; using it on a real 64-hex id double-hashes
(SHA-256(hex(digest))) -> wrong slot -> fail-open.

## Audit verdict: CLEAN. No remaining production fail-open keying path.
- Every production crypto/event-log/transport keying site routes through
  `context_id_to_bytes`: builder.rs (local shadow wrapper :704 delegates),
  supervisor recovery_send_notification_direct :3580, trust_recovery_helpers :322/453,
  messaging/lifecycle/ttl_close/broadcast/governance helpers, class_s :5701,
  actor handlers, identity/recovery.rs :2083 (synthetic label), all 4 FFI sites
  (pyo3/napi event_log+testing, uniffi bridge :12784).
- ONLY production raw `context_id_bytes(` call = resolver's own fallback (state.rs:2088).
  All others in `crates/` are tests/fixtures.
- WASM has NO string->keying derivation: per-context `EventLog` stored in
  WasmContextState (manager.rs:660), addressed by handle, not a 32-byte slot. ADR-034
  isolation means no double-hash surface. Diff correctly doesn't touch WASM.
- scp-node/relay `compute_routing_id` = ROUTING only (dumb-pipe blob address), never
  MLS keying. NOTE (pre-existing, NOT this PR): node projection.rs:compute_routing_id is
  BARE SHA-256(lowercased id), runtime context_routing_id is domain-separated
  SHA-256("scp:context-routing:"||id) — different fns, but routing not keying.

## seal/open guard fix (provider.rs) — necessary, not cosmetic
Old defense-in-depth guard compared `context_id_bytes(ctx_str) == *context_id` (raw
SHA-256). Callers now pass chokepoint digest as context_id; ctx_str is real 64-hex ->
old guard would SHA-256(hex(digest)) != digest -> FAIL CLOSED on every real-context
seal/open (self-DoS). Fix aligns guard to context_id_to_bytes. AAD still binds the RAW
ctx_str, so encryption-as-access-control is the deeper backstop (AEAD rejects mismatched
string even if guard passed). Resolution effectively injective (hex-decode unique;
cross-branch collision = SHA-256 preimage, infeasible).

## Regression tests are genuinely mutation-resistant (verified by reading)
- builder.rs:967 create_context_keys_crypto_under_decoded_digest_not_sha256: asserts
  export_crypto_state(digest) NON-empty AND export_crypto_state(SHA-256(id)) EMPTY.
  Regress to raw primitive -> both assertions flip -> FAIL.
- supervisor.rs:14121 recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive:
  seeds MLS under digest, drives direct path; distinguishes TransportFailed (seal found
  state under digest = correct) vs CryptoFailed "no MLS group" (seal keyed off raw =
  regression, explicit panic "ADR-056 REGRESSION"). Mutation-resistant.

## Import collision concern — NOT exploitable (backstop holds)
import_context keys via chokepoint :1836. Attacker can't forge colliding 64-hex id:
snapshot creator-signed, validate_export_for_import checks exporter==creator + sig BEFORE
consume; generate_context_id is CSPRNG (2^256 to hit a victim digest). Encryption-as-
access-control = backstop.

## Minor (non-finding): builder.rs:704 local `fn context_id_bytes` shadows the protocol
name. Functionally a chokepoint delegate, but the name collision is a future-maintainer
trap (a `use scp_protocol::context::context_id_bytes` would shadow-confuse). #1931
ContextDigest newtype is the principled fix.
