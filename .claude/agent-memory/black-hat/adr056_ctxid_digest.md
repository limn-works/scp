# ADR-056 canonical-context-id-as-digest (branch ctxid-digest, top 04f24646e)

Chokepoint `context_id_to_bytes` (scp-runtime state.rs:2072): if id is exactly
64 chars AND all `[0-9a-f]` (strict lowercase) -> hex::decode to [u8;32] digest;
else SHA-256(id) via raw `scp_protocol::context::context_id_bytes`.

## What's SOUND (verified by reading)
- Guard is exact: len==64 && all 0-9a-f. Uppercase/63/65/g-z all fall to hash. Boundary tests pin it.
- state.context_id ([u8;32], actor/state.rs:1021) set via context_id_to_bytes(handle.id) in ALL
  3 production PerContextState ctors (lifecycle_helpers.rs:1432/2064/2554 -> :1445/2078/2593).
- §6.2.4 Target-context binding saga.rs:1034 `req.target_context_id != state.context_id` now compares
  wire-digest vs decoded-digest. Producer (supervisor.rs:5480) takes [u8;32] wire value, does
  hex::encode for actor lookup; actor registered under handle string = hex(digest). Round-trips.
- builder.rs:704 local context_id_bytes wrapper now delegates to chokepoint (creation keys under digest).
- ttl.rs:66 local wrapper -> chokepoint (close/expire key destruction targets digest slot).
- key_destruction.rs:88 -> chokepoint (ephemeral close no longer no-ops against phantom group).
- recovery_send_notification_direct (supervisor.rs:3583) + registered recovery_send_notification
  (trust_recovery_helpers.rs) BOTH key seal under chokepoint digest, route under context_routing_id
  (domain-sep SHA-256 string). inner.epoch=0 hardcode is INERT: receive side returns early at
  messaging_helpers.rs:413 before reading inner.epoch; AAD binds sender_key_epoch not inner.epoch.
- seal/open AAD consistency guard (provider.rs:1581/1675): asserts context_id_to_bytes(ctx_str)==
  the 32-byte keying id. AAD binds RAW STRING (shared scp_protocol encrypt, same native+WASM).
- NATIVE<->WASM messaging interop PRESERVED: WASM WasmCryptoState is per-context-instance, keys
  sender-key store by (context_id STRING, sender_did), binds raw string in AAD via SAME shared
  scp_protocol encrypt. WASM never derives context_id_to_bytes. ADR-056 only changes native's
  internal HashMap slot; wire bytes (AAD=string, ciphertext under sender key) byte-identical.
- All 4 FFI event-log + 6 test-harness keying sites rerouted to scp_core::context::state::
  context_id_to_bytes (facade re-exports scp_runtime::context::state, pub mod, pub fn). No residual
  raw-primitive KEYING in scp-ffi or scp-node.
- governance read (event_log_entries_for_consequences:799) + write (governance_helpers/logic) both
  chokepoint -> consequences read the slot they write.
- publish_context (builder.rs:818) + delete_published (ttl.rs:680/870) BOTH decode -> same slot. Symmetric.
- broadcast publish routing FIXED (a969122b6): broadcast_publish_routing_id = SHA-256(id) (routing),
  event-log append still chokepoint (keying). Distinct domains by design.

## FINDING (MEDIUM, latent, pre-existing but diff's claim is FALSE for it)
Runtime<->node-projection case-normalization asymmetry on broadcast routing:
- scp-node compute_routing_id (projection.rs:79) = SHA-256(id.to_ascii_lowercase()) — NORMALIZES.
- runtime broadcast_routing_id / context_routing_id (scp-protocol mod.rs:111/129) — NO normalization.
- validate_context_id (scp-ffi/common/validate.rs:208) admits is_ascii_alphanumeric = UPPERCASE OK.
- For any caller-supplied mixed/upper-case context id: runtime publish routes SHA-256(X), node
  projection reads SHA-256(lowercase(X)) -> DIFFERENT slots -> broadcast deploy CommitCountMismatch
  (host_site fail-open). generate_context_id emits lowercase so real ids dodge it.
- commit a969122b6 doc (broadcast_helpers.rs:399-406) + regression test assert broadcast_routing_id
  == compute_routing_id "identical value" — TRUE ONLY for lowercase. Test fixture is lowercase
  hex(digest) so can't catch. Provenance defect + latent mixed-case fail-open.

## Forward dependency (not breakable in THIS diff)
§6.2.4 saga FFI export (tool_invoke_cross_context_saga, #116/#117 — NOT in this diff) MUST convert
target string->digest via the SAME chokepoint, else hex::encode(wire) != registered actor string
-> ContextNotRegistered (fail-closed, saga uncommittable — the bug ADR claims to fix). Trust assumption.
