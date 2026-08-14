# ADR-056 Canonical Context-ID Keying Chokepoint (PR feat/123, HEAD bb183ba70) -- 2026-06-28

## What the change is
ADR-056 (#1924): canonical context identity = 32-byte digest; id string = `hex(digest)`.
Keying funnels through `scp_runtime::context::state::context_id_to_bytes` (decode-64-lowercase-hex-else-SHA256).
Raw `scp_protocol::context::context_id_bytes` (SHA-256) on a real 64-hex id DOUBLE-HASHES -> wrong slot -> silent fail-open.
Fixes 4 FFI event-log sites (PyO3 query_manager_entries, NAPI event_log_query_on + event_log_verify_on, UniFFI bridge query),
key_destruction (real Ephemeral-close fail-open), MLS seal/open guards, builder/ttl/governance/messaging keying.
`context_id_to_bytes` `pub(crate)`->`pub`. Gate `scripts/check-context-id-keying.sh` (coarse tripwire, on NEVER-WEAKEN list).

## Verified SOUND
- Chokepoint resolver: 64-char + all-lowercase-hex guard is closed and TOTAL (no panic/unwrap; fallthrough to SHA256). Decodes digest verbatim.
- `pub` widening is SAFE: `scp_core::context::state` was ALREADY `pub use`-re-exported (no diff to scp-core/lib.rs). Only the fn went pub WITHIN an already-public module. Pure &str->[u8;32], no secret/capability -- a caller who knows the id can already compute both branches. Keying bytes are a SLOT LABEL, not access control (MLS membership is). Zero new capability. ContextDigest newtype follow-up = #1931.
- Gate: self-test PASSES (all detection+exemption rules incl. brace-depth early-test soundness). Real scan = exactly 2 allowlisted (state.rs:2088 resolver fallback, supervisor.rs:3547 synthetic identity-private-state). Anchors pinned. Only ADDS coverage (scans scp-ffi + scp_core spelling + alias/import shapes). CI wires self-test-first then real check.
- builder.rs/ttl.rs local `fn context_id_bytes` wrappers now delegate to chokepoint; files don't import raw symbol so bare calls not flagged. Correct.
- MLS seal/open guard moved to chokepoint: `hex(ctx_id)` now PASSES the guard (it IS the canonical id form) but AEAD AAD still rejects (binds raw string). Rejection moves 1 layer deeper; §9.16.1 property preserved. Not a regression.
- WASM out of scope CORRECTLY: WasmContextManager keys event-log by `require_context(context_id)` STRING map, no 32-byte digest derivation -> double-hash class structurally impossible (ADR-034 reimpl).

## FINDING (pre-existing, in-scope to flag): PyO3 + UniFFI verify prove over UNSYNCED tree
- NAPI `event_log_verify_on` (napi/src/event_log.rs:237-289) SYNCS manager Merkle entries into rt.core.event_log (push_leaf_raw) BEFORE prove_inclusion/prove_absence. Keying fix makes this read the right slot.
- PyO3 `event_log_verify_impl` (src/event_log.rs:507-) and UniFFI `event_log_verify` (uniffi/bridge.rs:12951-) have NO manager-sync. They prove over rt.event_log / ucan_state.event_log which receives ONLY direct UCAN-revocation + provenance appends, NEVER manager lifecycle events (ContextCreated, membership, etc.).
- `push_leaf_raw`/sync exists NOWHERE in crates/scp-ffi/src/ (PyO3) -- grep-confirmed. Only NAPI has it.
- => PyO3 (REFERENCE bridge, 100% coverage target) + UniFFI absence proofs can prove ABSENCE of a lifecycle event that genuinely IS in the authoritative log = FALSE-NEGATIVE absence proof = repudiation/audit-evasion primitive. Exactly focus#1's class.
- Pre-existing on origin/main (NAPI synced, PyO3/UniFFI did not). This PR's keying fix does NOT close it. Cross-bridge parity violation (ADR-046 OP_EVENT_LOG_* pins query filter but NOT verify sync).
- Recommendation: port NAPI's manager-sync into PyO3 + UniFFI verify, or hoist to scp_ffi_common shared helper. Both must funnel ctx-id through context_id_to_bytes.
