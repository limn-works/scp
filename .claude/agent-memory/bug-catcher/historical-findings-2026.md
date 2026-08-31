---
name: historical-findings-2026
description: Per-review bug findings from Feb-Jun 2026 SCP reviews, grouped by branch or PR; the archive MEMORY.md used to inline
metadata:
  type: project
---

# Per-review findings archive (Feb-Jun 2026)

Read a section only when you review the same area again. `recurring-patterns.md`
carries the distilled patterns; this file carries the specific instances.

## Feb 2026 — early reviews (summary)
Governance symmetry gaps, dead ownership checks, TOCTOU in standing_channel
(fixed), empty-set attenuation bypass (still in spending.rs), Python `delegate()`
token_id-as-context (still present), UniFFI key material discarded on
identity_create, divergent canonical attestation formats, missing field
separators in canonical hash, late votes accepted after deadline, silent message
drop in callbackFlow.

## Mar 2026 — PR #127, loom/main-0301-0312
Pass 1: UniFFI `ucan_mint` signs with an ephemeral key (token claims
issuer_did = creator, signature from a per-call InMemoryKeyCustody). FIXED since:
TTL sentinel collision, NAPI transport_disconnect TOCTOU, HotStreamFactory maps,
ScpViewModel.trackContext scope, rememberScpEventList scope leak.

Pass 2:
- MessageType discriminator absent from the canonical hash (HIGH). inner.rs
  documents `as_discriminator_byte()` as type-flip defense; `compute_canonical_hash`
  never includes it, and `InnerEnvelopeParams` has no `message_type`.
- WASM `ucan_validate` wildcard context prefix (HIGH): `starts_with("scp:ctx:{id}")`
  with no trailing `/` lets IDs that share a prefix escalate across contexts.
- Python `delegate()` mints without a parent proof (HIGH) — the delegated token
  reads as a root token. No `py_ucan_delegate` FFI binding exists.
- Compose `rememberScpHotStream` launches `onStop()` then cancels the scope (MEDIUM).
- `HotStreamFactory.contextEvents` get-then-put across a suspend point (MEDIUM).
- `CheckpointManager.is_checkpoint_due` ignores `min_events_since_last` (LOW).

## Mar 2026 — Transport expansion (DTLS/CoAP/QUIC/pool/manager/cover)
- UDP listener `dispatch_datagram` session limit uses a read lock (HIGH); safe
  only because the recv loop is sequential.
- UDP adapter `send_request` acquires the mutex three times (MEDIUM,
  udp/adapter.rs:176-194) — concurrent callers get mismatched responses.
- CoAP Observe and `request()` interleave on one DTLS session (MEDIUM,
  coap/adapter.rs:238-244).
- QUIC `deliver_to_subscribers` still `try_send` (MEDIUM).
- `BlockOption::block_size` accepts reserved SZX=7 (LOW, coap/message.rs:450).
- `send_to_context` hardcodes `latency_ms: 0` (LOW, manager.rs:459).
FIXED in that PR: MergedStream Pending-on-duplicate, QUIC accept_loop TOCTOU.

## Mar 2026 — Transport expansion, deferred-fix pass
- `MergedStream::poll_next` duplicate branch lacks `wake_by_ref()` (HIGH,
  manager.rs:1230-1232) — the task hangs when the rest return Pending.
- `per_client_recv_loop` holds a read lock across a 10 s DTLS recv (HIGH,
  udp/listener.rs:607-614).
- WebSocket server spawns no `rate_limiter_cleanup_task` (MEDIUM).
- `handle_new_client` comment claims one write lock, uses read + write (MEDIUM).
- `datagram_recv_loop` awaits the DTLS handshake in line (MEDIUM).
- `deliver_to_subscribers` holds a read lock across a 50 ms jitter sleep (LOW).

## Mar 2026 — Transport expansion, relay listener/session/client
- QUIC `handle_subscribe` TOCTOU on `my_subscriptions` (MEDIUM, quic/listener.rs:852).
- WebSocket relay total-connection limit split across two locks (MEDIUM,
  native/server.rs:482-512).
- WebTransport `subscribe_rate_limit` doc says per second, limiter treats it as
  per minute (MEDIUM, webtransport/session.rs:109).
- WebTransport listener spawns no rate-limiter cleanup (MEDIUM).
- WASM client leaks three `Closure::forget()` per reconnect (LOW, client.rs:386/399/430).
- WASM client broadcasts `BackfillComplete` to every subscription when an EVENT
  carries no ref_id (LOW, client.rs:1339-1352).

## Mar 2026 — production-readiness commits (7-commit review)
- `ProtocolRepository` migration chain still uses positional msgpack
  (`rmp_serde::to_vec`) at store/mod.rs:362 while the public paths moved to
  `to_vec_named` (MEDIUM, latent).
- `validate_block_notification_freshness` uses plain `+` for the freshness bound
  (LOW, key_protocol.rs:683).

## Mar 2026 — #310/#319 PkarrDhtClient + UCAN tool invocation
- WASM `validate_tool_ucan_wasm` reads `rt.revoked_tokens` (never written) instead
  of `WasmUcanState.revoked_cids`, and hashes the whole JWT string rather than the
  serialized payload (HIGH).
- The same function documents a ceiling check it never performs (HIGH).
- It treats required `exp`/`aud` as optional via if-let (HIGH).
- `main.rs` never calls `initialize_sequence()`/`set_sequence()` on `DidDht` (HIGH).
- `resolve_via_gateway` returns unverified BEP44 records (MEDIUM).
- All four non-WASM tool bridges pass an empty `BridgeProofResolver` map (MEDIUM).
- #319's "mint without tool capability -> rejected" test is missing (MEDIUM).

## Mar 2026 — #321/#326 timestamp validation + UniFFI UCAN signing
- `ucan_delegate` fallback URI prefixes short capability names with the
  delegator's context_id instead of the parent token's (HIGH, bridge.rs:2227).
- `SequenceTracker` checks sequence monotonicity but not per-sender timestamp
  monotonicity per §9.8.2(c) (MEDIUM).

## Mar 2026 — production readiness iteration 3 (#347/#349/#327/#315/#325)
- `SenderKeyResponse.hpke_sealed_key` keeps unbounded `serde_bytes` (HIGH,
  key_protocol.rs:209) — OOM precedes the runtime check at line 757.
- `check_tofu()` and `check_certificate_pin()` are never called from resolution
  or connection paths (HIGH) although #325 requires both.
- key_protocol.rs duplicates `serde_signature_64`/`serde_pubkey_32` locally (MEDIUM).
- `serde_bounded_bytes` allocates from the msgpack length hint before checking (MEDIUM).

## Mar 2026 — production readiness iteration 4 (#357/#299/#311)
- `SubscriberRegistration` signing input concatenates context_id + subscriber_did
  with no length prefixes or domain separator (HIGH, broadcast.rs:94-106).
- #311 left `BridgeDidResolver` in three production paths: src/tools.rs:251,
  napi/src/tools.rs:168, src/mcp.rs:662 (HIGH).
- `wrapping_pubkey` is `Vec<u8>` where the spec says 32 bytes (MEDIUM, broadcast.rs:70).

## Mar 2026 — fix/audit-remaining-findings (three passes)
Passes 1 and 2 verified fixes: joiner sender-key regeneration, WASM
`canonical_template_name` aliases, `import_context` TOCTOU, `TemplateId`
serde alias, WASM wildcard capability match, checkpoint-signature Zeroizing
removal, `RequiredSignal` Eq removal, `parse_template_id` across all four
bridges, PyO3 `VALID_TEMPLATE_IDS`.

Pass 3 — Kotlin `fromJsonObject` crashes on an `Active` RevocationStatus (MEDIUM,
Identity.kt:335): `obj["revocation_status"]?.jsonObject` throws
IllegalArgumentException when the value is the string `"Active"`. `?.` guards
null only. Fix with an `is JsonObject` check.

## Mar 2026 — Phase 5 step 2 (#386-389 FFI bridge rewrite)
- PyO3 `py_context_close` discards the ContextManager close error with
  `let _ = close_result;` (HIGH, context.rs:1026) — split-brain state.
- Close authorization diverges across four bridges: PyO3 RBAC, UniFFI/NAPI
  creator-only string compare, WASM creator-or-admin, ContextManager its own (HIGH).
- PyO3 `FfiBridgeState.role_state` never re-syncs after ChangeRole/ModifyCeiling
  (MEDIUM, runtime.rs:349-355).
- NAPI `context_create` drops caller-set ceiling/governance/promotion_policy/
  ceiling_policy through `..ContextParams::default()` (MEDIUM, napi/src/context.rs:304).
- NAPI calls `register_local_did` in context_create; UniFFI and PyO3 do not (LOW).

## Mar 2026 — PR #1586 wiring/batch-1-messaging envelope pipeline
- All three non-WASM bridges pass `None` for `signing_key` to `send_message`,
  so every FFI send fails for an encrypted context (HIGH).
- `rollback_sequence_number` runs on the broadcast path, which never took a
  sequence number (HIGH, latent because `saturating_sub(0) == 0`).
- `trust_recovery.rs` builds an InnerEnvelope without `wrap_content`, so
  `deliver_incoming` cannot deserialize the recovery notification (HIGH).
- Sender-key and access-key AAD hardcode epoch 0 / sequence 0 (MEDIUM).
- `deliver_message_and_drain_buffered` uses `inner.sequence + 1` (MEDIUM).
- `SequenceTracker` accepts sequence 0 for a first message (LOW).

## Mar 2026 — wiring/batch-2-governance
- `check_standing` and `enforce_role_demotion` use `SystemClock` instead of the
  injected clock (HIGH, governance.rs:231 and :53).
- `enforce_send_economy` blocks every sender without a pre-granted budget, and
  the creator cannot propose a grant because governance messages are blocked too
  (HIGH, messaging.rs:47-52). Same in `enforce_join_economy`, `check_tool_economy`.
- `execute_paid_action` discards `record_spend`'s Result (HIGH, economy.rs:275).
- `standing_context` drops its lock before `create_context` (HIGH, standing.rs:89).
- `enforce_capability_suspension` substring-matches "write"/"read" on capability
  names, so "spreadsheet" and "overwrite" misfire (MEDIUM, governance.rs:31-35).
- Per-action economy functions and `execute_paid_action` both call `record_spend`
  — double charge with a payment adapter configured (MEDIUM).
- `event_log_entries_for_consequences` stamps every synthesized event with `now`,
  so velocity triggers see them as simultaneous (MEDIUM, governance.rs:197).
- `lifecycle.rs:226` hardcodes a 3600 s velocity window instead of restoring the
  persisted `window_secs` (MEDIUM).

## Jun 2026 — PR-E #1543 enforcement hardening
- `pretooluse-enforcement-files.sh:85` write-verb regex includes bare `bun|node`
  and `python...\.py`, so read-only invocations that merely name a protected
  basename get blocked — including the repo's own validator (MEDIUM, false
  positive). Fix: drop the bare interpreter forms; keep `python -c` and redirects.
- The first unguarded `jq` at line 53 runs under `set -e`; malformed JSON exits 5,
  not the controlled `exit 2`, so the fail-closed handler at line 108 is
  unreachable for parse errors (LOW).
- Line 109's fail-closed message says "jq failed to parse tool_input" but fires on
  an absent file_path (LOW, cosmetic).
- VERIFIED CLEAN: `cites_durable_provenance` byte slicing is panic-safe; 44
  ffi_conformance tests pass; bridge-aliases.json valid; the WASM identity rename
  is complete.

## Jun 2026 — check-handler-no-panic.sh (60692e6, then 77c3296)
- 60692e6's flag-to-stack fix in `scan_helper_file`/`scan_dispatch_hub` is sound
  across deep nesting, sibling gates, same-line multi-pop, and double gates.
  System awk is mawk 1.3.4; the `gated_top==0` short-circuit is portable. Old
  scanner produced 5 false positives in supervisor.rs; new produces 0.
- 77c3296 replaced that stack with a scalar floor latched on first entry.
  Behaviorally equivalent — proven by a 4000-iteration differential fuzz over both
  functions (0 mismatches) plus targeted fixtures. The load-bearing element is the
  `if(!in_gated)` guard.
- PRE-EXISTING, unchanged by either commit: a `#[cfg(test)]` on a non-braced item
  (`use`/`const`/`type`) latches `gated_pending` onto the NEXT braced item and
  swallows a real panic there (MEDIUM, latent, not live). A char-literal `'{'`
  breaks depth accounting the same way (LOW, latent, 0 occurrences).

## Jun 2026 — event-log unification Phase 2 (dc18f5899, then 3d96058f5)
- The HIGH fix `run_buffered_post_delivery(event_name: Option<EventType>)` is
  correct and complete across all four buffered drain sites
  (messaging_helpers.rs 2244/2324/2434/2545). No double-count, no fifth site.
- Its regression test calls the helper directly with `event_name=None`, so it
  pins the helper contract, not the four call sites where the bug lived. A
  re-introduced `if let Some` gate at a call site would not be caught (LOW).
- The consequence decode rewrite is sound: msgpack is tried first, then JSON;
  a JSON `{` reads as a msgpack fixint, never a fixarray header, so no collision.
- `leaf_hash` extraction in tree.rs is clean; `verify_merkle_chain` rejects
  prefix truncation, reorder, removal, and suffix truncation.
- All four FFI bridges migrated `EventLogEntry` to `scp_event_log::Event`.
- Final substrate-swap review at 3d96058f5 was CLEAN: test helpers are
  `#[cfg(test)] pub(crate)`; `now_ms` cfg arms are mutually exclusive and the
  production wasm path is byte-identical; the non-backdatable deadline fix is
  correct; committer-assigned convergent timestamps leave only the prune cutoff
  on `SystemTime::now()`, which is a local decision, not a leaf hash.
- PRE-EXISTING: `prune_before_checkpoint`'s break-on-first-retained is
  non-monotonic under `structural_retention_multiplier`; errs toward over-retention.
- PRE-EXISTING, not a branch regression: scp-event-log --lib checkpoint/metrics
  tests fail locally with `InvalidSignature: unsupported DID format did:key:...`
  identically on origin/main — a local feature-flag environment issue.

## Jun 2026 — fix/sdk-coverage-fail-closed-and-parity
- `economy_verify_payment_receipts` wire-shape mismatch (HIGH at the time). The
  canonical shape from `verification_results_to_json` is
  `{"all_valid": bool, "results": [...]}` with no top-level `ok`, and the reject
  field is `error`, not `reason`. TS declared a required top-level `ok` and
  invented `reason?`; the Python parity test mocked `"receipts"` instead of
  `"results"`.
- RE-REVIEW AT HEAD: both were fixed. `PaymentReceiptVerificationEntry` now
  matches `verification_results_to_json` exactly, `economyVerifyPaymentReceipts`
  is correctly sync (the NAPI export owns its own block_on), and no dangling type
  references remain. Gate PASS, 62 TS tests pass.

## Jun 2026 — SCP-AB-021 KeyResolver VM-widening (ba06a8e0 + 7d4cdcf0) — CLEAN
KeyResolver widened from `Fn(&DID) -> Option<VK>` to
`Fn(&DID, SigningKeyId) -> Option<VK>`. Threading verified end to end from
`Supervisor::send_message` through `build_encrypted_envelope`;
`verify_and_unwrap` reads the wire value. All FFI bridges and self_host pass
`SigningKeyId::Active`, preserving prior behavior. `from_fragment` is the sole
canonical decoder.

PRE-EXISTING, not that diff: every production resolver (bridge_instance,
self_host, bridge_runtime not_configured) returns `None` regardless of arguments.
Real DID-document verification-method resolution is unwired, so encrypted-context
receive verification fails closed in a real deployment.
