---
name: historical-bug-patterns
description: Archive of dated per-review bug-pattern notes (Feb 2026 – Aug 2026), moved out of MEMORY.md to keep the index under its read limit. Recurring-pattern taxonomy at the top.
metadata:
  type: project
---

# Historical bug patterns (SCP)

## Recurring pattern taxonomy (the useful part — read this first)

1. **TOCTOU across async lock boundaries** (read-check-drop-write-act). The #1 pattern.
   Sites: standing_channel (fixed), NAPI transport_disconnect (fixed), Swift resolveKeyId,
   HotStreamFactory.contextEvents, QUIC accept_loop (fixed), UDP listener dispatch_datagram,
   QUIC handle_subscribe, WebSocket total-connection check, standing.rs standing_context,
   import_context (fixed). Fix: one write lock for check+mutate, or `entry()`.
2. **Bulk replacement missing call sites.** #347 `hpke_sealed_key`, #311 `BridgeDidResolver`
   in PyO3/NAPI tool paths, msgpack `to_vec_named` missed in the migration chain.
   Always grep ALL call sites when changing a type/fn/serialization format.
3. **FFI bridges mechanically passing `None`/default for a new parameter.**
   #386-389 + #1586 `signing_key`, NAPI `context_create` `..ContextParams::default()`.
4. **RwLock/guard held across an `.await`.** per_client_recv_loop (10 s DTLS recv),
   deliver_to_subscribers (50 ms jitter sleep).
5. **Types + logic shipped without call-site wiring.** TOFU `check_tofu`, cert pinning
   `check_certificate_pin`, `MessageType::as_discriminator_byte`, `DefaultRelayResolver`.
6. **WASM re-implementations drift from scp-core.** revocation CID hash input, missing
   ceiling check, required fields treated as optional.
7. **`let _ = result;` fire-and-forget on a fallible cleanup/spend** → split-brain.
   PyO3 `py_context_close`, `execute_paid_action` `record_spend`.
8. **Free functions extracted for pipeline-wiring AST gates lose injected deps**
   (clock/crypto/transport) and silently fall back to `SystemClock`.
9. **Renames applied comprehensively to WASM but minimally to the other 3 bridges.**
10. **Tests that pass already-resolved values mask the bridge's transformation path**
    (ucan_delegate full URIs bypassing the short-name fallback).

## Feb 2026 — early reviews (summarized)
Governance symmetry gaps; dead ownership checks; TOCTOU in standing_channel (fixed);
empty-set attenuation bypass (still present in spending.rs); Python `delegate()`
token_id-as-context (still present); UniFFI key material discarded on identity_create;
divergent canonical attestation formats; missing field separators in canonical hash;
late votes accepted after deadline; silent message drop in callbackFlow.

## Mar 2026 — PR #127 (loom/main-0301-0312), pass 1
- **UniFFI ucan_mint signs with an ephemeral key:** new InMemoryKeyCustody + DID per call;
  token claims issuer_did = creator but the signature is from the ephemeral key.
- FIXED: sentinel-value collision in TTL calc (now `Option<Duration>`); NAPI
  transport_disconnect TOCTOU; HotStreamFactory thread-unsafe maps; ScpViewModel.trackContext
  cleanupScope; rememberScpEventList scope leak (DisposableEffect + scope.cancel()).

## Mar 2026 — PR #127, pass 2
- **MessageType discriminator not in canonical hash (HIGH):** `as_discriminator_byte()` is
  doc'd as anti-type-flipping but `compute_canonical_hash` never includes it.
- **WASM ucan_validate wildcard context prefix (HIGH):** `starts_with("scp:ctx:{id}")` with no
  trailing `/` ⇒ cross-context escalation when IDs share a prefix.
- **Python `delegate()` has no proof chain (HIGH):** calls `mint()` without the parent token.
- **Compose rememberScpHotStream (MEDIUM):** `scope.launch{onStop()}` then `scope.cancel()`.
- **HotStreamFactory.contextEvents TOCTOU (MEDIUM).**
- **CheckpointManager.is_checkpoint_due ignores min_events_since_last (LOW)** — dead field.

## Mar 2026 — Transport expansion (DTLS/CoAP/QUIC/pool/manager/cover)
- FIXED: MergedStream::poll_next Pending-on-duplicate; QUIC accept_loop TOCTOU.
- **UDP dispatch_datagram (HIGH):** comment claims a fix; session limit still uses a read lock.
- **UDP adapter send_request triple lock (MEDIUM)** udp/adapter.rs:176-194 — concurrent callers
  get mismatched responses.
- **CoAP Observe + request() DTLS interleaving (MEDIUM)** coap/adapter.rs:238-244.
- **QUIC deliver_to_subscribers silent try_send drop (MEDIUM).**
- **BlockOption SZX=7 not validated (LOW)** coap/message.rs:450-452 (RFC 7959 reserves it).
- **send_to_context `latency_ms: 0` hardcoded (LOW)** manager.rs:459.

## Mar 2026 — Transport expansion, deferred-fix review
- **MergedStream poll_next missing `wake_by_ref` after a duplicate (HIGH)** manager.rs:1230-1232.
- **per_client_recv_loop holds RwLock across a 10 s blocking recv (HIGH)** udp/listener.rs:607.
- **WebSocket server missing rate_limiter_cleanup_task (MEDIUM)** — only QUIC spawns one.
- **Misleading "single write lock" comment (MEDIUM)** udp/listener.rs:383-385.
- **datagram_recv_loop blocks on the DTLS handshake in-line (MEDIUM)** udp/listener.rs:337-357.
- **deliver_to_subscribers holds a read lock across the jitter sleep (LOW)** subscription.rs:58.

## Mar 2026 — relay listener/session/client
- **QUIC handle_subscribe TOCTOU (MEDIUM)** quic/listener.rs:852-884 (WebTransport does it right).
- **WebSocket relay total-connection-limit TOCTOU (MEDIUM)** native/server.rs:482-512.
- **WebTransport subscribe_rate_limit unit mismatch (MEDIUM)** session.rs:109 — doc says
  "per second", `SubscribeRateLimiter::new` treats it as per minute.
- **WebTransport listener missing rate-limiter cleanup (MEDIUM).**
- **WASM client `Closure::forget()` leaks 3 closures per reconnect (LOW)** webtransport/client.rs.
- **WASM backfill_complete broadcasts to ALL subscriptions when ref_id is absent (LOW).**

## Mar 2026 — production-readiness commits (7-commit review)
- **ProtocolRepository migration chain still uses positional msgpack (MEDIUM)** store/mod.rs:362
  while `serialize()`/`store_migratable()` moved to `to_vec_named`.
- **validate_block_notification_freshness plain `+` overflow (LOW)** key_protocol.rs:683.
- New branches added without direct assertions (future-timestamp reject, RotateContentKeys
  conflict, same-member RemoveMember conflict).

## Mar 2026 — #310/#319 PkarrDhtClient + UCAN tool invocation
- **WASM revocation check is dead code (HIGH):** `validate_tool_ucan_wasm` reads
  `rt.revoked_tokens` (never populated) instead of `WasmUcanState.revoked_cids`, and hashes the
  full JWT string rather than the serialized payload.
- **WASM missing ceiling check (HIGH)** — doc claims it, body never reads `rt.ceiling_strings`.
- **WASM accepts missing exp/aud (HIGH)** — if-let-Some skips required UCAN fields.
- **`initialize_sequence` never called (HIGH)** main.rs — BEP44 sequence starts at 0.
- **Gateway returns unverified records (MEDIUM)** — `resolve_via_gateway` skips the BEP44 verify
  (sequence-poisoning DoS via `initialize_sequence`); the resolution path verifies at dht.rs:605.
- **Empty BridgeProofResolver in all 4 FFI tool bridges (MEDIUM)** — delegated UCANs always fail.
- **Missing AC test (MEDIUM):** #319 "mint UCAN without tool capability → rejected".

## Mar 2026 — #321/#326 timestamp validation + UniFFI UCAN signing
- **ucan_delegate fallback URI uses the wrong context_id (HIGH)** bridge.rs:2227-2231 — short
  capability names get the delegator's context_id, not the parent token's.
- **Missing per-sender timestamp monotonicity (MEDIUM)** validation.rs — §9.8.2(c) requires it
  alongside sequence monotonicity.

## Mar 2026 — production readiness iter. 3 (#347/#349/#327/#315/#325)
- **Unbounded `hpke_sealed_key` (HIGH)** key_protocol.rs:209 — missed in the bulk `serde_bytes`
  bounding; the runtime check at :757 fires after the OOM allocation.
- **TOFU / cert-pin types with no integration (HIGH)** — `check_tofu` / `check_certificate_pin`
  never called from resolution/connection paths (#325 requires it).
- **Duplicate serde modules (MEDIUM)** key_protocol.rs local `serde_signature_64`/`serde_pubkey_32`
  shadow serde_util.rs.
- **`serde_bounded_bytes` allocates from the msgpack length hint before the size check (MEDIUM).**

## Mar 2026 — production readiness iter. 4 (#357/#299/#311)
- **SubscriberRegistration signing_input missing length prefixes (HIGH)** broadcast.rs:94-106 —
  pre-#371 raw concatenation of context_id + subscriber_did.
- **#311 incomplete (HIGH):** src/tools.rs:251, napi/src/tools.rs:168, src/mcp.rs:662 still use
  `BridgeDidResolver`.
- **SubscriberRegistration wrapping_pubkey is `Vec<u8>` not `[u8; 32]` (MEDIUM)** broadcast.rs:70.

## Mar 2026 — fix/audit-remaining-findings (3 passes)
- FIXED: regenerate_and_distribute_sender_key joiner no-op; WASM canonical_template_name aliases;
  import_context TOCTOU; TemplateId DiscoveryContext→HandleRegistry serde alias; WASM wildcard
  capability match; Zeroizing removed from checkpoint signatures; RequiredSignal `Eq` removed;
  parse_template_id 4-alias acceptance across all bridges; PyO3 VALID_TEMPLATE_IDS.
- **Kotlin `fromJsonObject` crashes on `Active` RevocationStatus (MEDIUM)** Identity.kt:335 —
  `?.jsonObject` throws on a JSON primitive; `?.` only guards null. Use an `is JsonObject` check.

## Mar 2026 — Phase 5 Step 2, #386-389 FFI bridge rewrite
- **PyO3 `py_context_close` swallows errors (HIGH)** context.rs:1026 `let _ = close_result;`.
- **Close authorization diverges across 4 bridges (HIGH)** — PyO3 RBAC, UniFFI/NAPI creator-only,
  WASM creator-or-admin, while ContextManager has its own (`ttl::close_context`).
- **PyO3 FfiBridgeState.role_state drifts after governance (MEDIUM)** runtime.rs:349-355 — synced
  on join/leave only, not ChangeRole/ModifyCeiling.
- **NAPI context_create drops caller-set ContextParams fields (MEDIUM)** napi/src/context.rs:304.
- **NAPI register_local_did inconsistency (LOW)** — only NAPI calls it in context_create.

## Mar 2026 — PR #1586 wiring/batch-1-messaging
- **All 3 non-WASM bridges pass `None` for signing_key (HIGH)** — every FFI send fails for
  encrypted contexts.
- **Broadcast send failure rolls back the wrong sequence counter (HIGH)** messaging.rs.
- **Recovery notifications bypass access-key wrapping (HIGH)** trust_recovery.rs — never received.
- **Hardcoded epoch 0 / sequence 0 in sender-key + access-key AAD (MEDIUM).**
- **`inner.sequence + 1` wraps at u64::MAX (MEDIUM)** deliver_message_and_drain_buffered.
- **SequenceTracker accepts sequence 0 for the first message (LOW)** validation.rs.

## Mar 2026 — wiring/batch-2-governance
- **check_standing uses SystemClock not the injected clock (HIGH)** governance.rs:231; same in
  `enforce_role_demotion` (:53).
- **enforce_send_economy blocks every sender without a pre-granted budget (HIGH)** messaging.rs:47
  — chicken-and-egg: the creator can't propose a budget grant because governance is also blocked.
- **execute_paid_action discards `record_spend` (HIGH)** economy.rs:275.
- **standing_context TOCTOU (HIGH)** standing.rs:89-127.
- **enforce_capability_suspension substring matching (MEDIUM)** governance.rs:31 — "spreadsheet"
  triggers read revocation, "overwrite" triggers write revocation.
- **Double budget charge when a payment adapter is configured (MEDIUM).**
- **event_log_entries_for_consequences gives all synthesized events identical timestamps
  (MEDIUM)** governance.rs:197 — velocity triggers see them as simultaneous.
- **Persisted velocity_tracker ignores saved window_secs (MEDIUM)** lifecycle.rs:226 hardcodes 3600.

## Jun 2026 — PR-E #1543 enforcement hardening
- **pretooluse-enforcement-files.sh over-blocks reads (MEDIUM, false positive)** scripts/hooks/…:85
  — the write-verb list includes bare `bun|node` and `python….py`, so read-only invocations
  (`node check.js bridge-aliases.json`, the repo's own validator) are blocked. Fix: drop bare
  bun/node and the `.*\.py` script form; keep `python -c` + the redirect branch.
- **First unguarded `jq` aborts via `set -e` before the fail-closed handler (LOW)** line 53 —
  parse errors exit 5, not the blocking exit 2.
- **Misleading fail-closed message (LOW)** line 109.
- VERIFIED CLEAN: cites_durable_provenance byte-slicing panic-safe; 44 ffi_conformance tests;
  bridge-aliases.json valid; wasm identity rename clean.

## Jun 2026 — check-handler-no-panic.sh (commits 60692e6, then 77c3296)
- 60692e6 flag→stack fix in `scan_helper_file`/`scan_dispatch_hub` VERIFIED CORRECT (mawk 1.3.4
  short-circuit portable; old scanner had 5 false positives in supervisor.rs, new has 0).
- 77c3296 stack→scalar-floor rewrite is behaviorally EQUIVALENT — proven by a 4000-iteration
  random differential fuzz on both functions (0 mismatches) plus targeted fixtures. The
  load-bearing element is the `if(!in_gated)` guard.
- **PRE-EXISTING (both revisions) — `#[cfg(test)]` on a NON-braced item (use/const/static/type)
  latches `gated_pending` onto the NEXT braced item (MEDIUM, latent)** — swallows a real panic in
  the following fn. Not live in-tree.
- **PRE-EXISTING — char literals `'{'`/`'}'` break depth accounting (LOW, latent).** Not live.

## Jun 2026 — event-log unification Phase 2 (round 2 @dc18f5899, final @3d96058f5)
- HIGH fix VERIFIED: `run_buffered_post_delivery(event_name: Option<EventType>)` — append guarded
  on `Some`, velocity/consequence/checkpoint unconditional; all 4 drain sites call it
  unconditionally; no 5th site, no double-count.
- **Regression-test value gap (LOW, not a code defect):** the test drives the helper directly with
  `event_name = None`, so it tests the helper contract, not the 4 call sites where the bug lived.
- Consequence decode rewrite SOUND (msgpack-first then JSON; no header collision). Typed
  AccessRevoked/GovernanceActionExecuted payloads wired. `leaf_hash` extraction clean; the Merkle
  replay rejects prefix-trunc/reorder/remove-middle, suffix-trunc caught by signed-root compare.
- All 4 FFI bridges migrated `EventLogEntry` → `scp_event_log::Event` consistently.
- Final pass CLEAN: test helpers all `#[cfg(test)] pub(crate)`; `now_ms` cfg-gating mutually
  exclusive (prod wasm byte-identical); non-backdatable deadline fix correct; committer-assigned
  convergent timestamps correct; payment_receipts ring buffer correct.
- **PRE-EXISTING:** `prune_before_checkpoint` time-prune `break`-on-first-retained is
  non-monotonic under `structural_retention_multiplier` (errs toward over-retention).
- **PRE-EXISTING (identical on main):** scp-event-log --lib checkpoint/metrics tests fail locally
  with `InvalidSignature: unsupported DID format did:key:…` — local toolchain/feature env, CI-only
  resolver. Does not gate any branch.

## Jun 2026 — fix/sdk-coverage-fail-closed-and-parity
- **economy_verify_payment_receipts wire-shape mismatch (HIGH, cross-SDK).** Canonical shape from
  `scp_runtime::economy::receipt::verification_results_to_json` is
  `{"all_valid": bool, "results": [{"receipt_id","ok","valid","result"} | {"ok":false,"error"}]}`
  — NO top-level `ok`; the error arm has no `receipt_id`/`valid`; the reject field is `error`.
  TS `economy.ts` declared a required top-level `ok` and invented `reason?`; the Python parity
  test mocked `"receipts"` instead of `"results"` (false-premise green test).
- Re-review at HEAD: FIXED and VERIFIED CLEAN (types match exactly, TS export is sync because the
  NAPI export owns its own `block_on`, gate + 62 TS tests pass).

## Aug 2026 — SCP-RELAYRES-003 fix commit 7cdd735d6
- **DidSlotRegistry::sweep_expired same-blob_id re-establish clobber (LOW):** the `blob_id`-only
  guard does not protect the normal TTL-refresh republish (byte-identical re-establish keeps the
  same blob_id), so a sweep can drop a slot a concurrent refresh just made live. Availability-only.
  Fix: monotonic `generation` bumped on every insert. **(Applied — `DidSlot::generation` exists on
  the current tree and both `revert_if_stale` and `sweep_expired` gate on it.)**
- CLEAN otherwise: `publish_frame` holds the tokio RwLock write guard across all storage awaits
  (atomic read-modify-evict-store); cold-index reconciliation adopt condition
  `best_seq > seq || (best_seq == seq && best_id != blob_id)` correct; index-first eviction
  correct; `slot_publish_error_response` exhaustive; QUIC/UDP share one registry Arc; UDP listener
  is not wired into the node outside tests.
