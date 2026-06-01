# Bug Catcher Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

## SCP Project Knowledge

### Key Files
- `/Users/alec/Developer/limn/scp/.docs/specs/` — Full protocol specs.
- `/Users/alec/Developer/limn/scp/.docs/architecture.md` — Build document (~1024 lines).
- `/Users/alec/Developer/limn/scp/.docs/sketch.md` — API surfaces (~1477 lines).
- `/Users/alec/Developer/limn/scp/.docs/specs/00-open-questions.md` — Open and resolved design decisions.
- `/Users/alec/Developer/limn/scp/.docs/adrs/phase-2.md` — Phase 2 ADRs (context, roles, tools, events, transport).

### Known Bug Patterns (Feb 2026 — early reviews, summarized)
- See git history for full details. Key recurring patterns: governance symmetry gaps, dead ownership checks, TOCTOU in standing_channel (fixed), empty-set attenuation bypass (still present in spending.rs), Python delegate() token_id-as-context (still present), UniFFI key material discarded on identity_create, divergent canonical attestation formats, missing field separators in canonical hash, late votes accepted after deadline, silent message drop in callbackFlow.

### Known Bug Patterns (Mar 2026 — PR #127, loom/main-0301-0312 review, initial)
- **UniFFI ucan_mint signs with ephemeral key:** Creates new InMemoryKeyCustody + DID per call, signs token with wrong key. Token claims issuer_did = creator but signature is from ephemeral key. Pattern: placeholder key generation that looks real but produces unverifiable signatures. Same pattern as prior "key material discarded on identity_create".
- **FIXED: Sentinel-value collision in TTL calculation:** Now uses Option<Duration> sentinel, petname-only results get correct 365d TTL.
- **FIXED: NAPI transport_disconnect TOCTOU:** Single lock acquisition for check-and-modify.
- **FIXED: HotStreamFactory thread-unsafe maps:** Now uses ConcurrentHashMap.
- **FIXED: ScpViewModel.trackContext:** Now uses dedicated cleanupScope instead of viewModelScope.
- **FIXED: rememberScpEventList scope leak:** Now has DisposableEffect with scope.cancel().

### Known Bug Patterns (Mar 2026 — PR #127, loom/main-0301-0312 review, second pass)
- **MessageType discriminator not in canonical hash (HIGH):** inner.rs defines MessageType with as_discriminator_byte() doc'd as "for inclusion in canonical hashes to prevent type-flipping", but compute_canonical_hash never includes it. InnerEnvelopeParams lacks message_type field. Pattern: defense mechanism defined but never wired.
- **WASM ucan_validate wildcard context prefix confusion (HIGH):** starts_with("scp:ctx:{id}") without trailing "/" allows cross-context escalation when IDs share prefix. CLAUDE.md documents correct fix but code not updated. Pattern: documented fix not applied.
- **Python delegate() no proof chain (HIGH):** delegate() calls mint() without parent token proof. Delegated token appears as root token. No py_ucan_delegate FFI binding exists. Pattern: delegation that doesn't delegate.
- **Compose rememberScpHotStream scope race (MEDIUM):** scope.launch{onStop()} then scope.cancel() — onStop never executes. Pattern: launching cleanup work then immediately cancelling the scope.
- **HotStreamFactory.contextEvents TOCTOU (MEDIUM):** ConcurrentHashMap get-then-put with suspend point between. Duplicate subscriptions possible, first leaks. Pattern: check-then-act on ConcurrentHashMap across suspension points.
- **CheckpointManager.is_checkpoint_due ignores min_events_since_last (LOW):** Doc says min_events prevents spam, but time_due returns true regardless. Field is dead.

### Known Bug Patterns (Mar 2026 — Transport Expansion PR, DTLS/CoAP/QUIC/pool/manager/cover review)
- **FIXED: MergedStream::poll_next returns Pending for duplicates (HIGH):** Now uses `i += 1; continue;` loop instead of Poll::Pending. BUT: see deferred fix review below — missing wake_by_ref in duplicate branch.
- **FIXED: TOCTOU in QUIC accept_loop (HIGH):** quic/listener.rs now uses single write lock for check+increment (lines 389-415).
- **TOCTOU in UDP listener dispatch_datagram (HIGH):** Comment claims fix but session limit uses read lock, not write lock. Safe only because recv loop is sequential.
- **UDP adapter send_request triple lock acquisition (MEDIUM):** udp/adapter.rs:176-194. is_connected/send_datagram/recv_datagram each acquire-release the mutex separately. Concurrent callers get mismatched responses.
- **CoAP Observe + request() DTLS interleaving (MEDIUM):** coap/adapter.rs:238-244. Documented "known limitation" but no enforcement. Observe recv steals request responses, request recv steals Observe notifications.
- **QUIC deliver_to_subscribers silent drop (MEDIUM):** Now unified in subscription.rs:deliver_to_subscribers. Still try_send, but with better logging.
- **BlockOption::block_size SZX=7 not validated (LOW):** coap/message.rs:450-452. RFC 7959 reserves SZX=7 but decode() accepts it.
- **send_to_context latency_ms: 0 (LOW, pre-existing):** manager.rs:459. Still hardcoded from prior reviews.
- **RECURRING PATTERN:** TOCTOU across async lock boundaries (read-check-drop-write-act) is the #1 recurring bug pattern in this codebase. Found in: standing_channel (fixed), NAPI transport_disconnect (fixed), Swift resolveKeyId, HotStreamFactory.contextEvents, and now QUIC accept_loop (fixed) + UDP listener dispatch_datagram. Fix pattern: hold single write lock for check-and-mutate, or use entry() API.

### Known Bug Patterns (Mar 2026 — Transport Expansion PR, deferred fix review)
- **MergedStream poll_next missing wake after duplicate (HIGH):** manager.rs:1230-1232. Duplicate branch does `i += 1; continue;` without wake_by_ref(). If remaining streams return Pending, task hangs. Pattern: filtering items in Stream::poll_next without ensuring re-poll.
- **per_client_recv_loop holds RwLock across blocking recv (HIGH):** udp/listener.rs:607-614. Read lock held for up to 10s DTLS_RECV_TIMEOUT. Starves cleanup task, serializes last_activity updates. Pattern: RwLock guard held across async suspension point.
- **WebSocket server missing rate_limiter_cleanup_task (MEDIUM):** native/server.rs. Only QUIC spawns cleanup. WebSocket-only relay leaks rate limiter entries. Pattern: shared resource cleanup responsibility not coordinated.
- **Misleading comment in handle_new_client (MEDIUM):** udp/listener.rs:383-385. Claims "single write lock" but uses read lock + separate write lock. Safe only due to sequential processing.
- **datagram_recv_loop blocks on DTLS handshake (MEDIUM):** udp/listener.rs:337-357. Awaits handle_new_client in-line, blocking recv from all other new clients during handshake.
- **deliver_to_subscribers holds read lock during jitter sleep (LOW):** subscription.rs:58-113. Lock held for up to 50ms jitter delay. Pattern: RwLock guard held across spawned task joins.
- **RECURRING PATTERN:** RwLock held across async boundaries continues as #1 pattern. Now found in per_client_recv_loop AND deliver_to_subscribers.

### Known Bug Patterns (Mar 2026 — Transport Expansion, relay listener/session/client review)
- **QUIC listener handle_subscribe TOCTOU (MEDIUM):** quic/listener.rs:852-884. Read lock on my_subscriptions for limit check, dropped, then write lock for insert. Concurrent QUIC streams bypass limit. WebTransport session.rs does this correctly (single write lock). Pattern: TOCTOU across lock boundaries (recurring).
- **WebSocket relay total connection limit TOCTOU (MEDIUM):** native/server.rs:482-512. register_connection (write lock) then separate read lock for total check. Fix: incorporate total check into register_connection. Pattern: two-step atomic operation split into separate locks.
- **WebTransport subscribe_rate_limit unit mismatch (MEDIUM):** webtransport/session.rs:109. Doc says "per second" but SubscribeRateLimiter::new treats param as "per minute". QUIC listener names field correctly (rate_limit_subscribes_per_minute). Pattern: incorrect doc on config field leads to misconfiguration.
- **WebTransport listener missing rate_limiter cleanup (MEDIUM):** webtransport/server.rs. WebSocket and QUIC spawn cleanup tasks; WebTransport doesn't. Per-IP buckets leak. Pattern: shared cleanup responsibility not coordinated across transports (same as prior deferred-fix review finding for WebSocket server).
- **WASM client Closure::forget() leaks on reconnection (LOW):** webtransport/client.rs:386,399,430. Three closures leaked per WebSocket reconnection cycle. Pattern: wasm-bindgen Closure::forget without lifecycle management.
- **WASM client backfill_complete broadcast (LOW):** webtransport/client.rs:1339-1352. EVENT without ref_id broadcasts BackfillComplete to ALL subscriptions. Pattern: fallback dispatch that broadcasts instead of dropping unroutable events.
- **RECURRING PATTERN UPDATE:** TOCTOU across async lock boundaries remains the #1 recurring pattern. Now also found in QUIC handle_subscribe and WebSocket total connection check. Total count: 8+ instances across codebase (4 fixed, 4+ remaining).

### Known Bug Patterns (Mar 2026 — Production readiness commits, 7-commit review)
- **ProtocolRepository migration chain uses positional msgpack (MEDIUM):** store/mod.rs:362 still uses rmp_serde::to_vec (positional) for intermediate migration re-serialization, while serialize() and store_migratable() switched to to_vec_named. Latent: breaks if a Migratable::migrate() impl assumes named-format keys. Pattern: format migration applied to public APIs but missed internal path.
- **validate_block_notification_freshness overflow on addition (LOW):** key_protocol.rs:683 computes `now_ms + BLOCK_NOTIFICATION_FRESHNESS_MS` without saturating_add. Wraps at u64::MAX. Not practical (timestamps ~10^12, MAX ~10^19) but semantically wrong. Pattern: saturating_sub used defensively but plain + used for the symmetric check.
- **RECURRING PATTERN:** Format/serialization changes applied to main serialization paths but missed in secondary paths (migration chain, test helpers). Always grep for ALL call sites of the old function when switching serialization format.
- **Test coverage pattern:** New code paths added without corresponding tests (future-timestamp rejection, RotateContentKeys conflict, same-member RemoveMember conflict). Pattern: behavior change tested via existing passing tests but new branches not directly asserted.

### Known Bug Patterns (Mar 2026 — #310/#319 PkarrDhtClient + UCAN tool invocation review)
- **WASM revocation check dead code (HIGH):** runtime.rs validate_tool_ucan_wasm checks rt.revoked_tokens (always empty, never inserted into) instead of WasmUcanState.revoked_cids in ucan.rs. Also uses wrong hash function (SHA-256 of full JWT string vs SHA-256 of JSON-serialized payload). Pattern: new code in module A using stale field instead of existing infrastructure in module B.
- **WASM missing ceiling check (HIGH):** validate_tool_ucan_wasm doc claims "ceiling compliance" but never reads rt.ceiling_strings. Pattern: doc lists intended behavior not yet implemented in function body.
- **WASM accepts missing exp/aud (HIGH):** if-let-Some silently skips required UCAN fields. scp-core uses non-Option struct fields. Pattern: JSON dynamic access treating required fields as optional.
- **initialize_sequence never called (HIGH):** main.rs constructs DidDht via with_client_signer_and_store but never calls initialize_sequence() or set_sequence(). Sequence starts at 0. Pattern: constructor doc says "call X after" but integration site doesn't.
- **Gateway returns unverified records (MEDIUM):** resolve_via_gateway doesn't verify BEP44 Ed25519 signature. initialize_sequence would trust unverified seq (sequence poisoning DoS). Resolution path is safe (verifies at dht.rs:605).
- **Empty BridgeProofResolver in all FFI tool bridges (MEDIUM):** All 4 non-WASM bridges pass empty HashMap for proof resolution. Delegated UCANs always fail chain verification. Only root tokens work. Pattern: infrastructure from one FFI path not carried to new path.
- **Missing acceptance criterion test (MEDIUM):** #319 requires "mint UCAN without tool capability -> rejected" test but none exists.
- **RECURRING PATTERN:** WASM re-implementations drift from scp-core. Found: revocation CID (different hash input), ceiling check (missing), required field handling (optional vs required). Always verify WASM parity when adding validation.

### Known Bug Patterns (Mar 2026 — #321/#326 timestamp validation + UniFFI UCAN signing review)
- **ucan_delegate fallback URI uses wrong context_id (HIGH):** bridge.rs:2227-2231. Short capability names get prefixed with delegator's context_id instead of parent token's context_id. Attenuation check fails silently. Test masked by passing full URIs. Pattern: bridge-layer URI construction using wrong context source when multiple contexts are in play.
- **Missing per-sender timestamp monotonicity (MEDIUM):** validation.rs SequenceTracker checks sequence monotonicity but not timestamp monotonicity per 9.8.2(c). A replayed message with bumped sequence but older timestamp is accepted. Pattern: implementing part of a multi-property monotonicity spec requirement.
- **RECURRING PATTERN:** Tests that pass full/resolved values mask bridge-layer resolution bugs. The ucan_delegate test passes parent_capabilities (full URIs) bypassing the short-name-to-full-URI fallback path entirely. Always test BOTH the happy path AND the bridge's value-transformation path.

### Known Bug Patterns (Mar 2026 — Production Readiness Iteration 3, #347/#349/#327/#315/#325)
- **Unbounded hpke_sealed_key (HIGH):** key_protocol.rs:209-210. SenderKeyResponse.hpke_sealed_key still uses `serde_bytes` on Vec<u8> with no size cap. All other fields in same commit were converted. Runtime check exists (line 757) but OOM happens before it fires. Pattern: missed field during bulk conversion.
- **TOFU/cert-pin types without integration (HIGH):** tofu.rs and cert_pin.rs have complete types+logic+persistence but check_tofu() and check_certificate_pin() are never called from resolution/connection paths. Issue #325 explicitly requires "Integration with DID resolution -- check TOFU on every resolve" and "Pin violation -> connection rejected". Pattern: library types shipped without call-site wiring.
- **Duplicate serde modules (MEDIUM):** key_protocol.rs defines local serde_signature_64 and serde_pubkey_32 identical to serde_util.rs shared modules. serde_util.rs doc claims serde_pubkey_32 exists but module is missing. Pattern: shared module created but local copies not replaced.
- **serde_bounded_bytes allocates before checking (MEDIUM):** serde_bytes::deserialize pre-allocates Vec from msgpack length hint before the size check. WebSocket 512 KiB frame limit mitigates relay path. Pattern: post-allocation bounds checking on untrusted size hints.
- **RECURRING PATTERN:** When converting fields in bulk (e.g., Vec<u8> -> [u8; N] or adding serde bounds), grep for ALL instances of the old pattern. Missed fields are the #1 bug in bulk conversions. Found: hpke_sealed_key missed in #347.
- **RECURRING PATTERN:** Types+logic without call-site wiring. Found in: TOFU (check_tofu never called), cert pinning (check_certificate_pin never called). Always verify the integration point exists, not just the library code.

### Known Bug Patterns (Mar 2026 — Production Readiness Iteration 4, #357/#299/#311)
- **SubscriberRegistration signing_input missing length prefixes (HIGH):** broadcast.rs:94-106. Concatenates context_id + subscriber_did (both variable-length) without 4-byte BE length prefixes or domain separator. Spec §9.5 mandates length prefixes since #371. Pattern: new code using pre-#371 raw concatenation pattern instead of post-#371 canonical serialization.
- **#311 incomplete — 3 production paths still use BridgeDidResolver (HIGH):** src/tools.rs:251, napi/src/tools.rs:168, src/mcp.rs:662 still use BridgeDidResolver. UniFFI tool_invoke was updated but PyO3/NAPI tool paths missed. Pattern: bulk replacement missing call sites (same as #347 hpke_sealed_key).
- **SubscriberRegistration wrapping_pubkey Vec<u8> not [u8; 32] (MEDIUM):** broadcast.rs:70-71. Spec says X25519PublicKey (32 bytes). Runtime check only in register_subscriber, not verify_signature. Pattern: Vec<u8> for known-fixed-size fields.
- **RECURRING PATTERN UPDATE:** Bulk replacement missing call sites is now the #2 recurring pattern. Found in: #347 (hpke_sealed_key), #311 (BridgeDidResolver in tool paths). Always grep for ALL call sites when replacing a type/function across the codebase.

### Known Bug Patterns (Mar 2026 — fix/audit-remaining-findings branch review, pass 1)
- **FIXED: regenerate_and_distribute_sender_key is a no-op for joiner (LOW):** join_from_welcome in crypto.rs now extracts member DIDs from MLS group roster and populates self.members before returning. regenerate_and_distribute_sender_key reads from the now-populated map. Called in PyO3 and NAPI testing bridges immediately after join_from_welcome.
- **FIXED: WASM canonical_template_name missing old HandleRegistry names (LOW):** context.rs:3011-3014. Now maps "scp:template/handle-registry" | "HandleRegistry" | "scp:template/discovery-context" | "DiscoveryContext" => "HandleRegistry". Both old and new names aliased correctly.
- **FIXED: import_context TOCTOU:** manager.rs:2264-2281. Re-checks replaceability under lock before insert. try_read_state() returning None → reject is conservative/correct.
- **FIXED: TemplateId::DiscoveryContext → HandleRegistry:** serde alias "scp:template/discovery-context" correctly handles old wire format on deserialization.
- **FIXED: WASM wildcard capability match:** wasm_conformance.rs. self.action == "*" on granting side now matches any required action within the same resource.
- **FIXED: Zeroizing removed from checkpoint signatures:** correct (signatures are public values, not secrets).
- **FIXED: RequiredSignal Eq removed:** f64 in ThresholdRequirement prevents Eq — correct compilation fix.

### Known Bug Patterns (Mar 2026 — fix/audit-remaining-findings branch review, pass 2)
- **FIXED: parse_template_id missing backward compat + URI form:** All 4 bridges now accept all 4 alias forms: "scp:template/handle-registry", "HandleRegistry", "scp:template/discovery-context", "DiscoveryContext". PyO3 VALID_TEMPLATE_IDS also updated. build_core_context_params updated too.
- **FIXED: PyO3 VALID_TEMPLATE_IDS missing HandleRegistry:** Now includes all 4 alias forms.
- **RECURRING PATTERN:** Renames applied comprehensively to WASM but minimally to other bridges. Always grep all 4 bridges when renaming enum variants/string constants.

### Known Bug Patterns (Mar 2026 — fix/audit-remaining-findings branch review, pass 3)
- **Kotlin fromJsonObject crashes on Active RevocationStatus (MEDIUM):** Identity.kt:335. `obj["revocation_status"]?.jsonObject` throws IllegalArgumentException when revocation_status is the string "Active" (common case). kotlinx.serialization `.jsonObject` throws on non-JsonObject elements; `?.` only protects against null. Fix: use `obj["revocation_status"]?.let { if (it is JsonObject) it else null }` or check `is JsonObject` before calling `.jsonObject`. Latent bug — bridge functions throw not-implemented currently. No test for fromJsonObject parsing.
- **RECURRING PATTERN:** `?.jsonObject` in kotlinx.serialization is NOT a safe accessor for possibly-primitive JSON values. Always use `is JsonObject` check or `jsonObjectOrNull` before `.jsonObject`.

### Known Bug Patterns (Mar 2026 — Phase 5 Step 2, #386-389 FFI bridge rewrite review)
- **PyO3 py_context_close silently swallows errors (HIGH):** context.rs:1026. `let _ = close_result;` discards ContextManager close errors, creating split-brain between FFI state (cleaned up) and ContextManager state (still active). Pattern: fire-and-forget on fallible operation where caller assumes cleanup succeeded.
- **Close authorization diverges across 4 bridges (HIGH):** PyO3 uses RBAC capability check (role_state.member_has_capability), UniFFI/NAPI use creator-only string compare, WASM uses creator-or-admin. ContextManager has its own auth (ttl::close_context). Pattern: bridge-layer auth checks that duplicate/contradict the authoritative layer.
- **PyO3 FfiBridgeState.role_state diverges after governance (MEDIUM):** runtime.rs:349-355. Duplicate RoleState synced on join/leave but NOT after ChangeRole, ModifyCeiling, or other governance actions dispatched through ContextManager. Used for UCAN/tool capability checks. Pattern: copied state that drifts from source of truth.
- **NAPI context_create drops ContextParams fields (MEDIUM):** napi/src/context.rs:304-308. `..ContextParams::default()` silently drops ceiling, governance, promotion_policy, ceiling_policy from user input. Pattern: struct update syntax defaulting fields the caller set.
- **NAPI register_local_did inconsistency (LOW):** NAPI calls register_local_did in context_create; UniFFI/PyO3 don't. May cause is_local_did checks to fail on those bridges.
- **RECURRING PATTERN UPDATE:** Authorization logic duplicated at bridge layer instead of delegated to ContextManager is a new pattern. Found across all 4 bridges with 3 different implementations. Fix: remove bridge-layer auth, rely on ContextManager enforcement.
- **RECURRING PATTERN UPDATE:** `let _ = result;` (fire-and-forget on Result) is a code-smell for split-brain. Always propagate or explicitly handle close/cleanup errors.

### Known Bug Patterns (Mar 2026 — PR #1586, wiring/batch-1-messaging envelope pipeline review)
- **All 3 non-WASM FFI bridges pass None for signing_key (HIGH):** PyO3/NAPI/UniFFI context_send all pass `None` for `signing_key` to `send_message`. New pipeline requires signing key for InnerEnvelope creation. All FFI sends fail for encrypted contexts. Pattern: API signature extended but callers mechanically updated with None instead of resolving the parameter.
- **Broadcast send failure rolls back wrong sequence counter (HIGH):** messaging.rs rollback_sequence_number runs unconditionally for both broadcast and encrypted paths. Broadcast path never calls next_sequence_number, so rollback incorrectly decrements. Latent (saturating_sub(0)=0) but wrong.
- **Recovery notifications bypass access key wrapping (HIGH):** trust_recovery.rs creates InnerEnvelope from raw recovery payload without wrap_content. deliver_incoming tries to deserialize as WrappedContent, fails. Recovery notifications won't be received.
- **Hardcoded epoch 0 / sequence 0 in sender key + access key AAD (MEDIUM):** provider.rs seal/open and messaging.rs wrap/unwrap all use 0,0. AAD binding to actual epoch/sequence is eliminated. Defense-in-depth gap.
- **deliver_message_and_drain_buffered wrapping overflow (MEDIUM):** messaging.rs `inner.sequence + 1` wraps at u64::MAX. Should use saturating_add(1) like SequenceTracker.advance does.
- **SequenceTracker accepts sequence 0 for first message (LOW):** validation.rs `envelope.sequence <= 1` accepts 0. next_sequence_number starts at 1, so 0 should never appear.
- **RECURRING PATTERN UPDATE:** FFI bridges mechanically passing None/default for new parameters is now the #3 recurring pattern. Found in: #386-389 (signing_key), #1586 (signing_key again), NAPI context_create (ContextParams fields). Always verify FFI callers resolve new parameters from their bridge state.

### Known Bug Patterns (Mar 2026 — wiring/batch-2-governance review)
- **check_standing uses SystemClock instead of injected clock (HIGH):** governance.rs:231. Free function uses `scp_primitives::SystemClock.now_secs()` instead of `self.clock`. Same pattern in `enforce_role_demotion` (line 53). Pattern: free functions extracted for pipeline wiring gates lose access to ContextManager's injected clock.
- **enforce_send_economy blocks all senders without pre-granted budgets (HIGH):** messaging.rs:47-52. `record_spend` returns `NoBudget` for any member without a `grant()` call. No automatic budget provisioning on create/join. Chicken-and-egg: creator can't propose budget grant because governance messages are also blocked. Same pattern in enforce_join_economy and check_tool_economy.
- **execute_paid_action silently discards record_spend error (HIGH):** economy.rs:275. `let _ = budget_tracker.record_spend(...)` discards Result after payment capture. Split-brain between payment rail and budget state. Pattern: `let _ = result;` fire-and-forget (recurring).
- **standing_context TOCTOU (HIGH):** standing.rs:89-127. Lock dropped before create_context; concurrent calls race on same deterministic context ID. Pattern: TOCTOU across async lock boundaries (recurring #1).
- **enforce_capability_suspension substring matching (MEDIUM):** governance.rs:31-35. `contains("write")`/`contains("read")` on capability names. "spreadsheet" triggers read revocation, "overwrite" triggers write revocation. Pattern: heuristic string matching instead of enum-based dispatch.
- **Double budget charge with payment adapter (MEDIUM):** Per-action economy functions (enforce_send_economy, check_tool_economy) AND execute_paid_action both call record_spend. Double charge when payment adapter is configured. Pattern: two integration layers independently tracking the same resource.
- **event_log_entries_for_consequences identical timestamps (MEDIUM):** governance.rs:197. All synthesized events get `timestamp: now`. Velocity-based consequence triggers see all events as simultaneous. Pattern: temporal metadata lost when bridging event types.
- **Persisted velocity_tracker ignores saved window_secs (MEDIUM):** lifecycle.rs:226 hardcodes 3600 instead of using ctx_snapshot.velocity_tracker. Per-sender velocity data lost on restart. Pattern: snapshot saves config but restore ignores it.
- **RECURRING PATTERN UPDATE:** Free functions extracted for pipeline wiring AST gates lose access to ContextManager's injected dependencies (clock, crypto, transport). Found in: check_standing (SystemClock), enforce_role_demotion (SystemClock). Always thread injected deps as parameters when extracting free functions.

### Known Bug Patterns (Jun 2026 — PR-E #1543 enforcement-hardening review)
- **pretooluse-enforcement-files.sh Bash verb regex over-blocks reads (MEDIUM, false positive):** scripts/hooks/pretooluse-enforcement-files.sh:85. Verb list includes general-purpose interpreters `bun|node` and `python...\.py`. Pattern `(...|bun|node)[[:space:]].*BASENAME` matches ANY command that runs node/bun/python-script followed by the protected basename ANYWHERE later — including read-only invocations. Confirmed blocked: `node check.js bridge-aliases.json`, `bun run lint scripts/bridge-aliases.json`, `python3.12 validate.py scripts/bridge-aliases.json` (the repo's OWN validator). Hook's stated intent is "Allow READ-style operations." Fix: drop bare bun/node and the `.*\.py` script form from the write-verb branch (keep `python -c` write detection + the redirect branch), or require a write indicator. dd/install/ln are documented known limitations (acceptable).
- **First unguarded jq aborts via set -e before fail-closed handler (LOW):** line 53 `tool_name=$(...| jq -r ...)` runs under set -e. Malformed JSON makes jq exit 5, set -e kills script with rc=5 — NOT the controlled `exit 2` block code. The explicit fail-closed handler at line 108 is only reachable for the EMPTY-result case (jq -e exit 4), never parse errors. Claude Code treats only exit 2 as "block"; rc=5 is a non-blocking hook error. Not practically triggerable (Claude always sends valid JSON) but defeats documented fail-closed intent. Fix: wrap line-53 jq with `|| { echo ...; exit 2; }`.
- **Misleading fail-closed message (LOW):** line 109 prints "jq failed to parse tool_input" but actually fires on empty/absent file_path (jq -e exit 4), not parse failure. Cosmetic.
- **VERIFIED CLEAN:** cites_durable_provenance byte-slicing is panic-safe (match_indices guarantees i+prefix.len() is a char boundary, incl. 2-byte §). 44 ffi_conformance tests pass. bridge-aliases.json valid; napi `migrate` alias resolves to #[napi] method. wasm identity.rs rename (identity_verify_link_attestation_signature→identity_verify_link_attestation) clean, no stale refs, compiles for wasm32. New [[:space:]] classes correct (old [ \t] worked via backtracking anyway). Edit/Write/MultiEdit path, fixture non-matching, symlink realpath all correct.
