# ADR-055 / §7.2.4 Structured CapabilityValidation (branch c3c-ts) -- 2026-06-27 -- ZERO FINDINGS

Reviewed full diff origin/main...HEAD on branch c3c-ts (5 commits, base e406c15c5-ish).
Change: UCAN trust validation crosses FFI as structured `CapabilityValidation` (6 bools:
tokens_valid/signatures_valid/within_ceiling/nonce_valid/not_revoked/time_bounds_valid).
SDKs consume struct instead of parsing error prose; single TS bridge-error chokepoint
(`wrapBridgeErrors` Proxy + `mapBridgeError`). Diagnostic `evaluate_ucan` now takes
`Option<&CapabilityUri>` (None = skip step-6 invoked-cap grant-match, all other checks run).
Throwing gate `validate_ucan` UNCHANGED (mandatory capability).

CLEAN on all 5 audit lenses:
1. AuthZ: gate `validate_ucan` required_capability still `&CapabilityUri` (mandatory) — NOT
   changed by this branch (the `-` in diff was a doc-comment region). Diagnostic only ever
   populates informational TrustEvaluation.capability_validation; NO allow/deny/raise keys off
   it (grep confirmed). `None`-cap path provably non-weakening: only skips check_capability_match
   (validate.rs:836-838), every other stage still runs.
2. Error chokepoint fail-closed: mapBridgeError (errors.ts:265) always returns ScpError subclass,
   unknown->SCP-UNKNOWN-0000 (still error), never maps failure->success. wrapBridgeErrors Proxy
   preserves sync/async, does NOT deep-proxy handles (handle-affinity intact).
3. FFI untrusted input: all 4 bridges normalize empty/whitespace cap -> "no challenge" BEFORE
   parsing (.filter trim); supplied non-empty cap still validated+parsed (unparseable raises).
   UniFFI Option<String> threads to Kotlin/Swift. Result is plain bools, no JSON prose round-trip.
4. Tests: removed test_ucan_conformance.py (613L) was a PROSE-MATCHING META-TEST (asserted Python
   error-classifier prefixes == Rust UcanError variant strings) — ADR-055 deletes prose-parsing
   entirely (no _classify_ucan_error left in scp_sdk), so its subject is gone. NOT a regression.
   Negative coverage RELOCATED+EXPANDED to test_trust.py (revoked/invalid-sig/expired/
   outside-ceiling/malformed-all-false/idempotency/mock-models-recording) + test_real_ffi.py
   (evaluate_trust_end_to_end + import_rejects_tampered_export).
5. No secret leak: result = 6 bools only; error strings pass bridge message verbatim (same as
   Rust already emitted; invalid-cap echoes CALLER-supplied cap, not foreign state).

OBSERVATIONS (non-blocking):
- OBS-1 cross-SDK asymmetry: TS evaluateTrust passes subjectDid as presenting-agent (audience
  checks against DID-under-assessment, stricter); Python omits it (defaults to token's own aud,
  trivially self-satisfied). Non-enforcing diagnostic so no security impact; align Python for parity.
- OBS-2 GOOD: parse_granted_caps fail-closed in BOTH gate+diagnostic (validate.rs:454-468), explicit
  no-filter_map/ok comment — malformed attestation can't escape step-8 ceiling check.
- OBS-3 GOOD: diagnostic truly side-effect-free — nonce probed via check_replay, never record;
  takes &ValidationContext (shared); can't be nonce-burn oracle. Locked by test_mock_gate_actually_models_recording.

---

## Review 2 (full c3c-ts 1f0d59ca8..3e9ec3a22) -- 2026-06-27 -- ZERO FINDINGS, OBS-1 RESOLVED
- Python e8e7fc2e8 "audience tautology" fix landed: trust.py now passes subject_did as presenting_agent. Both SDKs aligned. Headline = AUDIENCE FIX closes trust-inflation (old default presenting-agent=token aud => aud==aud => signaturesValid for a token addressed to someone else).

## Review 3 (FINAL, HEAD 747f01403, base e406c15c5) -- 2026-06-27 -- ZERO FINDINGS
- 5 new commits beyond review 2: 4 docs/wording + ONE real fix 4d8980603.
- 4d8980603 (tool_invocations typed count map): FIXED a latent bug. TS evaluateTrust read `event.payload?.toolId` but raw bridge event carries `payloadJson` (JSON string), NO payload object; unsound `as readonly Event[]` cast masked it from tsc. Now both SDKs bucket every ToolInvoked under literal "ToolInvoked" key; BehavioralRecord.tool_invocations = dict[str,int]/Record<string,number>. Matches spec §7.2.4 sum(). NOT a security regression — correctness + cross-SDK alignment. Per-tool keying awaits ADR-051.
- Mock fix sound: trust.test.ts mock now emits REAL bridge shape (payloadJson, no payload obj); prior mock fabricated payload:{toolId} and masked the bug.
- All 4 bridges identical: `capability.filter(|c|!c.trim().is_empty())` BEFORE validate => empty/ws=None=no-challenge; None to evaluate_ucan. WASM REQUIRES expected_aud_did (no defaulting, by design).
- SDK consumers: TS scp.ts:2328 ucanEvaluate(handle,token,null,subjectDid); Python trust.py:661 ucan_evaluate(ctx,token,None,subject_did). capability None + subject as presenting agent.
- New negative tests (57c318261) exemplary REAL-FFI: audience-mismatch (Bob token eval Carol=>false, Bob control=>true); forged-token+empty-cap=>signaturesValid false AND equals omitted (coercion=no-challenge not no-check); error pass-through typed-not-downgraded (direct+Proxy async+sync); idempotent-records-nothing.
- CLEAN all 5 lenses. Branch ready.
