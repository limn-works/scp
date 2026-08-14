---
name: adr055-c3c-structured-capvalidation
description: ADR-055 structured CapabilityValidation across FFI + C3c SDK rebuild (SCP-302, branch c3c-ts) — ALIGNED except 1 phantom-provenance citation (§7.2.4 should be §7.3.2.1 for ToolInvocationCount)
metadata:
  type: project
---

# ADR-055 / SCP-302 C3c SDK rebuild review (branch `c3c-ts`, 2026-06-27)

PR #1867 Goal-#2 rebuild: structured six-bool `CapabilityValidation` crosses FFI; SDKs consume typed result, never parse error prose. Verdict NEEDS DISCUSSION (aligned in substance, one citation defect).

**What shipped (all ACs verified met):**
- Core: `evaluate_ucan` required_capability → `Option<&CapabilityUri>` (intrinsic-validity mode skips step-6 grant-match only; step-8 within_ceiling still runs over token's own att set, fail-closed). Gate `validate_ucan` stays MANDATORY `&CapabilityUri`. All 4 bridges take optional cap + `capability.filter(|c| !c.trim().is_empty())` coercion (empty/whitespace = no challenge; `*` sentinel rejected as malformed — absence expressed by OMISSION).
- Decision recorded in artifacts BEFORE code: ADR-055 Decision 2a + Consequences bullet 3 + spec §7.2.4. Artifact-flow clean.
- Python prose-parser fully deleted (9 symbols grep count 0: _classify_ucan_error/_extract_core_error/_PASSED_BEFORE/6 *_PREFIXES tuples). evaluate_trust now calls ucan_evaluate per-token + AND-combines six bools.
- TS: ucanEvaluate plumbed bridge→native+wasm→scp.ts; CapabilityValidation interface (6 camelCase bools) in types.ts re-exported index.ts; public evaluateTrust on SCP class. Error chokepoint = single mapBridgeError (errors.ts:265) at wrapBridgeErrors Proxy + raw-addon SCP-class methods.
- SDK-parity wrappers: TS identityRotateKey/identityAddAgentKey/identityRotateAgentKey/identityRemoveAgentKey/identityMigrate (scp.ts), module-level bridgeRegister (bridge.ts→index.ts), Python discover() + verify_payment_receipts().
- Capability matrix flips all present; stale "C3c-follow-up" exemptions removed on flipped cells; Kotlin/Swift UCAN.evaluate keep non-imminent exemption citing ADR-055 Decision-5. Aliases ("UCAN","evaluate") + ("Economy","verify_payment_receipts") added to check-sdk-coverage.py.
- validate-prd.py PASS (371 stories); check-sdk-coverage.py exit 0 (224 ops, 0 errors).

**THE ONE DEFECT — phantom provenance citation:**
`ToolInvocationCount = tool_invocations.values().sum()` is defined at spec **§7.3.2.1 line 221** (ParticipationFact categories), NOT §7.2.4. §7.2.4 (lines 118-149) is the NEW gate-vs-diagnostic section, zero tool_invocations refs (verified via awk between §7.2.4 and §7.3). Wrong citation appears in:
- `bindings/python/scp_sdk/trust.py:140`
- `bindings/typescript/src/scp.ts:2373-2374`
- (also test comments: test_trust.py ~1171, trust.test.ts ~4428/4819)
FIX: change "spec §7.2.4" → "spec §7.3.2.1" for the ToolInvocationCount-formula comment ONLY. Other §7.2.4/ADR-055 citations in these files are CORRECT (they're about the diagnostic, not tool counts) — leave them.

**LESSON:** the tool_invocations `list[dict]→dict[str,int]` map-shape change is genuinely spec-grounded (the `.values().sum()` formula is meaningless on a list) — only the section NUMBER in the citation was wrong, not the decision. When a code comment cites a section for a formula, grep the cited section for the formula's symbol — a plausible-looking nearby section number is the classic phantom-provenance tell.

**POSITIVE pattern worth repeating:** audience-binding WARNING doc-comments on all 4 bridges (PyO3/NAPI/UniFFI default aud→self = tautological self-check = trust inflation; WASM requires explicit expected_aud_did, no defaulting by design). Deliberate cross-bridge asymmetry documented honestly.
