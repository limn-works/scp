---
name: pr1867-failclosed-trust-parity-5e1bf40d2
description: PR #1867 fix/sdk-coverage-fail-closed-and-parity (HEAD b712f94ae, prev 5e1bf40d2) — ALIGNED w/ 1 pre-existing aud-binding observation; TS/py trust evaluateLayer1 att[0].with fix + typed errors + fail-closed coverage gate
metadata:
  type: project
---

PR #1867 `fix/sdk-coverage-fail-closed-and-parity`, base main, merge-base `1f1ea7cd2`. Two reviews:
- @5e1bf40d2 (first): ALIGNED, 0 findings, 3 info.
- @b712f94ae (re-review, 2026-06-22): delta = edef523f8 (ADR-053 one-word method-name fix import_seed_bytes→import_ed25519_signing_key) + b712f94ae (new lesson ucan-validate-needs-real-capability-uri.md). BOTH DOCS-ONLY; substantive code byte-identical to 5e1bf40d2. Verdict ALIGNED; 1 NEW pre-existing-not-introduced OBSERVATION surfaced by focused aud-binding question.

**Same branch family** as earlier sdk_coverage_failclosed_parity_* reviews. Core code facts re-confirmed (att[0].with fix, __PASSED_BEFORE 6-field collapse, typed errors, fail-closed gate, PermissionError removal, behavioral 0-not-fabricated) — all still ALIGNED per prior review.

**NEW OBSERVATION (pre-existing, NOT introduced/worsened by this PR — flag-only): evaluateTrust never binds token `aud` to `subjectDid`.**
- Spec §7.2.1 step 5 (07-trust...:77): "Verify audience matches the presenting agent's DID." In evaluateTrust(subjectDid,...), the subject IS the presenting agent.
- Both TS evaluateLayer1 (trust.ts:470) and py evaluate_trust (trust.py:795) call ucanValidate(handle, token, capUri) WITHOUT the `presenting_agent_did`/subjectDid arg.
- PyO3 ucan.rs:202: `let agent_did = presenting_agent_did.unwrap_or(&parsed_token.payload.aud)` → step 5 compares token.aud vs itself = TAUTOLOGY. A token whose aud ≠ subjectDid still reports signaturesValid:true for subjectDid.
- PRE-EXISTING: before this PR the call was `ucan_validate(context_id, token, "*")` (the bug fixed) — presenting_agent_did was ALSO omitted before. This PR fixed the more-severe "*" defect (made Layer1 unconditionally all-false); did NOT touch the aud binding. Lesson file scoped only to "*" — does not overclaim.
- DEEPER PRE-EXISTING BRIDGE DIVERGENCE (also untouched by PR): TS scp.ts:2372 ucanValidate ACCEPTS presentingAgentDid, but (a) NAPI shim native.ts:987-994 is typed/forwards ONLY 3 args (h,t,c) → silently DROPS presentingAgentDid+proofTokens even though NAPI bridge scp.rs:2981 accepts them; (b) WASM shim wasm.ts:1409 HARDCODES `handle.creatorDid` as expected_aud_did (WASM bridge requires non-empty DID, validate_did). So the three paths check aud against: PyO3=token's own aud, NAPI=token's own aud (arg dropped), WASM=context creatorDid. None checks subjectDid. Fixing properly = thread subjectDid through evaluateLayer1 + widen native.ts shim to 5 args + change wasm.ts to pass subjectDid not creatorDid. OUT OF THIS PR's STATED SCOPE; recommend follow-up (do not file issue per repo rule — fix inline in a follow-up, or escalate).

**3 prior info observations still stand:** (1) "not yet exposed over bridge" wording → cite §7.3.2; (2) STALE prds/main.json + phase-3.md:379 still name py `PermissionError` (off main already); (3) cosmetic cryptographer memory file mislabels ADR-053 as ADR-051.

ADR-053 (Proposed, new file) correct artifact-flow: design ADR, NO code, cites §9.7.4.1/§9.12/ADR-003§4b. edef523f8 corrects operational method name to the real KeyCustody trait method (traits.rs:499 import_ed25519_signing_key) vs the NEW PreRotationCustodyProvider::import_seed_bytes — accurate distinction.
