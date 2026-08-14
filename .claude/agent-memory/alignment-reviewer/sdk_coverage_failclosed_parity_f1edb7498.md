---
name: sdk-coverage-failclosed-parity-f1edb7498
description: fix/sdk-coverage-fail-closed-and-parity ALIGNED at f1edb7498 — rebase now CLEAN (merge-base==origin/main), all 5 PR parts verified against specs
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ f1edb7498 (2026-06-20) — ALIGNED, 0 blocking

**Why:** Re-review after rebase. The stale-base trap from the ad51633f3 review (~19 commits behind, phantom deletions) is RESOLVED.

**How to apply:** This branch is now mergeable from an alignment standpoint; verdict ALIGNED.

## Rebase sanity (resolves prior stale-base finding)
- HEAD f1edb7498. `git merge-base HEAD origin/main` == `git rev-parse origin/main` == `dabf13364`. Two-dot diff `origin/main...HEAD` = 46 files, +3548/-429, ZERO phantom deletions. The fake "reconnect/heartbeat/event-log removal" deletions seen at ad51633f3 are GONE — branch is correctly rebased on current main.

## 5 PR parts all verified ALIGNED against specs/code
1. **TS evaluateTrust 4-layer (trust.ts)** — full parity w/ python trust.py. 19-entry SIGNATURE_CHAIN_PREFIXES byte-identical; classify order identical (SIG→CEIL→PARSE→NONCE→REVOKE→EXPIRY); `__PASSED_BEFORE` map identical. Doc cites "spec §7.2–7.5, ADR-017" — VERIFIED accurate: spec 07 has §7.2 Layer1 Protocol Enforcement / §7.3 Layer2 Participation / §7.4 Layer3 Attestation Authenticity / §7.5 Layer4 Trust Evaluation. py dispatches by context_id, TS by Context handle (documented per-SDK NAPI idiom lines 404-408, [[feedback_per_sdk_idiom]], NOT a bug).
2. **Citation fix §9.12→§3.2.1** (py scp.py:720 identityMigrate docstring + TS identity.ts:115 rotationEventJson) — VERIFIED: spec 03-identity.md §3.2.1 "Key Custody Migration Protocol" item 2 = Identity Key migration creates NEW DID + DidRotationEvent to active contexts + alsoKnownAs. ADR-003 §4b (phase-1.md:375) = migrate_identity returns (Identity, DidDocument, DidRotationEvent, PreRotationKeyHandle). Both citations correct.
3. **economy_verify_payment_receipts** (py + TS economy.ts types) — wire shape `{all_valid, results:[{receipt_id, ok, valid, result}]}` mirrors crates/scp-runtime/src/economy/receipt.rs:153 doc-comment exactly. `ok==true` ≠ valid distinction correctly documented in both SDKs.
4. **discover_contexts** (py discovery.py async + TS) — dispatches bridge.context_discover; `_scp` param renamed to silence unused (commit f1edb7498). Cross-SDK shape `discoverContexts(scp, query)`.
5. **ADR-051 (Proposed)** — problem statement quotes §9.7.4.1 §3/§4/§5 VERBATIM-accurate (verified 09-security-model.md:655-696). Code citations real: PyO3 InMemoryPreRotationCustody at identity.rs:824/922/1052 (3 sites: create/create_with_agent_key/create_with_custody); UniFFI generate_ephemeral_ed25519_seed bridge.rs:676 + import_ed25519_signing_key fail-closed block :714/:736 verbatim error text. ADR-003 §4b + ADR-021 KeyCustodyProvider refs exist. Artifact-flow-compliant (open Q3 asks if §9.7.4.1 needs callback sub-clause before code).

## Gate (check-sdk-coverage.py) — fail-closed CONFIRMED
- Local run EXIT 0: 222 ops, 1 coverage-exempt (add_relay_url kotlin tree-sitter-kotlin gap), errors=0, unmatched-true=0, false-w/o-exempt=0. 9 self-tests pass (pytest). Null-safe `(node.text or b"").decode()` :547. Non-empty exemption-reason validation :1131. All-exempted-vacuous guard :1208. CI adds self-tests as BLOCKING step before gate run (NEW assertion = legit enforcement-file mod per CLAUDE.md).

## Matrix changes accurate
- rotate_key exemption text CORRECTED: old "UniFFI does not export rotate_key" was FALSE; UniFFI bridge.rs:2178 `pub async fn rotate_key`. New text "exports rotate_key; no SDK wrapper yet" accurate — Swift Identity.swift:9 is a COMMENT not impl; Kotlin has only `rotateAgentKey`(different op) + broadcast `rotateKeys`(param). No identity rotate_key wrapper in either SDK = exemption valid.
- add_relay_url coverage_exemption for kotlin: UniFFI bridge.rs:13387 has it; generated-Kotlin not git-tracked + tree-sitter-kotlin grammar doesn't surface backtick @Throws override as function_declaration. Accurate.

## TS surface complete
index.ts: evaluateTrust + 6 trust types exported; bridge `evaluateTrust` disambiguated as `bridgeEvaluateTrust` (mirrors py bridge_evaluate_trust, spec §12); BehavioralRecord/TrustEvaluation re-sourced ./bridge→./trust; economy receipt types exported.

See [[two-dot-diff-stale-base-trap]], [[feedback_per_sdk_idiom]].
