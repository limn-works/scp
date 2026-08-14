---
name: adr057-c3c-trust-sdk-caff1e32d
description: ADR-057 / §7.2.4 structured-FFI trust-signal SDK rebuild (C3c, SCP-302/303) review at caff1e32d — NEEDS DISCUSSION, one phantom-provenance finding
metadata:
  type: project
---

# ADR-057 C3c Trust-Signal SDK Rebuild @ `caff1e32d` (branch feat/actor-2c-xctx-tool-saga, 2026-06-30) — NEEDS DISCUSSION

Reviewed three-dot diff `origin/main...HEAD` (101 files, +13645/-2565). Branch intentionally ~1 commit behind origin/main (unrelated saga PR); final rebase pre-push. WASM removed (ADR-055) — 3 bridges, 4 SDKs at parity; do NOT flag missing WASM.

**Why:** C3c rebuild — SDKs MUST consume structured `CapabilityValidation` (six per-stage booleans) from `ucan_evaluate`, never reverse-engineer per-check outcome from error prose. Plus typed `participation_record` op + the twelve-field `ParticipationFacts` projection.
**How to apply:** For future rounds, the ONE finding below is the only residual; everything else verified ALIGNED.

## THE FINDING (phantom provenance + asymmetric remediation)
`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Participation.kt` (NOT in this diff; last touched `3f437f0ff` package-rename, pre-branch) defines a pure-Kotlin free fn `verifyParticipationRequirements(requirement, profile)` (line 90) whose doc (line 82-83) claims "Pure Kotlin implementation **matching the Rust trust module's `verify_participation_requirements` logic**" and (line 4) "These types mirror the Rust trust module's participation types." FALSE: it only sums plaintext `value` fields vs min/max — NO Ed25519 signature verify, NO subject binding (`expected_subject`), NO distinct-signer/min_contexts, NO freshness. The Rust `verify_participation_requirements` (participation.rs:987) does ALL of those (Step 0 subject filter line 1005, Step 1 `verify_statement_signature` per statement, freshness, distinct signers).
- Asymmetric: this branch FIXED the Swift twin (Trust.swift:990 now honestly "a pure Swift function with no bridge dependency", commit `6da9545ad`) and added the SECURE bridge-backed `SCP.verifyParticipationRequirements(expectedSubject, profileJson, requirementsJson)` in Kotlin Scp.kt:1913 (delegates to `uniffi.scp.verifyParticipationRequirements`) — but MISSED the Kotlin Participation.kt twin. The prior reviewer flagged BOTH Trust.swift AND Participation.kt; only Swift was remediated.
- Impact: Kotlin ships TWO public `verifyParticipationRequirements` (secure SCP method + insecure free fn) AND duplicate competing types `ParticipationFact`/`ParticipationProfile`/`RequireParticipation` in pkg `works.limn.scp` (Participation.kt) distinct from the UniFFI `uniffi.scp` ones used by new Trust.kt. Misuse hazard; the false doc claim actively misleads toward the insecure twin. Fix: delete the vestigial Participation.kt twin (superseded) or correct its doc to honestly state no-crypto/no-relation-to-Rust-admission.
- Severity NEEDS DISCUSSION (not MISALIGNED): secure path exists; this is a residual cleanup gap the branch's own stated phantom-provenance-scrubbing intent (commits 61d85f651, 6da9545ad) should have caught.

## VERIFIED ALIGNED (no findings)
- ADR-057 (phase-2.md) coherent; Decision-5 = all four bindings, no deferral residue ✓. WASM-removal noted correctly.
- §7.2.4 gate-vs-diagnostic well-specified (gate records nonce/throws/mandatory cap; diagnostic read-only/optional cap/never records).
- §7.3.2/§7.3.2.1 twelve fields consistent across ALL layers (Rust `ParticipationFacts` participation.rs:147, pyo3/napi/uniffi bridges, Python trust.py, TS types.ts/scp.ts, Swift Trust.swift, Kotlin Trust.kt). `attestation_count_anchored` on UNSIGNED projection ONLY (const ATTESTATION_COUNT_ANCHORED always false); signed `ParticipationProfile` does NOT carry it ✓ (matches spec note).
- ADR-011 amendment: NO `AttestationPublished`/`AttestationRevoked` EventType (AttestationRevoked is only a `TrustError` variant) ✓.
- §7.4 caveats present: authenticity≠Sybil, authenticity≠authorization, issuer-legitimacy (also in Rust doc-comments on attestation_count). Subject binding documented BOTH §7.3.2.1 step 5(a) and §7.4.1 ✓.
- Capability matrix: all UCAN.evaluate / evaluate_trust / participation_record cells true, exemptions removed; bundled SDK-parity cells also closed (rotate_key/add_agent_key/rotate_agent_key/remove_agent_key/migrate TS, register TS, discover py, verify_payment_receipts py) — all the prior "C3c SDK-parity follow-up"/"same bundled branch" deferral residue cleared.
- Core subject binding: verify_participation_requirements Step 0 `expected_subject` filter (matches HEAD commit "fix(trust): bind subject…").
- One-way flow respected: spec/ADR/PRD drive code; new lesson sdk-consume-structured-ffi-results-not-error-prose.md cites ADR-057/§7.2.4.

## Minor observation (not blocking)
3 `#NNNN` refs (#1305/#1324/#501) on added lines are all in `crates/scp-ffi/CLAUDE.md` (project DOC, not source/comments/tests) and pre-exist on origin/main (the edit only swapped NoOpEventLogProvider→MerkleEventLogProvider, keeping the refs). Branch DID scrub issue-refs from trust bridge comments (b6d6de50d); CLAUDE.md left as-is. Could scrub for consistency.
